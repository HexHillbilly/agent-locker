"""SQLite store (WAL mode) for pads, blocks, and tickets.

Methods are intentionally lock-free; the request layer serializes compound
operations with ``Store.lock``. A single aiosqlite connection is used.
"""
from __future__ import annotations

import asyncio
import sqlite3
import time

import aiosqlite

from . import config as cfg


def now() -> int:
    """Current unix time (monkeypatchable in tests)."""
    return int(time.time())


SCHEMA = """
CREATE TABLE IF NOT EXISTS pads (
     id TEXT PRIMARY KEY,
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     max_blocks INTEGER NOT NULL DEFAULT 32,
     max_bytes INTEGER NOT NULL DEFAULT 262144,
     current_bytes INTEGER NOT NULL DEFAULT 0,
     state TEXT CHECK(state IN ('open', 'sealed', 'expired')) NOT NULL DEFAULT 'open',
     write_key_hash TEXT NOT NULL,
     head_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
     sealed_at INTEGER
);

CREATE TABLE IF NOT EXISTS blocks (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     pad_id TEXT NOT NULL REFERENCES pads(id),
     seq INTEGER NOT NULL,
     prev_hash TEXT NOT NULL,
     curr_hash TEXT NOT NULL,
     content_type TEXT NOT NULL DEFAULT 'application/json',
     payload BLOB NOT NULL,
     created_at INTEGER NOT NULL,
     UNIQUE(pad_id, seq)
);

CREATE TABLE IF NOT EXISTS tickets (
     ticket_id TEXT PRIMARY KEY,
     pad_id TEXT NOT NULL REFERENCES pads(id),
     type TEXT CHECK(type IN ('read_once', 'read_unlimited')) NOT NULL,
     redeemed_count INTEGER NOT NULL DEFAULT 0,
     max_reads INTEGER NOT NULL DEFAULT 1,
     lease_started_at INTEGER,
     created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blocks_pad_seq ON blocks(pad_id, seq);
CREATE INDEX IF NOT EXISTS idx_tickets_pad ON tickets(pad_id);

CREATE TABLE IF NOT EXISTS payment_receipts (
     tx_hash TEXT PRIMARY KEY,
     pad_id TEXT NOT NULL REFERENCES pads(id),
     amount_units INTEGER NOT NULL,
     payer_address TEXT,
     created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipts_pad_id ON payment_receipts(pad_id);
"""


async def connect(path: str) -> aiosqlite.Connection:
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode = WAL")
    await conn.execute("PRAGMA foreign_keys = ON")
    await conn.execute("PRAGMA synchronous = NORMAL")
    for stmt in SCHEMA.split(";"):
        stmt = stmt.strip()
        if stmt:
            await conn.execute(stmt)
    await conn.commit()
    return conn


class Store:
    def __init__(self, conn: aiosqlite.Connection, read_lease_seconds: int = cfg.READ_LEASE_SECONDS):
        self.conn = conn
        self.lock = asyncio.Lock()
        self.read_lease_seconds = read_lease_seconds

    # ---- pads ----
    async def create_pad(self, pad_id, write_key_hash, ttl_seconds, max_blocks):
        t = now()
        await self.conn.execute(
            "INSERT INTO pads (id, created_at, expires_at, max_blocks, max_bytes, write_key_hash)"
            " VALUES (?,?,?,?,?,?)",
            (pad_id, t, t + ttl_seconds, max_blocks, cfg.DEFAULT_MAX_BYTES, write_key_hash),
        )
        await self.conn.commit()

    async def has_receipt(self, tx_hash):
        cur = await self.conn.execute(
            "SELECT 1 FROM payment_receipts WHERE tx_hash = ?", (tx_hash,)
        )
        row = await cur.fetchone()
        await cur.close()
        return row is not None

    async def create_pad_with_receipt(self, pad_id, write_key_hash, ttl_seconds,
                                      max_blocks, tx_hash, amount_units, payer_address):
        """Atomically create a pad and record its payment receipt.

        Returns False (leaving no pad behind) if ``tx_hash`` was already redeemed.
        """
        t = now()
        try:
            await self.conn.execute(
                "INSERT INTO pads (id, created_at, expires_at, max_blocks, max_bytes, write_key_hash)"
                " VALUES (?,?,?,?,?,?)",
                (pad_id, t, t + ttl_seconds, max_blocks, cfg.DEFAULT_MAX_BYTES, write_key_hash),
            )
            await self.conn.execute(
                "INSERT INTO payment_receipts (tx_hash, pad_id, amount_units, payer_address, created_at)"
                " VALUES (?,?,?,?,?)",
                (tx_hash, pad_id, amount_units, payer_address, t),
            )
            await self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            await self.conn.rollback()
            return False
        except Exception:
            await self.conn.rollback()
            raise

    async def get_pad(self, pad_id):
        cur = await self.conn.execute("SELECT * FROM pads WHERE id = ?", (pad_id,))
        row = await cur.fetchone()
        await cur.close()
        return dict(row) if row else None

    async def expire_pad_if_needed(self, pad):
        if pad["state"] == "open" and pad["expires_at"] <= now():
            await self.conn.execute(
                "UPDATE pads SET state='expired' WHERE id=? AND state='open'", (pad["id"],)
            )
            await self.conn.commit()
            pad["state"] = "expired"
        return pad

    async def seal_pad(self, pad_id):
        await self.conn.execute(
            "UPDATE pads SET state='sealed', sealed_at=? WHERE id=?", (now(), pad_id)
        )
        await self.conn.commit()

    # ---- blocks ----
    async def block_count(self, pad_id):
        cur = await self.conn.execute(
            "SELECT COUNT(*) AS c FROM blocks WHERE pad_id=?", (pad_id,)
        )
        row = await cur.fetchone()
        await cur.close()
        return row["c"]

    async def append_block(self, pad_id, seq, prev_hash, curr_hash, content_type, payload):
        await self.conn.execute(
            "INSERT INTO blocks (pad_id, seq, prev_hash, curr_hash, content_type, payload, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (pad_id, seq, prev_hash, curr_hash, content_type, payload, now()),
        )
        await self.conn.execute(
            "UPDATE pads SET head_hash=?, current_bytes=current_bytes+? WHERE id=?",
            (curr_hash, len(payload), pad_id),
        )
        await self.conn.commit()

    async def get_blocks(self, pad_id, frm, to):
        cur = await self.conn.execute(
            "SELECT seq, prev_hash, curr_hash, content_type, payload, created_at"
            " FROM blocks WHERE pad_id=? AND seq BETWEEN ? AND ? ORDER BY seq",
            (pad_id, frm, to),
        )
        rows = await cur.fetchall()
        await cur.close()
        return [dict(r) for r in rows]

    # ---- tickets ----
    async def create_ticket(self, ticket_id, pad_id, ttype, max_reads=1):
        await self.conn.execute(
            "INSERT INTO tickets (ticket_id, pad_id, type, max_reads, created_at)"
            " VALUES (?,?,?,?,?)",
            (ticket_id, pad_id, ttype, max_reads, now()),
        )
        await self.conn.commit()

    async def check_ticket(self, pad_id, ticket_id):
        """Return 'ok', 'invalid', or 'exhausted' without consuming a read.

        ``read_once`` tickets carry a read *lease*: the first successful read
        opens a ``read_lease_seconds`` window; reads inside it are allowed and
        reads after it are rejected.
        """
        cur = await self.conn.execute(
            "SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)
        )
        row = await cur.fetchone()
        await cur.close()
        if row is None or row["pad_id"] != pad_id:
            return "invalid"
        if row["type"] == "read_once" and row["lease_started_at"] is not None:
            if now() - row["lease_started_at"] > self.read_lease_seconds:
                return "exhausted"
        return "ok"

    async def record_read(self, ticket_id):
        """Record a successful read: open the lease on first read (read_once)."""
        await self.conn.execute(
            "UPDATE tickets SET redeemed_count = redeemed_count + 1,"
            " lease_started_at = COALESCE(lease_started_at, ?)"
            " WHERE ticket_id = ? AND type = 'read_once'",
            (now(), ticket_id),
        )
        await self.conn.commit()

    # ---- health ----
    async def health_check(self):
        """Return ``(writable, wal_mode, total, unsealed, sealed)``."""
        cur = await self.conn.execute("PRAGMA query_only")
        row = await cur.fetchone()
        await cur.close()
        read_only = bool(row[0]) if row else False

        cur = await self.conn.execute("PRAGMA journal_mode")
        row = await cur.fetchone()
        await cur.close()
        wal_mode = ((row[0] or "").lower() if row else "") == "wal"

        writable = not read_only
        if writable:
            try:
                await self.conn.execute("BEGIN IMMEDIATE")
                await self.conn.execute("ROLLBACK")
            except Exception:
                writable = False

        cur = await self.conn.execute("SELECT COUNT(*) AS c FROM pads")
        row = await cur.fetchone()
        await cur.close()
        total = row["c"]

        cur = await self.conn.execute("SELECT COUNT(*) AS c FROM pads WHERE state='open'")
        row = await cur.fetchone()
        await cur.close()
        unsealed = row["c"]

        cur = await self.conn.execute("SELECT COUNT(*) AS c FROM pads WHERE state='sealed'")
        row = await cur.fetchone()
        await cur.close()
        sealed = row["c"]

        return writable, wal_mode, total, unsealed, sealed
