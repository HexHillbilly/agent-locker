"""SQLite store (WAL mode) for pads, blocks, and tickets.

Transaction ownership
---------------------
There is ONE application connection (:attr:`Store.conn`) and it is shared by every
request. Two rules keep it safe, and both are load-bearing:

1. **Every statement on that connection is issued while holding** :attr:`Store.lock`.
   ``Store.lock`` is what makes a multi-statement operation atomic with respect to
   other coroutines -- the individual ``await``\ s yield, and without the lock another
   coroutine's statements, and its ``COMMIT``/``ROLLBACK``, can land in the middle of
   one. Methods here are deliberately lock-free so that a caller can hold the lock
   across a whole compound operation; the request layer does exactly that.
2. **Only the owner of a transaction may end it.** Nothing outside an operation may
   issue ``COMMIT`` or ``ROLLBACK`` on the shared connection. A stray ``ROLLBACK``
   discards whatever another coroutine has written but not yet committed, while that
   coroutine goes on to report success.

:meth:`Store.health_check` follows both rules and additionally performs no transaction
control at all (see its docstring), and reads its aggregates on a separate connection
when one is supplied (:attr:`Store.health_conn`) so a liveness probe never touches the
connection carrying application work.

**[C] Scope of the lock.** ``asyncio.Lock`` serializes coroutines within *one process*.
Each process opens its own connection, so this is the correct protection for the
single-process deployment this daemon runs; it is not a cross-process lock, and it is
not a substitute for a real transaction boundary if the daemon is ever run with a
shared connection across workers.
"""
from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import time
from contextlib import asynccontextmanager

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


async def connect_readonly(path: str) -> aiosqlite.Connection:
    """Open a second connection that is physically unable to write.

    Used for liveness reads only. ``PRAGMA query_only = ON`` means this connection
    cannot commit or roll back anything ever, so a health probe holding it cannot
    disturb application work even if the code around it is wrong later. The schema is
    not created here -- the main connection owns that.
    """
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA query_only = ON")
    return conn


class Store:
    def __init__(self, conn: aiosqlite.Connection, read_lease_seconds: int = cfg.READ_LEASE_SECONDS,
                 health_conn: aiosqlite.Connection | None = None):
        self.conn = conn
        self.lock = asyncio.Lock()
        self.read_lease_seconds = read_lease_seconds
        # Optional dedicated read-only connection used only by health_check(), so a
        # liveness probe never interleaves a cursor with application transactions.
        self.health_conn = health_conn

    @asynccontextmanager
    async def transaction(self):
        """Own the shared connection's transaction for the duration of the block.

        Enter this **while holding** :attr:`lock`. On any exit that is not a clean
        return -- an exception *or* cancellation -- the connection is rolled back, so a
        handler that fails part-way cannot leave uncommitted statements behind for a
        later request to commit by accident. On a clean exit it commits, which is a
        no-op for operations that already committed their own work.
        """
        try:
            yield
        except BaseException:
            await self.conn.rollback()
            raise
        else:
            await self.conn.commit()

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
    async def _pragma_scalar(self, conn, stmt: str):
        cur = await conn.execute(stmt)
        row = await cur.fetchone()
        await cur.close()
        return row[0] if row else None

    async def _counts(self, conn) -> tuple[int, int, int]:
        total = await self._pragma_scalar(conn, "SELECT COUNT(*) AS c FROM pads")
        unsealed = await self._pragma_scalar(conn, "SELECT COUNT(*) AS c FROM pads WHERE state='open'")
        sealed = await self._pragma_scalar(conn, "SELECT COUNT(*) AS c FROM pads WHERE state='sealed'")
        return total, unsealed, sealed

    async def health_check(self):
        """Return ``(writable, wal_mode, total, unsealed, sealed)``. **Non-mutating.**

        This used to probe write capability with ``BEGIN IMMEDIATE`` / ``ROLLBACK`` on
        the connection it was handed. On the shared request connection that made
        ``/health`` a participant in other requests' transactions: a rollback landing
        between another coroutine's ``INSERT`` and its ``COMMIT`` discards that write
        while the request still reports success. See the module docstring, rule 2.

        ``writable`` is the documented "503 if DB read-only" signal: it means the
        store's connection is not in read-only mode. **[C] It is a capability
        indicator, not proof that a write succeeded** -- a later write can still fail
        for reasons this probe cannot see (disk full, a lock held by another process).

        The single read against the shared connection is taken under :attr:`lock`, like
        every other statement on it. The aggregates are read on
        :attr:`health_conn` when one was supplied, so a liveness probe does not
        interleave a cursor with application work; without one they are read under the
        lock as well, which keeps rule 1 true in every configuration.
        """
        async with self.lock:
            read_only = bool(await self._pragma_scalar(self.conn, "PRAGMA query_only"))
        writable = not read_only

        if self.health_conn is not None:
            wal_mode = ((await self._pragma_scalar(self.health_conn, "PRAGMA journal_mode")) or "").lower() == "wal"
            total, unsealed, sealed = await self._counts(self.health_conn)
        else:
            async with self.lock:
                wal_mode = ((await self._pragma_scalar(self.conn, "PRAGMA journal_mode")) or "").lower() == "wal"
                total, unsealed, sealed = await self._counts(self.conn)

        return writable, wal_mode, total, unsealed, sealed

    # ---- integrity (read-only) ----
    async def chain_report(self, pad_id):
        """Read-only consistency and accounting report for one pad. Never writes.

        Checks, against the stored rows: contiguous 0-based ``seq``; ``prev_hash``
        linkage with ``ZERO_HASH`` at the genesis; each ``curr_hash`` recomputed from
        the previous hash and the payload bytes; the pad's stored ``head_hash`` equal
        to the last block's ``curr_hash`` (or ``ZERO_HASH`` when empty); and
        ``current_bytes`` equal to the sum of the payload lengths.

        **[C] It cannot prove that nothing was ever lost.** A chain that was written
        correctly and then had acknowledged tail data discarded looks exactly like a
        short-but-consistent chain, because the pad keeps no independent record of what
        it acknowledged. Catching that needs the caller's own acknowledgment record --
        see ``scripts/check_integrity.py`.
        """
        problems: list[str] = []
        cur = await self.conn.execute(
            "SELECT seq, prev_hash, curr_hash, payload FROM blocks WHERE pad_id=? ORDER BY seq",
            (pad_id,))
        rows = await cur.fetchall()
        await cur.close()
        cur = await self.conn.execute("SELECT head_hash, current_bytes FROM pads WHERE id=?", (pad_id,))
        pad = await cur.fetchone()
        await cur.close()
        if pad is None:
            return {"pad_id": pad_id, "ok": False, "blocks": 0,
                    "problems": ["pad does not exist"]}

        prev = cfg.ZERO_HASH
        nbytes = 0
        for i, r in enumerate(rows):
            if r["seq"] != i:
                problems.append(f"block at position {i} stores seq={r['seq']}: not a contiguous 0-based sequence")
            if r["prev_hash"] != prev:
                problems.append(f"block {i}: prev_hash does not link to the previous block's curr_hash")
            payload = bytes(r["payload"])
            nbytes += len(payload)
            expect = hashlib.sha256(prev.encode() + payload).hexdigest()
            if r["curr_hash"] != expect:
                problems.append(f"block {i}: stored curr_hash does not match its payload and predecessor")
            prev = r["curr_hash"]
        if pad["head_hash"] != prev:
            problems.append("stored head_hash does not match the last block's curr_hash")
        if pad["current_bytes"] != nbytes:
            problems.append(f"current_bytes is {pad['current_bytes']} but the stored payloads total {nbytes}")
        return {"pad_id": pad_id, "ok": not problems, "blocks": len(rows),
                "head_hash": pad["head_hash"], "current_bytes": pad["current_bytes"],
                "actual_bytes": nbytes, "problems": problems}
