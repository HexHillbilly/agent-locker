"""Narrow checks on the transaction boundary and the health claims.

Item 1 — the boundary. Store methods commit their own work, so an operation assembled
from two of them has two commit points and is not atomic: an outer rollback cannot undo
an inner commit. These tests pin that distinction down per operation, by mutating and then
failing, and inspecting persisted state through a *separately opened* connection:

* append, seal, ticket activation and pad creation (with its initial ticket, and on the
  paid path with its receipt) either land whole or not at all;
* pad creation and its initial ticket are one unit (they used to commit separately);
* payment-receipt replay protection covers the whole operation, not just the receipt;
* the connection is clean and the lock free before the next request runs.

Item 2 — health. The probe reads on its own connection, opened with
``PRAGMA query_only = ON``; that setting is not filesystem writability and not a write
probe, and ``database.writable`` must not be read as either. Repeated polling must not
accumulate connections or tasks, and a cancelled poll must not hold the lock.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3

import httpx
import pytest

from lockerd import config as cfg
from lockerd import db as dbmod
from lockerd.main import create_app

_ABSENT = object()


def envelope() -> dict:
    return {"schema": "locker.handoff.v1", "task_id": "t", "from_agent": "a",
            "to_agent": "b", "constraints": [], "artifacts": [], "budget_usd": None}


@pytest.fixture
async def rig(tmp_path):
    path = str(tmp_path / "t.db")
    app = create_app(cfg.Config(db_path=path, auth_mode=cfg.AUTH_OPEN))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://t") as c:
            yield c, app, app.state.store, path


def raw(path, sql, args=()):
    """Read through a connection this test owns, never the application's."""
    con = sqlite3.connect(path)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


class Failing:
    """Pass-through connection that raises on one chosen statement."""

    def __init__(self, real, needle, exc):
        self._real, self.needle, self.exc = real, needle, exc

    def __getattr__(self, name):
        return getattr(self._real, name)

    async def execute(self, sql, parameters=_ABSENT):
        if self.needle in sql:
            raise self.exc
        if parameters is _ABSENT:
            return await self._real.execute(sql)
        return await self._real.execute(sql, parameters)


async def new_pad(client, blocks=8) -> dict:
    r = await client.post("/v1/pads", json={"ttl_seconds": 3600, "max_blocks": blocks})
    assert r.status_code == 201, r.text
    return r.json()


async def seed_envelope(client, pad) -> None:
    r = await client.post(f"/v1/pads/{pad['pad_id']}/append",
                          content=json.dumps(envelope()).encode(),
                          headers={"Authorization": f"Bearer {pad['write_key']}"})
    assert r.status_code == 201, r.text


# --------------------------------------------------------------------------- #
# The boundary: lock ownership is not atomicity
# --------------------------------------------------------------------------- #

async def test_pad_creation_and_its_initial_ticket_are_one_unit(rig):
    """They used to commit separately: a failure on the ticket left a pad nobody could use."""
    client, app, store, path = rig
    pads_before = len(raw(path, "SELECT id FROM pads"))

    store.conn = Failing(store.conn, "INSERT INTO tickets", RuntimeError("injected: ticket insert failed"))
    try:
        with pytest.raises(RuntimeError):
            await client.post("/v1/pads", json={"ttl_seconds": 3600, "max_blocks": 4})
    finally:
        store.conn = store.conn._real

    assert len(raw(path, "SELECT id FROM pads")) == pads_before, \
        "the pad was committed even though its ticket was not: the operation is not atomic"
    assert raw(path, "SELECT ticket_id FROM tickets WHERE pad_id NOT IN ('demo-pad-v1')") == []


async def test_creation_is_usable_after_a_failed_creation(rig):
    """Cleanup must finish before the next request: the lock is free and the connection clean."""
    client, app, store, path = rig
    store.conn = Failing(store.conn, "INSERT INTO pads", RuntimeError("injected"))
    try:
        with pytest.raises(RuntimeError):
            await client.post("/v1/pads", json={"ttl_seconds": 3600, "max_blocks": 4})
    finally:
        store.conn = store.conn._real

    assert store.lock.locked() is False, "the failed request left the store lock held"
    pad = await new_pad(client)                      # the next request acquires it cleanly
    assert raw(path, "SELECT id FROM pads WHERE id=?", (pad["pad_id"],))
    assert len(raw(path, "SELECT ticket_id FROM tickets WHERE pad_id=?", (pad["pad_id"],))) == 1


async def test_append_after_a_mutation_but_before_completion_rolls_back(rig):
    client, app, store, path = rig
    pad = await new_pad(client, blocks=8)
    await seed_envelope(client, pad)
    auth = {"Authorization": f"Bearer {pad['write_key']}"}

    real = dbmod.Store.append_block

    async def mutate_then_fail(self, pad_id, seq, prev_hash, curr_hash, ct, payload):
        await self.conn.execute(
            "INSERT INTO blocks (pad_id, seq, prev_hash, curr_hash, content_type, payload, created_at)"
            " VALUES (?,?,?,?,?,?,?)", (pad_id, seq, prev_hash, curr_hash, ct, payload, 0))
        raise RuntimeError("injected after the block insert, before commit")

    store.append_block = mutate_then_fail.__get__(store, dbmod.Store)
    with pytest.raises(RuntimeError):
        await client.post(f"/v1/pads/{pad['pad_id']}/append", content=b"doomed", headers=auth)
    store.append_block = real.__get__(store, dbmod.Store)

    assert raw(path, "SELECT seq FROM blocks WHERE pad_id=? ORDER BY seq", (pad["pad_id"],)) == [(0,)]
    assert store.lock.locked() is False
    # the head and byte count were not advanced by the failed attempt either
    r = await client.post(f"/v1/pads/{pad['pad_id']}/append", content=b"second", headers=auth)
    assert r.status_code == 201, r.text
    assert r.json()["seq"] == 1


async def test_seal_after_a_mutation_but_before_completion_rolls_back(rig):
    client, app, store, path = rig
    pad = await new_pad(client)
    await seed_envelope(client, pad)
    auth = {"Authorization": f"Bearer {pad['write_key']}"}

    real = dbmod.Store.seal_pad

    async def mutate_then_fail(self, pad_id):
        await self.conn.execute(
            "UPDATE pads SET state='sealed', sealed_at=? WHERE id=?", (1, pad_id))
        raise RuntimeError("injected after the seal update, before commit")

    store.seal_pad = mutate_then_fail.__get__(store, dbmod.Store)
    with pytest.raises(RuntimeError):
        await client.post(f"/v1/pads/{pad['pad_id']}/seal", headers=auth)
    store.seal_pad = real.__get__(store, dbmod.Store)

    assert raw(path, "SELECT state, sealed_at FROM pads WHERE id=?",
               (pad["pad_id"],))[0] == ("open", None), "a half-done seal was committed"
    assert store.lock.locked() is False
    # and the pad is still sealable, so the failed attempt left nothing behind
    assert (await client.post(f"/v1/pads/{pad['pad_id']}/seal", headers=auth)).status_code == 200


async def test_ticket_activation_after_a_mutation_but_before_completion_rolls_back(rig):
    """A cancelled lease write must not consume the ticket."""
    client, app, store, path = rig
    pad = await new_pad(client)
    await seed_envelope(client, pad)
    auth = {"Authorization": f"Bearer {pad['write_key']}"}
    await client.post(f"/v1/pads/{pad['pad_id']}/seal", headers=auth)
    ticket = pad["read_ticket"]

    real = dbmod.Store.record_read

    async def mutate_then_fail(self, ticket_id):
        await self.conn.execute(
            "UPDATE tickets SET redeemed_count = redeemed_count + 1,"
            " lease_started_at = COALESCE(lease_started_at, ?) WHERE ticket_id = ?", (1, ticket_id))
        raise RuntimeError("injected after the lease update, before commit")

    store.record_read = mutate_then_fail.__get__(store, dbmod.Store)
    with pytest.raises(RuntimeError):
        await client.get(f"/v1/pads/{pad['pad_id']}/blocks",
                         headers={"Authorization": f"Bearer {ticket}"})
    store.record_read = real.__get__(store, dbmod.Store)

    row = raw(path, "SELECT redeemed_count, lease_started_at FROM tickets WHERE ticket_id=?", (ticket,))[0]
    assert row == (0, None), f"a half-done lease activation was committed: {row}"
    # the ticket is still usable, i.e. the failed read did not consume it
    r = await client.get(f"/v1/pads/{pad['pad_id']}/blocks",
                         headers={"Authorization": f"Bearer {ticket}"})
    assert r.status_code == 200, r.text


async def test_cancellation_leaves_the_lock_free_and_the_connection_clean(rig):
    client, app, store, path = rig
    pad = await new_pad(client, blocks=8)
    await seed_envelope(client, pad)
    auth = {"Authorization": f"Bearer {pad['write_key']}"}

    started = asyncio.Event()
    real = dbmod.Store.append_block

    async def slow(self, *a, **kw):
        started.set()
        await asyncio.sleep(5)
        return await real(self, *a, **kw)

    store.append_block = slow.__get__(store, dbmod.Store)
    task = asyncio.create_task(client.post(f"/v1/pads/{pad['pad_id']}/append",
                                           content=b"cancelled", headers=auth))
    await asyncio.wait_for(started.wait(), timeout=10)
    assert store.lock.locked() is True
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    store.append_block = real.__get__(store, dbmod.Store)

    assert store.lock.locked() is False, "cancellation released the lock too late"
    assert raw(path, "SELECT seq FROM blocks WHERE pad_id=? ORDER BY seq", (pad["pad_id"],)) == [(0,)]
    assert (await client.post(f"/v1/pads/{pad['pad_id']}/append",
                              content=b"after", headers=auth)).status_code == 201


# --------------------------------------------------------------------------- #
# The paid path
# --------------------------------------------------------------------------- #

@pytest.fixture
async def paid_rig(tmp_path, monkeypatch):
    """A payment-mode app whose RPC is faked, reusing the helpers in test_payments."""
    import test_payments as tp          # tests/ is on sys.path under pytest
    from lockerd import payments

    wallet = "0x" + "11" * 20
    receipts = {}

    async def fake_fetch(url, tx_hash):
        if tx_hash not in receipts:
            raise payments.RPCError("unknown tx")
        return receipts[tx_hash]

    monkeypatch.setattr(payments, "get_transaction_receipt", fake_fetch)
    path = str(tmp_path / "p.db")
    app = create_app(cfg.Config(db_path=path, auth_mode=cfg.AUTH_TXID,
                                payment_wallet_address=wallet))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://t") as c:
            yield c, app, app.state.store, path, receipts, tp, wallet


def tx(n: int) -> str:
    return "0x" + f"{n:064x}"


async def test_paid_creation_is_one_unit_and_does_not_consume_the_payment(paid_rig):
    """A failure between the receipt and the ticket must leave the tx redeemable."""
    client, app, store, path, receipts, tp, wallet = paid_rig
    receipts[tx(7)] = tp.make_receipt(logs=[tp.make_transfer_log(wallet, 2000)])

    store.conn = Failing(store.conn, "INSERT INTO tickets", RuntimeError("injected: ticket insert failed"))
    try:
        with pytest.raises(RuntimeError):
            await client.post("/v1/pads", headers={"X-Payment-Proof": tx(7)},
                              json={"ttl_seconds": 3600, "max_blocks": 4})
    finally:
        store.conn = store.conn._real

    assert raw(path, "SELECT tx_hash FROM payment_receipts WHERE tx_hash=?", (tx(7),)) == [], \
        "the receipt was committed even though the pad was not"
    assert raw(path, "SELECT id FROM pads WHERE id != 'demo-pad-v1'") == []

    # Replay protection still holds for a *successful* redemption, and the payment was
    # not consumed by the failure, so the caller may retry.
    ok = await client.post("/v1/pads", headers={"X-Payment-Proof": tx(7)},
                           json={"ttl_seconds": 3600, "max_blocks": 4})
    assert ok.status_code == 201, ok.text
    again = await client.post("/v1/pads", headers={"X-Payment-Proof": tx(7)},
                              json={"ttl_seconds": 3600, "max_blocks": 4})
    assert again.status_code == 409, again.text
    assert len(raw(path, "SELECT tx_hash FROM payment_receipts WHERE tx_hash=?", (tx(7),))) == 1


async def test_paid_creation_lands_pad_ticket_and_receipt_together(paid_rig):
    client, app, store, path, receipts, tp, wallet = paid_rig
    receipts[tx(9)] = tp.make_receipt(logs=[tp.make_transfer_log(wallet, 2000)])
    r = await client.post("/v1/pads", headers={"X-Payment-Proof": tx(9)},
                          json={"ttl_seconds": 3600, "max_blocks": 4})
    assert r.status_code == 201, r.text
    pad_id = r.json()["pad_id"]
    assert raw(path, "SELECT id FROM pads WHERE id=?", (pad_id,))
    assert raw(path, "SELECT ticket_id FROM tickets WHERE pad_id=?", (pad_id,))
    assert raw(path, "SELECT amount_units FROM payment_receipts WHERE pad_id=?", (pad_id,)) == [(2000,)]


# --------------------------------------------------------------------------- #
# Item 2 — health claims
# --------------------------------------------------------------------------- #

async def test_health_connection_is_opened_read_only(rig):
    """query_only is the setting that makes health physically unable to write."""
    client, app, store, path = rig
    assert store.health_conn is not None
    q = await store.health_conn.execute("PRAGMA query_only")
    row = await q.fetchone()
    await q.close()
    assert bool(row[0]) is True, "the health connection is not read-only"
    # and it really cannot write
    with pytest.raises(sqlite3.OperationalError):
        await store.health_conn.execute("INSERT INTO pads (id, created_at, expires_at,"
                                        " write_key_hash) VALUES ('x',0,0,'y')")


async def test_health_writable_does_not_claim_a_successful_write(rig):
    """It reports SQLite's connection-level read-only flag, nothing more."""
    client, app, store, path = rig
    body = (await client.get("/health")).json()
    assert body["database"]["writable"] is True
    await store.conn.execute("PRAGMA query_only = ON")
    try:
        r = await client.get("/health")
        assert r.status_code == 503 and r.json()["database"]["writable"] is False
    finally:
        await store.conn.execute("PRAGMA query_only = OFF")
    # a filesystem-level fact is deliberately NOT what this reports: the database file
    # stays writable throughout, and health never attempts a write to find out.
    import os
    assert os.access(path, os.W_OK)


async def test_repeated_polling_does_not_accumulate_connections_or_tasks(rig):
    client, app, store, path = rig
    conn_identity = store.health_conn
    main_identity = store.conn
    tasks_before = len([t for t in asyncio.all_tasks() if not t.done()])
    for _ in range(60):
        assert (await client.get("/health")).status_code == 200
    tasks_after = len([t for t in asyncio.all_tasks() if not t.done()])
    assert store.health_conn is conn_identity, "a new health connection was created per request"
    assert store.conn is main_identity
    assert tasks_after <= tasks_before + 1, f"tasks accumulated: {tasks_before} -> {tasks_after}"


async def test_cancelled_health_request_releases_everything(rig):
    """Cursor and lock cleanup must happen on cancellation too."""
    client, app, store, path = rig
    gate = asyncio.Event()
    entered = asyncio.Event()
    real = dbmod.Store._counts

    async def slow_counts(self, conn):
        entered.set()
        await gate.wait()
        return await real(self, conn)

    store._counts = slow_counts.__get__(store, dbmod.Store)
    task = asyncio.create_task(client.get("/health"))
    await asyncio.wait_for(entered.wait(), timeout=10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    store._counts = real.__get__(store, dbmod.Store)
    gate.set()
    # nothing was left held, and the next poll works
    assert store.lock.locked() is False
    assert (await client.get("/health")).status_code == 200
    assert len(raw(path, "SELECT id FROM pads")) >= 1


async def test_health_connections_close_on_shutdown(tmp_path):
    path = str(tmp_path / "s.db")
    app = create_app(cfg.Config(db_path=path, auth_mode=cfg.AUTH_OPEN))
    async with app.router.lifespan_context(app):
        store = app.state.store
        health, main = store.health_conn, store.conn
        assert health._running is True and main._running is True
    assert health._running is False, "the health connection was left open"
    assert main._running is False
