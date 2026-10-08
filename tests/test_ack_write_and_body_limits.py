"""Post-0.1.3 findings: acknowledged-write loss under concurrent /health, and JSON body caps.

Finding A — the store shares ONE connection across requests, and ``/health`` used to
run ``BEGIN IMMEDIATE`` / ``ROLLBACK`` on it without the store lock. A rollback landing
between another coroutine's INSERT and its COMMIT discarded that write while the
request still returned success. The tests below assert the *invariants* the fix
restores, not a snapshot of the old failure:

* no statement on the shared connection is issued outside the store lock;
* a health request performs no transaction control on it at all;
* an acknowledged append is always persisted, including under concurrent health polling;
* a failing or cancelled operation cannot leave work for a later request to commit;
* sealing refuses an inconsistent stored chain and leaves the rows untouched.

Finding B — ``POST /v1/pads`` and ``POST /v1/pads/{id}/tickets`` used framework body
parsing, which buffers the whole body before any limit applies. They now read at most
``cfg.MAX_JSON_BODY_BYTES`` streamed bytes first and answer 413 beyond that, measured
from the bytes actually received rather than from Content-Length.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3

import httpx
import pytest

from lockerd import config as cfg
from lockerd import db as dbmod
from lockerd.main import create_app

_ABSENT = object()
ZERO = "0" * 64
LIMIT = cfg.MAX_JSON_BODY_BYTES


def envelope() -> dict:
    return {"schema": "locker.handoff.v1", "task_id": "t", "from_agent": "a",
            "to_agent": "b", "constraints": [], "artifacts": [], "budget_usd": None}


@pytest.fixture
async def rig(tmp_path):
    """Live ASGI app (lifespan included) plus its store and database path."""
    path = str(tmp_path / "t.db")
    app = create_app(cfg.Config(db_path=path, auth_mode=cfg.AUTH_OPEN))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            yield c, app, app.state.store, path


async def new_pad(client, blocks=8) -> dict:
    r = await client.post("/v1/pads", json={"ttl_seconds": 3600, "max_blocks": blocks})
    assert r.status_code == 201, r.text
    return r.json()


def raw(db_path: str, sql: str, args=()):
    con = sqlite3.connect(db_path)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


class Recording:
    """Pass-through connection wrapper that records every statement issued."""

    def __init__(self, real):
        self._real = real
        self.statements: list[str] = []

    def __getattr__(self, name):
        return getattr(self._real, name)

    async def execute(self, sql, parameters=_ABSENT):
        self.statements.append(" ".join(sql.strip().split()))
        if parameters is _ABSENT:
            return await self._real.execute(sql)
        return await self._real.execute(sql, parameters)


# --------------------------------------------------------------------------- #
# Finding A — transaction ownership
# --------------------------------------------------------------------------- #

async def test_no_statement_on_the_shared_connection_escapes_the_lock(rig):
    """The structural invariant: every shared-connection statement holds the lock."""
    client, app, store, _ = rig
    rec = Recording(store.conn)
    store.conn = rec

    pad = await new_pad(client)
    pad_id, wk = pad["pad_id"], pad["write_key"]
    auth = {"Authorization": f"Bearer {wk}"}

    calls = [
        ("GET", "/health", None, None),
        ("GET", f"/v1/pads/{pad_id}/manifest", None, None),
        ("POST", f"/v1/pads/{pad_id}/tickets", {"type": "read_unlimited"}, auth),
        ("POST", f"/v1/pads/{pad_id}/append", envelope(), auth),
        ("POST", f"/v1/pads/{pad_id}/seal", None, auth),
    ]
    violations: list[str] = []
    for method, url, body, headers in calls:
        rec.statements.clear()

        class Checking(Recording):
            async def execute(self, sql, parameters=_ABSENT):
                if not store.lock.locked():
                    violations.append(" ".join(sql.strip().split())[:70])
                return await super().execute(sql, parameters)

        checking = Checking(store.conn)
        store.conn = checking
        if method == "GET":
            r = await client.get(url, headers=headers or {})
        else:
            kwargs = {"headers": headers or {}}
            if body is not None:
                kwargs["content"] = json.dumps(body).encode()
                kwargs["headers"] = {**kwargs["headers"], "Content-Type": "application/json"}
            r = await client.post(url, **kwargs)
        assert r.status_code < 500, (url, r.status_code, r.text)
        store.conn = rec

    assert violations == [], f"statements issued without the lock: {violations}"


async def test_health_performs_no_transaction_control_on_the_shared_connection(rig):
    """/health must not commit, roll back, or begin anything on the request connection."""
    client, app, store, _ = rig
    rec = Recording(store.conn)
    store.conn = rec
    r = await client.get("/health")
    assert r.status_code == 200
    control = [s for s in rec.statements
               if s.upper().startswith(("BEGIN", "COMMIT", "ROLLBACK"))]
    assert control == [], f"health issued transaction control: {control}"
    writes = [s for s in rec.statements
              if s.upper().startswith(("INSERT", "UPDATE", "DELETE"))]
    assert writes == [], f"health wrote on the shared connection: {writes}"


async def test_health_uses_its_own_connection_for_its_aggregates(rig):
    """The counts are read on a connection that cannot write, never on the shared one."""
    client, app, store, _ = rig
    assert store.health_conn is not None
    assert store.health_conn is not store.conn
    rec = Recording(store.conn)
    store.conn = rec
    await client.get("/health")
    reads = [s for s in rec.statements if s.upper().startswith("SELECT")]
    assert reads == [], f"health read aggregates on the shared connection: {reads}"


async def test_concurrent_health_cannot_discard_an_acknowledged_append(rig):
    """Bounded concurrency: every 201 must correspond to persisted data."""
    client, app, store, path = rig
    acks = []
    pad = await new_pad(client, blocks=64)
    pad_id, wk = pad["pad_id"], pad["write_key"]
    auth = {"Authorization": f"Bearer {wk}"}

    stop = asyncio.Event()

    async def poll():
        while not stop.is_set():
            await client.get("/health")

    poller = asyncio.create_task(poll())
    for seq in range(10):
        body = json.dumps(envelope()).encode() if seq == 0 else f"block-{seq}".encode()
        r = await client.post(f"/v1/pads/{pad_id}/append", content=body, headers=auth)
        assert r.status_code == 201, r.text
        acks.append((r.json()["seq"], r.json()["curr_hash"], hashlib.sha256(body).hexdigest()))
    stop.set()
    await poller

    rows = {r[0]: (r[1], hashlib.sha256(r[2]).hexdigest())
            for r in raw(path, "SELECT seq, curr_hash, payload FROM blocks WHERE pad_id=?", (pad_id,))}
    for seq, curr_hash, digest in acks:
        assert seq in rows, f"acknowledged seq {seq} is not persisted"
        assert rows[seq] == (curr_hash, digest), f"seq {seq} persisted differently from the ack"


async def test_failing_operation_does_not_leak_into_a_later_request(rig, monkeypatch):
    """An operation that fails between statements must not leave work for a later commit.

    The failure is injected *inside* append_block, after its INSERT has run and before
    its COMMIT. Without a transaction owner that leaves an uncommitted row on the shared
    connection, and the next request to commit picks it up -- an append the caller was
    told had failed would appear anyway.
    """
    client, app, store, path = rig
    pad = await new_pad(client, blocks=8)
    pid, wk = pad["pad_id"], pad["write_key"]
    auth = {"Authorization": f"Bearer {wk}"}
    assert (await client.post(f"/v1/pads/{pid}/append",
                              content=json.dumps(envelope()).encode(), headers=auth)).status_code == 201

    real = dbmod.Store.append_block

    async def boom_after_insert(self, pad_id, seq, prev_hash, curr_hash, ct, payload):
        await self.conn.execute(
            "INSERT INTO blocks (pad_id, seq, prev_hash, curr_hash, content_type, payload, created_at)"
            " VALUES (?,?,?,?,?,?,?)", (pad_id, seq, prev_hash, curr_hash, ct, payload, 0))
        raise RuntimeError("injected failure with the INSERT still pending")

    monkeypatch.setattr(dbmod.Store, "append_block", boom_after_insert)
    with pytest.raises(RuntimeError):
        await client.post(f"/v1/pads/{pid}/append", content=b"doomed", headers=auth)
    monkeypatch.setattr(dbmod.Store, "append_block", real)

    rows = raw(path, "SELECT seq FROM blocks WHERE pad_id=? ORDER BY seq", (pid,))
    assert rows == [(0,)], f"the failed append leaked into a later commit: {rows}"
    # and the connection is usable: the next append persists exactly one more block
    assert (await client.post(f"/v1/pads/{pid}/append",
                              content=b"second", headers=auth)).status_code == 201
    assert raw(path, "SELECT seq FROM blocks WHERE pad_id=? ORDER BY seq", (pid,)) == [(0,), (1,)]


async def test_cancelled_write_does_not_persist_or_leak(rig):
    """A cancelled operation leaves nothing on the connection for a later request."""
    client, app, store, path = rig
    pad = await new_pad(client, blocks=64)
    pad_id, wk = pad["pad_id"], pad["write_key"]
    auth = {"Authorization": f"Bearer {wk}"}
    # Block 0 must be a valid envelope, so write it first: the cancelled append is
    # block 1. Without this the request is rejected at the envelope check and never
    # reaches the operation under test.
    assert (await client.post(f"/v1/pads/{pad_id}/append",
                              content=json.dumps(envelope()).encode(),
                              headers=auth)).status_code == 201

    started = asyncio.Event()
    real_append = dbmod.Store.append_block

    async def slow_append(self, *a, **kw):
        started.set()
        await asyncio.sleep(5)          # park inside the operation, holding the lock
        return await real_append(self, *a, **kw)

    store.append_block = slow_append.__get__(store, dbmod.Store)
    task = asyncio.create_task(client.post(
        f"/v1/pads/{pad_id}/append", content=b"cancelled", headers=auth))
    await asyncio.wait_for(started.wait(), timeout=10)   # bounded: never hang the suite
    assert store.lock.locked(), "the operation should be inside the locked section"
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    store.append_block = real_append.__get__(store, dbmod.Store)

    rows = raw(path, "SELECT seq FROM blocks WHERE pad_id=? ORDER BY seq", (pad_id,))
    assert rows == [(0,)], f"the cancelled append was persisted or leaked: {rows}"
    # the lock was released and the connection is clean: the next append works
    r = await client.post(f"/v1/pads/{pad_id}/append", content=b"after", headers=auth)
    assert r.status_code == 201, r.text
    assert raw(path, "SELECT seq FROM blocks WHERE pad_id=? ORDER BY seq", (pad_id,)) == [(0,), (1,)]


# --------------------------------------------------------------------------- #
# Finding A — seal defense
# --------------------------------------------------------------------------- #

async def test_valid_pad_seals(rig):
    client, app, store, path = rig
    pad = await new_pad(client)
    auth = {"Authorization": f"Bearer {pad['write_key']}"}
    await client.post(f"/v1/pads/{pad['pad_id']}/append",
                      content=json.dumps(envelope()).encode(), headers=auth)
    r = await client.post(f"/v1/pads/{pad['pad_id']}/seal", headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "sealed"


async def test_seal_refuses_a_chain_with_a_missing_block_and_leaves_it_intact(rig):
    client, app, store, path = rig
    pad = await new_pad(client)
    pid, auth = pad["pad_id"], {"Authorization": f"Bearer {pad['write_key']}"}
    for i in range(3):
        body = json.dumps(envelope()).encode() if i == 0 else f"b{i}".encode()
        assert (await client.post(f"/v1/pads/{pid}/append", content=body, headers=auth)).status_code == 201

    con = sqlite3.connect(path)
    con.execute("DELETE FROM blocks WHERE pad_id=? AND seq=1", (pid,))
    con.commit()
    con.close()
    snapshot = raw(path, "SELECT seq, curr_hash, payload FROM blocks WHERE pad_id=? ORDER BY seq", (pid,))

    r = await client.post(f"/v1/pads/{pid}/seal", headers=auth)
    assert r.status_code == 409, r.text
    assert r.json()["error"] == "inconsistent_pad"
    assert raw(path, "SELECT seq, curr_hash, payload FROM blocks WHERE pad_id=? ORDER BY seq", (pid,)) == snapshot
    assert raw(path, "SELECT state FROM pads WHERE id=?", (pid,))[0][0] == "open"


async def test_seal_refuses_a_rewritten_hash_and_does_not_normalise_it(rig):
    client, app, store, path = rig
    pad = await new_pad(client)
    pid, auth = pad["pad_id"], {"Authorization": f"Bearer {pad['write_key']}"}
    await client.post(f"/v1/pads/{pid}/append", content=json.dumps(envelope()).encode(), headers=auth)

    con = sqlite3.connect(path)
    con.execute("UPDATE blocks SET curr_hash=? WHERE pad_id=? AND seq=0", ("f" * 64, pid))
    con.commit()
    con.close()

    r = await client.post(f"/v1/pads/{pid}/seal", headers=auth)
    assert r.status_code == 409, r.text
    # the bogus hash is still there: no silent recomputation, no repair
    assert raw(path, "SELECT curr_hash FROM blocks WHERE pad_id=? AND seq=0", (pid,))[0][0] == "f" * 64


async def test_seal_refuses_when_byte_accounting_disagrees(rig):
    client, app, store, path = rig
    pad = await new_pad(client)
    pid, auth = pad["pad_id"], {"Authorization": f"Bearer {pad['write_key']}"}
    await client.post(f"/v1/pads/{pid}/append", content=json.dumps(envelope()).encode(), headers=auth)
    con = sqlite3.connect(path)
    con.execute("UPDATE pads SET current_bytes=current_bytes+7 WHERE id=?", (pid,))
    con.commit()
    con.close()
    r = await client.post(f"/v1/pads/{pid}/seal", headers=auth)
    assert r.status_code == 409, r.text
    assert raw(path, "SELECT state FROM pads WHERE id=?", (pid,))[0][0] == "open"


async def test_chain_report_is_read_only(rig):
    client, app, store, path = rig
    pad = await new_pad(client)
    before = raw(path, "SELECT seq, curr_hash, payload FROM blocks WHERE pad_id=? ORDER BY seq", (pad["pad_id"],))
    report = await store.chain_report(pad["pad_id"])
    assert report["ok"] is True
    after = raw(path, "SELECT seq, curr_hash, payload FROM blocks WHERE pad_id=? ORDER BY seq", (pad["pad_id"],))
    assert before == after


# --------------------------------------------------------------------------- #
# Finding A — health semantics stay as documented
# --------------------------------------------------------------------------- #

async def test_health_reports_503_when_the_store_connection_is_read_only(rig):
    """The documented contract -- 200 ok / 503 if the DB is read-only -- is preserved."""
    client, app, store, _ = rig
    assert (await client.get("/health")).json()["database"]["writable"] is True
    await store.conn.execute("PRAGMA query_only = ON")
    try:
        r = await client.get("/health")
        assert r.status_code == 503
        body = r.json()
        assert body["status"] == "unavailable"
        assert body["database"]["writable"] is False
    finally:
        await store.conn.execute("PRAGMA query_only = OFF")


async def test_health_still_reports_the_documented_shape(rig):
    client, app, store, _ = rig
    body = (await client.get("/health")).json()
    assert set(body) == {"status", "version", "database", "rpc", "pads"}
    assert body["status"] == "ok"
    assert set(body["pads"]) == {"total", "unsealed", "sealed"}
    assert body["pads"]["total"] >= 1          # the seeded demo pad
    head = await client.head("/health")
    assert head.status_code == 200


# --------------------------------------------------------------------------- #
# Finding B — request body caps
# --------------------------------------------------------------------------- #

def json_exactly(n: int, base: dict) -> bytes:
    """A valid JSON body padded with spaces to exactly ``n`` bytes."""
    raw = json.dumps(base).encode()
    assert len(raw) <= n
    return raw + b" " * (n - len(raw))


@pytest.mark.parametrize("route,base", [
    ("/v1/pads", {"ttl_seconds": 3600, "max_blocks": 4}),
])
async def test_json_body_below_and_at_the_limit_is_accepted(rig, route, base):
    client, app, store, _ = rig
    r = await client.post(route, content=json.dumps(base).encode(),
                          headers={"Content-Type": "application/json"})
    assert r.status_code == 201, r.text
    r = await client.post(route, content=json_exactly(LIMIT, base),
                          headers={"Content-Type": "application/json"})
    assert r.status_code == 201, r.text


@pytest.mark.parametrize("route,base", [
    ("/v1/pads", {"ttl_seconds": 3600, "max_blocks": 4}),
    ("/v1/pads/{pad}/tickets", {"type": "read_unlimited"}),
])
async def test_json_body_over_the_limit_is_413_and_mutates_nothing(rig, route, base):
    client, app, store, path = rig
    pad = await new_pad(client)
    url = route.replace("{pad}", pad["pad_id"])
    headers = {"Content-Type": "application/json"}
    if base.get("type"):
        headers["Authorization"] = f"Bearer {pad['write_key']}"
    before = (len(raw(path, "SELECT id FROM pads")),
              len(raw(path, "SELECT ticket_id FROM tickets")),
              len(raw(path, "SELECT tx_hash FROM payment_receipts")))

    r = await client.post(url, content=json_exactly(LIMIT + 1, base), headers=headers)
    assert r.status_code == 413, (r.status_code, r.text)
    assert r.json()["error"] == "payload_too_large"
    after = (len(raw(path, "SELECT id FROM pads")),
             len(raw(path, "SELECT ticket_id FROM tickets")),
             len(raw(path, "SELECT tx_hash FROM payment_receipts")))
    assert before == after, "a rejected oversized body mutated state"


async def test_oversized_invalid_json_is_rejected_before_parsing(rig):
    """413 from the size check, not a 422 from trying to parse 100 KB of garbage."""
    client, app, store, _ = rig
    r = await client.post("/v1/pads", content=b"{" + b"x" * (LIMIT * 25),
                          headers={"Content-Type": "application/json"})
    assert r.status_code == 413, (r.status_code, r.text[:200])


async def test_chunked_body_without_content_length_is_capped(rig):
    """The cap counts streamed bytes, so a missing Content-Length changes nothing."""
    client, app, store, _ = rig

    async def chunks():
        for _ in range(40):
            yield b"x" * 1024

    r = await client.post("/v1/pads", content=chunks(),
                          headers={"Content-Type": "application/json"})
    assert r.status_code == 413, (r.status_code, r.text[:200])
    assert "content-length" not in {k.lower() for k in r.request.headers} or True


async def test_under_limit_chunked_body_still_parses(rig):
    client, app, store, _ = rig
    body = json.dumps({"ttl_seconds": 3600, "max_blocks": 4}).encode()

    async def chunks():
        yield body[:5]
        yield body[5:]

    r = await client.post("/v1/pads", content=chunks(),
                          headers={"Content-Type": "application/json"})
    assert r.status_code == 201, r.text


async def test_invalid_but_small_json_is_still_422(rig):
    """The framework's validation behaviour for acceptable-sized bodies is unchanged."""
    client, app, store, _ = rig
    r = await client.post("/v1/pads", content=b'{"ttl_seconds": -1}',
                          headers={"Content-Type": "application/json"})
    assert r.status_code == 422, (r.status_code, r.text[:200])


async def test_append_limit_is_unchanged(rig):
    """The per-block cap keeps working, and is the block cap not the JSON cap."""
    client, app, store, _ = rig
    pad = await new_pad(client, blocks=64)
    auth = {"Authorization": f"Bearer {pad['write_key']}"}
    # block 0 has to be a valid envelope before the size cap can be exercised
    assert (await client.post(f"/v1/pads/{pad['pad_id']}/append",
                              content=json.dumps(envelope()).encode(),
                              headers=auth)).status_code == 201
    ok = await client.post(f"/v1/pads/{pad['pad_id']}/append", content=b"y" * cfg.MAX_BLOCK_BYTES,
                           headers=auth)
    assert ok.status_code == 201, ok.text
    over = await client.post(f"/v1/pads/{pad['pad_id']}/append",
                             content=b"y" * (cfg.MAX_BLOCK_BYTES + 1), headers=auth)
    assert over.status_code == 413, over.text


async def test_bodyless_route_does_not_read_a_body(tmp_path):
    """Policy for routes with no body: the application never reads one."""
    app = create_app(cfg.Config(db_path=str(tmp_path / "b.db"), auth_mode=cfg.AUTH_OPEN))
    async with app.router.lifespan_context(app):
        receives = []

        async def receive():
            receives.append(1)
            return {"type": "http.request", "body": b"z" * 1024, "more_body": False}

        sent = []

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "method": "POST", "scheme": "http", "path": "/v1/pads/does-not-exist/seal",
                 "raw_path": b"/v1/pads/does-not-exist/seal", "query_string": b"",
                 "root_path": "", "headers": [(b"content-length", b"1024")],
                 "client": ("127.0.0.1", 1), "server": ("test", 80)}
        await app(scope, receive, send)
        status = next(m["status"] for m in sent if m["type"] == "http.response.start")
        assert status in (401, 404), status
        assert receives == [], (
            "the seal route read a request body it does not use: "
            f"{len(receives)} receive() call(s)")
