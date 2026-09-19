"""Behavioral tests for the Agent Locker Daemon, written against the spec'd API."""
import base64
import hashlib
import json
import time

import aiosqlite
import httpx
import pytest

from lockerd import config as cfg
from lockerd.main import create_app

ZERO = "0" * 64


@pytest.fixture
async def client(tmp_path):
    app = create_app(cfg.Config(db_path=str(tmp_path / "test.db"), auth_mode=cfg.AUTH_LOCAL))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


async def create_pad(client, ttl=3600, max_blocks=32):
    r = await client.post("/v1/pads", json={"ttl_seconds": ttl, "max_blocks": max_blocks})
    assert r.status_code == 201, r.text
    return r.json()


async def append(client, pad_id, write_key, payload, content_type="application/json"):
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload).encode()
    elif isinstance(payload, str):
        payload = payload.encode()
    return await client.post(
        f"/v1/pads/{pad_id}/append",
        content=payload,
        headers={"Authorization": f"Bearer {write_key}", "Content-Type": content_type},
    )


def envelope(**kw):
    e = {
        "schema": "locker.handoff.v1",
        "task_id": "task-1",
        "from_agent": "agent-a",
        "to_agent": "agent-b",
        "constraints": ["be concise"],
        "artifacts": [{"name": "input.txt", "size": 10}],
        "budget_usd": 0.5,
    }
    e.update(kw)
    return e


# ---- creation ----

async def test_create_pad_returns_keys(client):
    d = await create_pad(client, ttl=3600, max_blocks=8)
    assert len(d["pad_id"]) == 32
    assert d["write_key"] and d["read_ticket"]
    assert d["write_key"] != d["read_ticket"]


async def test_create_pad_validation(client):
    bad = [
        {"ttl_seconds": 0, "max_blocks": 4},
        {"ttl_seconds": -5, "max_blocks": 4},
        {"ttl_seconds": "abc", "max_blocks": 4},
        {"ttl_seconds": 60, "max_blocks": 0},
        {"ttl_seconds": 60, "max_blocks": -1},
        {"ttl_seconds": 60, "max_blocks": "abc"},
    ]
    for body in bad:
        r = await client.post("/v1/pads", json=body)
        assert r.status_code == 422, body
    r = await client.post("/v1/pads", content=b"not json",
                          headers={"Content-Type": "application/json"})
    assert r.status_code == 422


# ---- manifest ----

async def test_manifest_is_free_no_ticket(client):
    d = await create_pad(client)
    r = await client.get(f"/v1/pads/{d['pad_id']}/manifest")
    assert r.status_code == 200
    m = r.json()
    assert m["state"] == "open"
    assert m["block_count"] == 0
    assert m["head_hash"] == ZERO


# ---- append / hash chain ----

async def test_append_envelope_then_chain(client):
    d = await create_pad(client)
    env = envelope()
    p0 = json.dumps(env).encode()

    r0 = await append(client, d["pad_id"], d["write_key"], p0)
    assert r0.status_code == 201, r0.text
    b0 = r0.json()
    assert b0["seq"] == 0

    p1 = b"second block payload"
    r1 = await append(client, d["pad_id"], d["write_key"], p1)
    assert r1.status_code == 201
    b1 = r1.json()
    assert b1["seq"] == 1

    assert b0["curr_hash"] == hashlib.sha256(ZERO.encode() + p0).hexdigest()
    assert b1["curr_hash"] == hashlib.sha256(b0["curr_hash"].encode() + p1).hexdigest()

    m = (await client.get(f"/v1/pads/{d['pad_id']}/manifest")).json()
    assert m["block_count"] == 2
    assert m["head_hash"] == b1["curr_hash"]


async def test_block_zero_must_be_envelope(client):
    d = await create_pad(client)
    r = await append(client, d["pad_id"], d["write_key"], envelope(schema="something.else"))
    assert r.status_code == 400
    r = await append(client, d["pad_id"], d["write_key"], b"not json")
    assert r.status_code == 400
    for field in ["task_id", "from_agent", "to_agent", "constraints", "artifacts", "budget_usd"]:
        env = envelope()
        env.pop(field)
        r = await append(client, d["pad_id"], d["write_key"], env)
        assert r.status_code == 400, field
    r = await append(client, d["pad_id"], d["write_key"], envelope(constraints="not a list"))
    assert r.status_code == 400


async def test_append_rejects_bad_write_key(client):
    d = await create_pad(client)
    r = await append(client, d["pad_id"], "wrong-key", envelope())
    assert r.status_code == 401


async def test_append_missing_auth(client):
    d = await create_pad(client)
    r = await client.post(f"/v1/pads/{d['pad_id']}/append", content=b"x")
    assert r.status_code == 401


async def test_append_empty_payload(client):
    d = await create_pad(client)
    r = await client.post(
        f"/v1/pads/{d['pad_id']}/append", content=b"",
        headers={"Authorization": f"Bearer {d['write_key']}"},
    )
    assert r.status_code == 400


async def test_append_rejects_oversize_payload(client):
    d = await create_pad(client)
    big = b"x" * (cfg.MAX_BLOCK_BYTES + 1)
    r = await append(client, d["pad_id"], d["write_key"], big)
    assert r.status_code == 413


async def test_append_rejects_over_block_quota(client):
    d = await create_pad(client, max_blocks=2)
    assert (await append(client, d["pad_id"], d["write_key"], envelope())).status_code == 201
    assert (await append(client, d["pad_id"], d["write_key"], b"block 1")).status_code == 201
    r = await append(client, d["pad_id"], d["write_key"], b"block 2")
    assert r.status_code == 409


async def test_append_rejects_over_byte_quota(client):
    d = await create_pad(client)  # default max_bytes 256 KB
    assert (await append(client, d["pad_id"], d["write_key"], envelope())).status_code == 201
    block = b"x" * cfg.MAX_BLOCK_BYTES
    ok = 0
    for _ in range(8):
        r = await append(client, d["pad_id"], d["write_key"], block)
        if r.status_code == 409:
            assert "byte" in r.text.lower()
            break
        assert r.status_code == 201
        ok += 1
    else:
        pytest.fail("byte quota never enforced")
    assert ok >= 3
    m = (await client.get(f"/v1/pads/{d['pad_id']}/manifest")).json()
    assert m["total_bytes"] <= cfg.DEFAULT_MAX_BYTES


async def test_append_rejects_expired_pad(client, monkeypatch):
    d = await create_pad(client, ttl=60)
    monkeypatch.setattr("lockerd.db.now", lambda: int(time.time()) + 9999)
    r = await append(client, d["pad_id"], d["write_key"], envelope())
    assert r.status_code == 410
    m = (await client.get(f"/v1/pads/{d['pad_id']}/manifest")).json()
    assert m["state"] == "expired"


# ---- seal ----

async def test_seal_revokes_writes(client):
    d = await create_pad(client)
    assert (await append(client, d["pad_id"], d["write_key"], envelope())).status_code == 201
    r = await client.post(
        f"/v1/pads/{d['pad_id']}/seal",
        headers={"Authorization": f"Bearer {d['write_key']}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "sealed"
    assert body["sealed_at"] is not None
    assert (await append(client, d["pad_id"], d["write_key"], b"after seal")).status_code == 409
    r = await client.post(
        f"/v1/pads/{d['pad_id']}/seal",
        headers={"Authorization": f"Bearer {d['write_key']}"},
    )
    assert r.status_code == 409


async def test_seal_requires_write_key(client):
    d = await create_pad(client)
    r = await client.post(
        f"/v1/pads/{d['pad_id']}/seal", headers={"Authorization": "Bearer wrong"}
    )
    assert r.status_code == 401


# ---- blocks / tickets ----

async def test_blocks_requires_ticket(client):
    d = await create_pad(client)
    assert (await append(client, d["pad_id"], d["write_key"], envelope())).status_code == 201
    r = await client.get(f"/v1/pads/{d['pad_id']}/blocks")
    assert r.status_code == 401


async def test_blocks_invalid_ticket(client):
    d = await create_pad(client)
    assert (await append(client, d["pad_id"], d["write_key"], envelope())).status_code == 201
    r = await client.get(f"/v1/pads/{d['pad_id']}/blocks", params={"ticket": "nope"})
    assert r.status_code == 401


async def test_blocks_wrong_ticket_for_other_pad(client):
    d1 = await create_pad(client)
    d2 = await create_pad(client)
    assert (await append(client, d1["pad_id"], d1["write_key"], envelope())).status_code == 201
    r = await client.get(f"/v1/pads/{d1['pad_id']}/blocks", params={"ticket": d2["read_ticket"]})
    assert r.status_code == 401


async def test_read_once_allows_slicing_within_lease(client):
    d = await create_pad(client)
    assert (await append(client, d["pad_id"], d["write_key"], envelope())).status_code == 201
    assert (await append(client, d["pad_id"], d["write_key"], b"payload-1")).status_code == 201
    # read block 0 (envelope) first — this opens the lease
    r = await client.get(f"/v1/pads/{d['pad_id']}/blocks",
                         params={"ticket": d["read_ticket"], "from": 0, "to": 0})
    assert r.status_code == 200
    assert [b["seq"] for b in r.json()["blocks"]] == [0]
    # reading block 1 with the SAME ticket must still work within the lease
    r = await client.get(f"/v1/pads/{d['pad_id']}/blocks",
                         params={"ticket": d["read_ticket"], "from": 1, "to": 1})
    assert r.status_code == 200
    assert [b["seq"] for b in r.json()["blocks"]] == [1]


async def test_read_once_lease_expires(client, monkeypatch):
    d = await create_pad(client)
    assert (await append(client, d["pad_id"], d["write_key"], envelope())).status_code == 201
    r = await client.get(f"/v1/pads/{d['pad_id']}/blocks", params={"ticket": d["read_ticket"]})
    assert r.status_code == 200  # first read opens the lease
    monkeypatch.setattr("lockerd.db.now", lambda: int(time.time()) + 9999)
    r = await client.get(f"/v1/pads/{d['pad_id']}/blocks", params={"ticket": d["read_ticket"]})
    assert r.status_code == 403  # lease expired


async def test_blocks_range(client):
    d = await create_pad(client)
    assert (await append(client, d["pad_id"], d["write_key"], envelope())).status_code == 201
    assert (await append(client, d["pad_id"], d["write_key"], b"b1")).status_code == 201
    assert (await append(client, d["pad_id"], d["write_key"], b"b2")).status_code == 201
    r = await client.get(
        f"/v1/pads/{d['pad_id']}/blocks",
        params={"ticket": d["read_ticket"], "from": 0, "to": 1},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 2
    assert [b["seq"] for b in data["blocks"]] == [0, 1]


async def test_blocks_slice_exceeds_response_limit(client):
    d = await create_pad(client)
    assert (await append(client, d["pad_id"], d["write_key"], envelope())).status_code == 201
    for _ in range(2):
        assert (await append(client, d["pad_id"], d["write_key"],
                             b"x" * cfg.MAX_BLOCK_BYTES)).status_code == 201
    r = await client.get(
        f"/v1/pads/{d['pad_id']}/blocks",
        params={"ticket": d["read_ticket"], "from": 0, "to": 2},
    )
    assert r.status_code == 413


# ---- tamper evidence ----

async def test_hash_chain_detects_tampering(client, tmp_path):
    d = await create_pad(client)
    assert (await append(client, d["pad_id"], d["write_key"], envelope())).status_code == 201
    assert (await append(client, d["pad_id"], d["write_key"],
                         b"integrity-protected")).status_code == 201

    r = await client.get(f"/v1/pads/{d['pad_id']}/blocks", params={"ticket": d["read_ticket"]})
    blocks = r.json()["blocks"]
    prev = ZERO
    for b in blocks:
        payload = base64.b64decode(b["payload_b64"])
        assert b["prev_hash"] == prev
        assert b["curr_hash"] == hashlib.sha256(prev.encode() + payload).hexdigest()
        prev = b["curr_hash"]

    # Tamper with a stored payload directly; the chain must now diverge.
    conn = await aiosqlite.connect(str(tmp_path / "test.db"))
    conn.row_factory = aiosqlite.Row
    await conn.execute("UPDATE blocks SET payload=? WHERE pad_id=? AND seq=1",
                       (b"tampered", d["pad_id"]))
    await conn.commit()
    cur = await conn.execute(
        "SELECT seq, prev_hash, curr_hash, payload FROM blocks WHERE pad_id=? ORDER BY seq",
        (d["pad_id"],),
    )
    rows = await cur.fetchall()
    await cur.close()
    await conn.close()

    prev = ZERO
    diverged = False
    for row in rows:
        expect = hashlib.sha256(prev.encode() + row["payload"]).hexdigest()
        if row["curr_hash"] != expect:
            diverged = True
            break
        prev = row["curr_hash"]
    assert diverged


# ---- x402 payment rail: covered comprehensively in tests/test_payments.py ----


# ---- ticket minting (read_unlimited audit tickets) ----

async def test_mint_read_unlimited_ticket(client):
    d = await create_pad(client)
    r = await client.post(
        f"/v1/pads/{d['pad_id']}/tickets",
        json={"type": "read_unlimited"},
        headers={"Authorization": f"Bearer {d['write_key']}"},
    )
    assert r.status_code == 201, r.text
    ticket = r.json()
    assert ticket["pad_id"] == d["pad_id"]
    assert ticket["type"] == "read_unlimited"
    assert ticket["ticket"] and ticket["ticket"] != d["read_ticket"]
    # the minted ticket reads blocks
    r2 = await client.get(f"/v1/pads/{d['pad_id']}/blocks", params={"ticket": ticket["ticket"]})
    assert r2.status_code == 200


async def test_mint_read_once_ticket(client):
    d = await create_pad(client)
    r = await client.post(
        f"/v1/pads/{d['pad_id']}/tickets",
        json={"type": "read_once"},
        headers={"Authorization": f"Bearer {d['write_key']}"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["type"] == "read_once"


async def test_mint_ticket_requires_write_key(client):
    d = await create_pad(client)
    r = await client.post(f"/v1/pads/{d['pad_id']}/tickets", json={"type": "read_unlimited"})
    assert r.status_code == 401
    r = await client.post(
        f"/v1/pads/{d['pad_id']}/tickets",
        json={"type": "read_unlimited"},
        headers={"Authorization": "Bearer wrong-key"},
    )
    assert r.status_code == 401


async def test_mint_ticket_rejects_bad_type(client):
    d = await create_pad(client)
    r = await client.post(
        f"/v1/pads/{d['pad_id']}/tickets",
        json={"type": "bogus"},
        headers={"Authorization": f"Bearer {d['write_key']}"},
    )
    assert r.status_code == 422


# ---- block 0 allowed_paths (optional, type-checked) ----

async def test_allowed_paths_optional_and_typechecked(client):
    d = await create_pad(client)
    assert (await append(client, d["pad_id"], d["write_key"],
                         envelope(allowed_paths=["src/*", "tests/*"]))).status_code == 201
    d2 = await create_pad(client)
    assert (await append(client, d2["pad_id"], d2["write_key"],
                         envelope(allowed_paths=None))).status_code == 201
    d3 = await create_pad(client)
    assert (await append(client, d3["pad_id"], d3["write_key"],
                         envelope(allowed_paths="src/*"))).status_code == 400
    d4 = await create_pad(client)
    assert (await append(client, d4["pad_id"], d4["write_key"],
                         envelope(allowed_paths=[1, 2]))).status_code == 400
