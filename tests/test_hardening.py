"""Tests for the hardening tasks: structured errors, /health, demo pad."""
import base64
import hashlib

import httpx
import pytest

from lockerd import __version__ as LOCKERD_VERSION
from lockerd import config as cfg
from lockerd.main import create_app

ZERO = "0" * 64


@pytest.fixture
async def client(tmp_path):
    app = create_app(cfg.Config(db_path=str(tmp_path / "test.db"),
                                auth_mode=cfg.AUTH_LOCAL))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


def envelope():
    return {
        "schema": "locker.handoff.v1",
        "task_id": "task-1",
        "from_agent": "a",
        "to_agent": "b",
        "constraints": ["x"],
        "artifacts": [{"name": "f"}],
        "budget_usd": 0.0,
    }


async def create_pad(client):
    r = await client.post("/v1/pads", json={"ttl_seconds": 3600, "max_blocks": 32})
    assert r.status_code == 201, r.text
    return r.json()


# ---- Task 1: structured error bodies + ordering ----

async def test_append_nonexistent_pad_is_404_not_500(client):
    r = await client.post("/v1/pads/doesnotexist/append", content=b"x",
                          headers={"Authorization": "Bearer whatever"})
    assert r.status_code == 404
    assert r.json() == {"error": "not_found", "detail": "pad not found"}


async def test_append_pad_check_precedes_write_key_check(client):
    # Non-existent pad + NO auth must be 404 (pad existence first), not 401.
    r = await client.post("/v1/pads/doesnotexist/append", content=b"x")
    assert r.status_code == 404
    assert r.json()["error"] == "not_found"


async def test_append_bad_write_key_is_structured_401(client):
    d = await create_pad(client)
    r = await client.post(f"/v1/pads/{d['pad_id']}/append", content=b"x",
                          headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401
    assert r.json() == {"error": "unauthorized", "detail": "invalid write key"}


async def test_seal_nonexistent_pad_is_404(client):
    r = await client.post("/v1/pads/doesnotexist/seal",
                          headers={"Authorization": "Bearer x"})
    assert r.status_code == 404
    assert r.json() == {"error": "not_found", "detail": "pad not found"}


async def test_append_sealed_pad_is_structured_409(client):
    d = await create_pad(client)
    import json
    r = await client.post(f"/v1/pads/{d['pad_id']}/append",
                          content=json.dumps(envelope()).encode(),
                          headers={"Authorization": f"Bearer {d['write_key']}",
                                   "Content-Type": "application/json"})
    assert r.status_code == 201
    await client.post(f"/v1/pads/{d['pad_id']}/seal",
                      headers={"Authorization": f"Bearer {d['write_key']}"})
    r = await client.post(f"/v1/pads/{d['pad_id']}/append", content=b"x",
                          headers={"Authorization": f"Bearer {d['write_key']}"})
    assert r.status_code == 409
    assert r.json() == {"error": "conflict", "detail": "pad is sealed"}


# ---- Task 4: /health ----

async def test_health_returns_ok(client):
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"] == LOCKERD_VERSION
    assert body["database"]["writable"] is True
    assert body["database"]["wal_mode"] is True
    assert body["rpc"]["network"] == "base"
    assert body["rpc"]["reachable"] is True  # open mode never probes
    # fresh DB: only the seeded demo pad exists
    assert body["pads"] == {"total": 1, "unsealed": 0, "sealed": 1}


async def test_health_head_supported(client):
    r = await client.head("/health")
    assert r.status_code == 200
    assert r.content == b""  # HEAD returns no body


# ---- Task 8: seeded demo pad + unauthenticated reads ----

async def test_demo_pad_is_seeded(client):
    r = await client.get("/v1/pads/demo-pad-v1/manifest")
    assert r.status_code == 200
    m = r.json()
    assert m["pad_id"] == "demo-pad-v1"
    assert m["state"] == "sealed"
    assert m["block_count"] >= 1


async def test_demo_pad_reads_without_ticket(client):
    r = await client.get("/v1/pads/demo-pad-v1/blocks")
    assert r.status_code == 200
    body = r.json()
    blocks = body["blocks"]
    assert len(blocks) >= 1
    # verify the chain independently
    prev = ZERO
    for b in blocks:
        payload = base64.b64decode(b["payload_b64"])
        assert b["prev_hash"] == prev
        assert b["curr_hash"] == hashlib.sha256(prev.encode() + payload).hexdigest()
        prev = b["curr_hash"]
    assert prev == (await client.get("/v1/pads/demo-pad-v1/manifest")).json()["head_hash"]


async def test_blocks_nonexistent_pad_is_404_not_401(client):
    # Task 4: pad existence is checked before the read ticket.
    r = await client.get("/v1/pads/doesnotexist/blocks")
    assert r.status_code == 404
    assert r.json() == {"error": "not_found", "detail": "pad not found"}


async def test_demo_pad_sealed_write_is_409_with_published_key(client):
    # Task 9: the published write key "demo-write-key" verifies, then the sealed
    # state returns 409 — proving conflict handling without a secret key.
    r = await client.post("/v1/pads/demo-pad-v1/append", content=b"x",
                          headers={"Authorization": "Bearer demo-write-key"})
    assert r.status_code == 409
    assert r.json() == {"error": "conflict", "detail": "pad is sealed"}
