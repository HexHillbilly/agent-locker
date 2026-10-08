"""End-to-end handoff test over lockermcp (stdio).

Planner initializes a pad, writes a strict Block 0 envelope + Block 1 payload,
and seals. Worker reads the manifest, envelope (inspects constraints), payload,
and asserts chain_valid == True. Also checks: post-seal write is rejected,
read-lease expiry is enforced, and a tampered block makes the read fail closed
(verification_failed, no payload) rather than returning tampered content.

Run with the project venv:  .venv/bin/python scripts/test_handoff_e2e.py
Starts its own daemon on a free port unless LOCKER_URL is set.
"""
import asyncio
import base64
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEASE_SECONDS = 3


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def mcp_params(url: str) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "lockermcp"],
                                 env={**os.environ, "LOCKER_URL": url}, cwd=REPO_ROOT)


class ToolError(RuntimeError):
    pass


async def call_tool(session, name, arguments):
    result = await session.call_tool(name, arguments)
    is_err = getattr(result, "isError", False) or any(
        getattr(b, "isError", False) for b in getattr(result, "content", [])
    )
    if is_err:
        msg = "".join(getattr(b, "text", "") for b in getattr(result, "content", []))
        raise ToolError(f"{name} failed: {msg.strip()}")
    if getattr(result, "structuredContent", None):
        return result.structuredContent
    for block in getattr(result, "content", []):
        if getattr(block, "text", None):
            try:
                return json.loads(block.text)
            except json.JSONDecodeError:
                raise ToolError(f"{name}: {block.text.strip()}")
    raise ToolError(f"{name} returned no usable content")


async def planner(session) -> dict:
    """Planner agent: create pad, write envelope + payload, seal; reject post-seal write."""
    created = await call_tool(session, "locker_create", {"ttl_seconds": 300, "max_blocks": 8})
    pad_id, write_key, read_ticket = created["pad_id"], created["write_key"], created["read_ticket"]

    envelope = {
        "schema": "locker.handoff.v1",
        "task_id": "e2e-task-1",
        "from_agent": "planner",
        "to_agent": "worker",
        "constraints": ["keep it under 200 words", "cite sources"],
        "artifacts": [{"name": "brief.md", "size": 512}],
        "budget_usd": 0.75,
    }
    b0 = await call_tool(session, "locker_append",
                         {"pad_id": pad_id, "write_key": write_key, "payload": envelope})
    b1 = await call_tool(session, "locker_append",
                         {"pad_id": pad_id, "write_key": write_key,
                          "payload": "block-1 payload", "content_type": "text/plain"})
    sealed = await call_tool(session, "locker_seal",
                             {"pad_id": pad_id, "write_key": write_key})

    # Post-seal write must be rejected (409)
    r = await call_tool(session, "locker_append",
                        {"pad_id": pad_id, "write_key": write_key, "payload": "sneaky"})
    assert "error" in r and r["error"]["status"] == 409, f"expected 409, got: {r}"

    return {"pad_id": pad_id, "read_ticket": read_ticket,
            "head_hash": sealed["head_hash"], "seqs": (b0["seq"], b1["seq"])}


async def worker(session, handoff: dict):
    """Worker agent: manifest, envelope (inspect constraints), payload, verify chain."""
    pad_id, ticket = handoff["pad_id"], handoff["read_ticket"]

    manifest = await call_tool(session, "locker_manifest",
                               {"pad_id": pad_id, "ticket": ticket})
    assert manifest["integrity"]["chain_valid"] is True
    assert manifest["state"] == "sealed" and manifest["block_count"] == 2

    env = await call_tool(session, "locker_read_blocks",
                          {"pad_id": pad_id, "ticket": ticket})
    assert env["integrity"]["chain_valid"] is True
    assert env["integrity"]["blocks_verified"] == 2
    block0 = env["blocks"][0]
    envelope = json.loads(base64.b64decode(block0["payload_b64"]))
    constraints = envelope["constraints"]
    assert isinstance(constraints, list) and all(isinstance(c, str) for c in constraints)

    rest = await call_tool(session, "locker_read_blocks",
                           {"pad_id": pad_id, "ticket": ticket,
                            "from_block": 1, "to_block": 1})
    block1 = rest["blocks"][0]
    assert rest["integrity"]["chain_valid"] is True
    assert block1["payload_utf8"] == "block-1 payload"

    return envelope, block1


async def main() -> None:
    url = os.environ.get("LOCKER_URL")
    daemon = None
    dbpath = None
    if url is None:
        port = free_port()
        dbpath = f"/tmp/locker_e2e_{os.getpid()}.db"
        url = f"http://127.0.0.1:{port}"
        env = {**os.environ, "LOCKER_DB_PATH": dbpath, "LOCKER_MODE": "local",
               "LOCKER_READ_LEASE_SECONDS": str(LEASE_SECONDS)}
        daemon = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "lockerd.main:create_app",
             "--factory", "--host", "127.0.0.1", "--port", str(port)],
            env=env, cwd=REPO_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
                s.close()
                break
            except OSError:
                await asyncio.sleep(0.1)
        else:
            raise RuntimeError("daemon did not become ready")

    print(f"=== daemon at {url} (lease {LEASE_SECONDS}s) ===")

    # Planner
    async with stdio_client(mcp_params(url)) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            handoff = await planner(session)
    print(f"[planner] sealed pad {handoff['pad_id']} (seqs {handoff['seqs']}); "
          f"post-seal write rejected (409)")

    # Worker
    async with stdio_client(mcp_params(url)) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            envelope, block1 = await worker(session, handoff)
    print(f"[worker] chain_valid=True; constraints={envelope['constraints']}; "
          f"payload={block1['payload_utf8']!r}")

    # Tamper: corrupt block 1 in the DB. The re-read must fail CLOSED.
    #
    # [C] This assertion was previously the opposite: the tampered read returned the
    # blocks with chain_valid=False and no top-level error, which preserved the
    # pre-0.1.2 response contract. That contract delivered tampered payloads to any
    # caller that did not inspect the integrity block. Chain verification failures
    # now return an error and no payload, anchored or not. The expectation is
    # updated rather than the unsafe output preserved to keep this test green.
    assert dbpath, "tamper check needs a local DB"
    conn = sqlite3.connect(dbpath)
    conn.execute("UPDATE blocks SET payload=? WHERE pad_id=? AND seq=1",
                 (b"tampered", handoff["pad_id"]))
    conn.commit()
    conn.close()
    print("[tamper] corrupted block 1 payload in the DB")

    async with stdio_client(mcp_params(url)) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            # still inside the read lease -> must fail closed now
            env = await call_tool(session, "locker_read_blocks",
                                  {"pad_id": handoff["pad_id"], "ticket": handoff["read_ticket"]})
            err = env.get("error")
            assert err, f"tampered read returned a result instead of an error: {env}"
            assert err["kind"] == "verification_failed", err
            assert err["cause"] == "chain_inconsistent", err
            assert "blocks" not in env, "a tampered read returned payloads"
            assert env["integrity"]["verdict"] == "failed"
            assert "tampered" not in json.dumps(env), "the error echoed the tampered payload"
            print(f"[tamper] verification_failed (cause={err['cause']}) — no payload "
                  f"returned, tamper detected")

            # then let the lease expire and confirm reads are rejected
            print(f"[lease] sleeping {LEASE_SECONDS + 1}s to expire the read lease...")
            await asyncio.sleep(LEASE_SECONDS + 1)
            r = await call_tool(session, "locker_read_blocks",
                                {"pad_id": handoff["pad_id"], "ticket": handoff["read_ticket"]})
            assert "error" in r and r["error"]["status"] == 403, \
                f"expected 403 after lease expiry, got: {r}"
    print("[lease] read after expiry correctly rejected (403)")

    print("\nE2E HANDOFF TEST PASSED")

    if daemon is not None:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()


if __name__ == "__main__":
    asyncio.run(main())
