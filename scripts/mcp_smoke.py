"""Local smoke test: two simulated agent sessions hand off a task through the
locker over the MCP tools (stdio). Also demonstrates the under-the-hood
integrity verification catching a tampered block.

Run with the project venv:  .venv/bin/python scripts/mcp_smoke.py
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


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def mcp_params(locker_url: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable, args=["-m", "lockermcp"],
        env={**os.environ, "LOCKER_URL": locker_url}, cwd=REPO_ROOT,
    )


async def call_tool(session, name, arguments):
    result = await session.call_tool(name, arguments)
    if getattr(result, "structuredContent", None):
        return result.structuredContent
    for block in result.content:
        if getattr(block, "text", None):
            return json.loads(block.text)
    raise RuntimeError(f"tool {name} returned no usable content: {result!r}")


async def agent_a_write_and_seal(locker_url: str, task_id: str, payload_text: str) -> dict:
    """Writer agent: create pad, append envelope + payload, seal; returns handoff."""
    async with stdio_client(mcp_params(locker_url)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            created = await call_tool(session, "locker_create",
                                      {"ttl_seconds": 3600, "max_blocks": 8})
            pad_id, write_key = created["pad_id"], created["write_key"]
            envelope = {
                "schema": "locker.handoff.v1",
                "task_id": task_id,
                "from_agent": "agent-a",
                "to_agent": "agent-b",
                "constraints": ["be concise"],
                "artifacts": [{"name": "report.txt", "size": 1234}],
                "budget_usd": 1.25,
            }
            await call_tool(session, "locker_append",
                            {"pad_id": pad_id, "write_key": write_key, "payload": envelope})
            await call_tool(session, "locker_append",
                            {"pad_id": pad_id, "write_key": write_key,
                             "payload": payload_text, "content_type": "text/plain"})
            sealed = await call_tool(session, "locker_seal",
                                     {"pad_id": pad_id, "write_key": write_key})
            return {"pad_id": pad_id, "read_ticket": created["read_ticket"],
                    "head_hash": sealed["head_hash"]}


async def agent_b_reads(locker_url: str, handoff: dict) -> tuple:
    """Reader agent: manifest (verified) + envelope-first read + payload read."""
    async with stdio_client(mcp_params(locker_url)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            pad_id, ticket = handoff["pad_id"], handoff["read_ticket"]

            manifest = await call_tool(session, "locker_manifest",
                                       {"pad_id": pad_id, "ticket": ticket})
            env = await call_tool(session, "locker_read_blocks",
                                  {"pad_id": pad_id, "ticket": ticket})
            rest = await call_tool(session, "locker_read_blocks",
                                   {"pad_id": pad_id, "ticket": ticket,
                                    "from_block": 1, "to_block": 1})
            return manifest, env, rest


async def main() -> None:
    locker_url = os.environ.get("LOCKER_URL")
    daemon = None
    dbpath = None
    if locker_url is None:
        port = free_port()
        dbpath = f"/tmp/locker_mcp_smoke_{os.getpid()}.db"
        locker_url = f"http://127.0.0.1:{port}"
        env = {**os.environ, "LOCKER_DB": dbpath, "AUTH_MODE": "local"}
        daemon = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "lockerd.main:create_app",
             "--factory", "--host", "127.0.0.1", "--port", str(port)],
            env=env, cwd=REPO_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
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

    print(f"=== daemon at {locker_url} ===")

    # --- Scenario 1: clean handoff, chain must verify ---
    h1 = await agent_a_write_and_seal(locker_url, "task-42", "the actual handoff payload")
    print(f"[A] wrote + sealed pad {h1['pad_id']}")
    manifest, env, rest = await agent_b_reads(locker_url, h1)
    assert manifest["integrity"]["chain_valid"] is True, "manifest chain should verify"
    assert manifest["integrity"]["blocks_verified"] == 2
    assert env["integrity"]["chain_valid"] is True
    assert env["integrity"]["blocks_verified"] == 2
    assert rest["integrity"]["chain_valid"] is True
    block0 = env["blocks"][0]
    block1 = rest["blocks"][0]
    env_payload = json.loads(base64.b64decode(block0["payload_b64"]))
    assert env_payload["task_id"] == "task-42" and env_payload["to_agent"] == "agent-b"
    assert block1["payload_utf8"] == "the actual handoff payload"
    print(f"[B] clean handoff: chain_valid=True, blocks_verified=2, "
          f"envelope task_id={env_payload['task_id']}, payload={block1['payload_utf8']!r}")

    # --- Scenario 2: tamper a block, chain must fail ---
    h2 = await agent_a_write_and_seal(locker_url, "task-43", "tamper-me payload")
    assert dbpath, "tamper scenario needs a local DB path"
    conn = sqlite3.connect(dbpath)
    conn.execute("UPDATE blocks SET payload=? WHERE pad_id=? AND seq=1",
                 (b"tampered payload", h2["pad_id"]))
    conn.commit()
    conn.close()
    print(f"[T] tampered block 1 of pad {h2['pad_id']}")
    manifest2, env2, _ = await agent_b_reads(locker_url, h2)
    assert manifest2["integrity"]["chain_valid"] is False, "tampered chain must NOT verify"
    assert env2["integrity"]["chain_valid"] is False
    print(f"[B] tampered pad: chain_valid=False (blocks_verified="
          f"{manifest2['integrity']['blocks_verified']}) — tamper detected")

    print("\nMCP SMOKE TEST PASSED")

    if daemon is not None:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()


if __name__ == "__main__":
    asyncio.run(main())
