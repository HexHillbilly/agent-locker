"""Local smoke test: two simulated agent sessions hand off a task through the
locker, driven end-to-end over the MCP tools (stdio).

Run with the project venv:  .venv/bin/python scripts/mcp_smoke.py
It starts its own daemon on a free port unless LOCKER_URL is set.
"""
import asyncio
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZERO = "0" * 64


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def mcp_params(locker_url: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "lockermcp"],
        env={**os.environ, "LOCKER_URL": locker_url},
        cwd=REPO_ROOT,
    )


async def call_tool(session, name, arguments):
    result = await session.call_tool(name, arguments)
    if getattr(result, "structuredContent", None):
        return result.structuredContent
    for block in result.content:
        if getattr(block, "text", None):
            return json.loads(block.text)
    raise RuntimeError(f"tool {name} returned no usable content: {result!r}")


async def agent_a_writes(locker_url: str, handoff: dict) -> None:
    """Writer agent: create pad, append envelope + payload, seal."""
    async with stdio_client(mcp_params(locker_url)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            created = await call_tool(session, "locker_create",
                                      {"ttl_seconds": 3600, "max_blocks": 8})
            pad_id, write_key = created["pad_id"], created["write_key"]
            print(f"[A] created pad {pad_id}")

            envelope = {
                "schema": "locker.handoff.v1",
                "task_id": "task-42",
                "from_agent": "agent-a",
                "to_agent": "agent-b",
                "constraints": ["be concise", "cite sources"],
                "artifacts": [{"name": "report.txt", "size": 1234}],
                "budget_usd": 1.25,
            }
            b0 = await call_tool(session, "locker_append",
                                 {"pad_id": pad_id, "write_key": write_key,
                                  "payload": envelope})
            print(f"[A] appended block 0 (envelope) seq={b0['seq']}")

            b1 = await call_tool(session, "locker_append",
                                 {"pad_id": pad_id, "write_key": write_key,
                                  "payload": "the actual handoff payload",
                                  "content_type": "text/plain"})
            print(f"[A] appended block 1 seq={b1['seq']}")

            sealed = await call_tool(session, "locker_seal",
                                     {"pad_id": pad_id, "write_key": write_key})
            print(f"[A] sealed: state={sealed['state']}")

            handoff["pad_id"] = pad_id
            handoff["read_ticket"] = created["read_ticket"]
            handoff["head_hash"] = sealed["head_hash"]


async def agent_b_reads(locker_url: str, handoff: dict) -> None:
    """Reader agent: grab the envelope first (default), then the payload, verify chain."""
    async with stdio_client(mcp_params(locker_url)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            pad_id, ticket = handoff["pad_id"], handoff["read_ticket"]

            manifest = await call_tool(session, "locker_manifest", {"pad_id": pad_id})
            print(f"[B] manifest: state={manifest['state']} blocks={manifest['block_count']}")

            # default read grabs block 0 (the envelope) first
            env_result = await call_tool(session, "locker_read_blocks",
                                         {"pad_id": pad_id, "ticket": ticket})
            block0 = env_result["blocks"][0]
            env_payload = json.loads(base64.b64decode(block0["payload_b64"]))
            print(f"[B] envelope (block 0) task_id={env_payload['task_id']} "
                  f"from={env_payload['from_agent']} to={env_payload['to_agent']}")

            # then read block 1 with the same ticket (within the read lease)
            rest = await call_tool(session, "locker_read_blocks",
                                   {"pad_id": pad_id, "ticket": ticket,
                                    "from_block": 1, "to_block": 1})
            block1 = rest["blocks"][0]
            print(f"[B] payload (block 1): {block1['payload_utf8']}")

            # verify the chain genesis -> head
            prev = ZERO
            for b in (block0, block1):
                payload = base64.b64decode(b["payload_b64"])
                expect = hashlib.sha256(prev.encode() + payload).hexdigest()
                assert b["prev_hash"] == prev, "prev_hash mismatch"
                assert b["curr_hash"] == expect, "curr_hash mismatch"
                prev = b["curr_hash"]
            assert prev == manifest["head_hash"], "chain head != manifest head"
            assert prev == handoff["head_hash"], "chain head != seal head"
            print("[B] hash chain verified (genesis -> head)")


async def main() -> None:
    locker_url = os.environ.get("LOCKER_URL")
    daemon = None
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
    handoff: dict = {}
    await agent_a_writes(locker_url, handoff)
    print("--- handoff A -> B ---")
    await agent_b_reads(locker_url, handoff)
    print("\nMCP SMOKE TEST PASSED")

    if daemon is not None:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()


if __name__ == "__main__":
    asyncio.run(main())
