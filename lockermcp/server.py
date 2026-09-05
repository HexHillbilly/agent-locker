"""MCP server (stdio) exposing the Agent Locker daemon to AI agents."""
from __future__ import annotations

import json
import os
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer

LOCKER_URL = os.environ.get("LOCKER_URL", "http://127.0.0.1:8000")

server = MCPServer(
    "lockermcp",
    version="0.1.0",
    instructions=(
        "Append-only, tamper-evident agent-to-agent handoff. Block 0 must be a "
        "locker.handoff.v1 envelope. Read the manifest first, then block 0 (the "
        "envelope) before the remaining blocks."
    ),
)


def _request(method: str, path: str, token: str | None = None, **kw) -> dict:
    headers = dict(kw.pop("headers", {}))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = httpx.request(method, LOCKER_URL + path, headers=headers, timeout=30.0, **kw)
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        raise RuntimeError(f"locker daemon error {r.status_code}: {detail}")
    return r.json()


@server.tool()
def locker_create(ttl_seconds: int, max_blocks: int = 32) -> dict:
    """Create a locker pad. Returns pad_id, write_key, read_ticket."""
    return _request("POST", "/v1/pads",
                    json={"ttl_seconds": ttl_seconds, "max_blocks": max_blocks})


@server.tool()
def locker_append(pad_id: str, write_key: str, payload: Any,
                  content_type: str = "application/json") -> dict:
    """Append a block. Block 0 must be a locker.handoff.v1 envelope dict."""
    if isinstance(payload, (dict, list)):
        data = json.dumps(payload).encode()
    elif isinstance(payload, str):
        data = payload.encode()
    else:
        raise ValueError("payload must be a string, dict, or list")
    return _request("POST", f"/v1/pads/{pad_id}/append", token=write_key,
                    content=data, headers={"Content-Type": content_type})


@server.tool()
def locker_seal(pad_id: str, write_key: str) -> dict:
    """Seal a pad: freeze it and revoke write capability."""
    return _request("POST", f"/v1/pads/{pad_id}/seal", token=write_key)


@server.tool()
def locker_manifest(pad_id: str, ticket: str | None = None) -> dict:
    """Read pad metadata (state, block count, bytes, head hash). Free — no ticket needed."""
    return _request("GET", f"/v1/pads/{pad_id}/manifest")


@server.tool()
def locker_read_blocks(pad_id: str, ticket: str, from_block: int = 0, to_block: int = 0) -> dict:
    """Read a slice of blocks. Defaults to block 0 (the envelope) first."""
    return _request("GET", f"/v1/pads/{pad_id}/blocks",
                    params={"ticket": ticket, "from": from_block, "to": to_block})


def main() -> None:
    server.run()  # stdio transport


if __name__ == "__main__":
    main()
