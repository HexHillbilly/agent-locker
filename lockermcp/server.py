"""MCP server (stdio) exposing the Agent Locker daemon to AI agents."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer

LOCKER_URL = os.environ.get("LOCKER_URL", "http://127.0.0.1:8000")
ZERO_HASH = "0" * 64

server = MCPServer(
    "lockermcp",
    version="0.1.0",
    instructions=(
        "Append-only, tamper-evident agent-to-agent handoff. Block 0 must be a "
        "locker.handoff.v1 envelope. Every read reports an `integrity` block — "
        "the hash chain is verified in Python, never in the model's context."
    ),
)


class LockerError(RuntimeError):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        super().__init__(f"locker daemon error {status_code}: {detail}")


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
        raise LockerError(r.status_code, detail)
    return r.json()


def _fetch_and_verify_chain(pad_id: str, ticket: str):
    """Walk the full chain genesis -> head.

    Returns ``(chain_valid, blocks_verified, blocks, manifest)``.
    ``blocks_verified`` is the number of consecutive blocks from genesis whose
    hashes checked out before any break.
    """
    manifest = _request("GET", f"/v1/pads/{pad_id}/manifest")
    block_count = manifest["block_count"]
    head_hash = manifest["head_hash"]

    blocks = []
    chunk = 256
    start = 0
    while start < block_count:
        end = min(start + chunk - 1, block_count - 1)
        try:
            resp = _request("GET", f"/v1/pads/{pad_id}/blocks",
                            params={"ticket": ticket, "from": start, "to": end})
        except LockerError as e:
            if e.status_code == 413 and chunk > 1:
                chunk = max(1, chunk // 2)  # page shrank past the 64 KB response cap
                continue
            raise
        blocks.extend(resp["blocks"])
        start = end + 1

    prev = ZERO_HASH
    verified = 0
    chain_valid = True
    for b in blocks:
        payload = base64.b64decode(b["payload_b64"])
        expect = hashlib.sha256(prev.encode() + payload).hexdigest()
        if b["prev_hash"] != prev or b["curr_hash"] != expect:
            chain_valid = False
            break
        prev = b["curr_hash"]
        verified += 1

    if chain_valid and prev != head_hash:
        chain_valid = False  # chain did not reach the advertised head hash

    return chain_valid, verified, blocks, manifest


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
    """Read pad metadata. Pass a read ticket to also verify the hash chain."""
    if ticket:
        chain_valid, verified, _, manifest = _fetch_and_verify_chain(pad_id, ticket)
        integrity = {"chain_valid": chain_valid, "blocks_verified": verified}
    else:
        manifest = _request("GET", f"/v1/pads/{pad_id}/manifest")
        integrity = {"chain_valid": None, "blocks_verified": 0}
    return {**manifest, "integrity": integrity}


@server.tool()
def locker_read_blocks(pad_id: str, ticket: str, from_block: int = 0,
                       to_block: int = 0) -> dict:
    """Read a slice of blocks (defaults to block 0, the envelope) and verify the
    full hash chain against head_hash under the hood."""
    chain_valid, verified, blocks, _ = _fetch_and_verify_chain(pad_id, ticket)
    total = len(blocks)
    if total == 0:
        slice_, to = [], 0
    else:
        f = max(0, from_block)
        to = min(to_block, total - 1)
        slice_ = blocks[f:to + 1] if f <= to else []
    return {
        "pad_id": pad_id,
        "from": from_block,
        "to": to,
        "count": len(slice_),
        "total_blocks": total,
        "integrity": {"chain_valid": chain_valid, "blocks_verified": verified},
        "blocks": slice_,
    }


def main() -> None:
    server.run()  # stdio transport


if __name__ == "__main__":
    main()
