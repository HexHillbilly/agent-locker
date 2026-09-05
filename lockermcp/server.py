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


class PaymentRequired(LockerError):
    """HTTP 402 carrying the daemon's structured payment challenge body."""
    def __init__(self, challenge: dict):
        super().__init__(402, "payment required")
        self.challenge = challenge


def _err(e: LockerError) -> dict:
    """Daemon errors come back as a structured error dict, not a raised exception."""
    if isinstance(e, PaymentRequired):
        return {"error": {"status": 402, "challenge": e.challenge}}
    return {"error": {"status": e.status_code, "detail": str(e)}}


def _request(method: str, path: str, token: str | None = None,
             payment_tx_hash: str | None = None, **kw) -> dict:
    headers = dict(kw.pop("headers", {}))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payment_tx_hash:
        headers["X-Payment-Proof"] = payment_tx_hash
    r = httpx.request(method, LOCKER_URL + path, headers=headers, timeout=30.0, **kw)
    if r.status_code == 402:
        try:
            challenge = r.json()
        except Exception:
            challenge = {"error": "payment_required", "detail": r.text}
        raise PaymentRequired(challenge)
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


@server.tool(description=(
    "Create a new locker pad. Returns pad_id, write_key, and read_ticket. "
    "Save these — you MUST reuse the returned pad_id and write_key (never invent "
    "your own) for every later append and seal. Must be called ALONE: do NOT batch "
    "it with append/seal in the same step, because pad_id is generated dynamically "
    "and is only available after this call returns. In x402 (pay-per-pad) mode, "
    "pass payment_tx_hash to prove payment; without it the daemon returns a 402 "
    "challenge that is surfaced in the error object."
))
def locker_create(ttl_seconds: int, max_blocks: int = 32,
                  payment_tx_hash: str | None = None) -> dict:
    try:
        return _request("POST", "/v1/pads", payment_tx_hash=payment_tx_hash,
                        json={"ttl_seconds": ttl_seconds, "max_blocks": max_blocks})
    except LockerError as e:
        return _err(e)


@server.tool(description=(
    "Append ONE block to an existing pad (pass the real pad_id and write_key from "
    "locker_create). The very first append is Block 0 and MUST be a "
    "locker.handoff.v1 envelope object with exactly these fields: "
    "schema='locker.handoff.v1', task_id (string), from_agent (string), "
    "to_agent (string), constraints (list of strings), artifacts (list of objects), "
    "budget_usd (number or null). Subsequent appends (Block 1+) carry the task "
    "payload."
))
def locker_append(pad_id: str, write_key: str, payload: Any,
                  content_type: str = "application/json") -> dict:
    if isinstance(payload, (dict, list)):
        data = json.dumps(payload).encode()
    elif isinstance(payload, str):
        data = payload.encode()
    else:
        raise ValueError("payload must be a string, dict, or list")
    try:
        return _request("POST", f"/v1/pads/{pad_id}/append", token=write_key,
                        content=data, headers={"Content-Type": content_type})
    except LockerError as e:
        return _err(e)


@server.tool(description=(
    "Seal the pad to finalize it (pass the pad_id and write_key from locker_create). "
    "After sealing, further appends are rejected."
))
def locker_seal(pad_id: str, write_key: str) -> dict:
    try:
        return _request("POST", f"/v1/pads/{pad_id}/seal", token=write_key)
    except LockerError as e:
        return _err(e)


@server.tool(description=(
    "Atomically create a pad, write the envelope (Block 0), write each artifact as "
    "a block (Block 1+), and seal — all in one call. envelope must be a "
    "locker.handoff.v1 envelope dict with exactly: schema='locker.handoff.v1', "
    "task_id (string), from_agent (string), to_agent (string), constraints (list of "
    "strings), artifacts (list of objects), budget_usd (number or null). artifacts "
    "is the list of payload blocks (each a string or dict) to append after the "
    "envelope. Returns pad_id, read_ticket, head_hash, status."
))
def locker_deposit(envelope: dict, artifacts: list, ttl_seconds: int = 3600,
                   payment_tx_hash: str | None = None) -> dict:
    try:
        created = _request("POST", "/v1/pads", payment_tx_hash=payment_tx_hash, json={
            "ttl_seconds": ttl_seconds,
            "max_blocks": max(2, len(artifacts) + 1),
        })
        pad_id = created["pad_id"]
        write_key = created["write_key"]
        read_ticket = created["read_ticket"]
        _request("POST", f"/v1/pads/{pad_id}/append", token=write_key,
                 content=json.dumps(envelope).encode(),
                 headers={"Content-Type": "application/json"})
        for artifact in artifacts:
            if isinstance(artifact, (dict, list)):
                data = json.dumps(artifact).encode()
                ct = "application/json"
            elif isinstance(artifact, str):
                data = artifact.encode()
                ct = "text/plain"
            else:
                raise ValueError("each artifact must be a string or dict")
            _request("POST", f"/v1/pads/{pad_id}/append", token=write_key,
                     content=data, headers={"Content-Type": ct})
        sealed = _request("POST", f"/v1/pads/{pad_id}/seal", token=write_key)
        return {"pad_id": pad_id, "read_ticket": read_ticket,
                "head_hash": sealed["head_hash"], "status": sealed["state"]}
    except LockerError as e:
        return _err(e)


@server.tool(description=(
    "Read pad metadata: state, block count, total bytes, sealed_at, head hash. "
    "Pass a read_ticket to also verify the hash chain and receive an integrity block."
))
def locker_manifest(pad_id: str, ticket: str | None = None) -> dict:
    try:
        if ticket:
            chain_valid, verified, _, manifest = _fetch_and_verify_chain(pad_id, ticket)
            integrity = {"chain_valid": chain_valid, "blocks_verified": verified}
        else:
            manifest = _request("GET", f"/v1/pads/{pad_id}/manifest")
            integrity = {"chain_valid": None, "blocks_verified": 0}
        return {**manifest, "integrity": integrity}
    except LockerError as e:
        return _err(e)


@server.tool(description=(
    "Read blocks from a pad using the read_ticket. Defaults to Block 0 (the "
    "envelope). Read Block 0 first, then call again with from_block=1 and a larger "
    "to_block to get the payload. Every result includes an integrity block."
))
def locker_read_blocks(pad_id: str, ticket: str, from_block: int = 0,
                       to_block: int = 0) -> dict:
    try:
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
    except LockerError as e:
        return _err(e)


def main() -> None:
    server.run()  # stdio transport


if __name__ == "__main__":
    main()
