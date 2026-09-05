#!/usr/bin/env python3
"""Two-agent handoff demo against a local lockerd (open mode).

Run:  python demo_handoff.py [LOCKER_URL]
"""
import base64
import hashlib
import json
import os
import sys

import httpx

URL = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("LOCKER_URL", "http://127.0.0.1:8000")
ZERO = "0" * 64

envelope = {
    "schema": "locker.handoff.v1",
    "task_id": "demo-001",
    "from_agent": "agent-a",
    "to_agent": "agent-b",
    "constraints": ["be concise", "cite sources"],
    "artifacts": [{"name": "brief.md", "size": 100}],
    "budget_usd": 0.5,
}


def verify_chain(blocks, head_hash):
    prev = ZERO
    for b in blocks:
        payload = base64.b64decode(b["payload_b64"])
        expect = hashlib.sha256(prev.encode() + payload).hexdigest()
        if b["prev_hash"] != prev or b["curr_hash"] != expect:
            return False
        prev = b["curr_hash"]
    return prev == head_hash


# 1. Agent A provisions the pad
created = httpx.post(f"{URL}/v1/pads",
                     json={"ttl_seconds": 3600, "max_blocks": 8}).json()
pad_id, write_key, read_ticket = created["pad_id"], created["write_key"], created["read_ticket"]

# 2. Agent A writes the envelope (Block 0)
httpx.post(f"{URL}/v1/pads/{pad_id}/append", content=json.dumps(envelope).encode(),
           headers={"Authorization": f"Bearer {write_key}"}).raise_for_status()

# 3. Agent B reads Block 0 (the envelope) with the read ticket
block0 = httpx.get(f"{URL}/v1/pads/{pad_id}/blocks",
                   params={"ticket": read_ticket, "from": 0, "to": 0}).json()["blocks"][0]
print("Agent B received envelope:", base64.b64decode(block0["payload_b64"]).decode())

# 4. Agent B appends the payload result (Block 1)
result = {"summary": "done", "word_count": 42}
httpx.post(f"{URL}/v1/pads/{pad_id}/append", content=json.dumps(result).encode(),
           headers={"Authorization": f"Bearer {write_key}"}).raise_for_status()

# 5. Agent A seals the pad
sealed = httpx.post(f"{URL}/v1/pads/{pad_id}/seal",
                    headers={"Authorization": f"Bearer {write_key}"}).json()

# 6. Independently recalculate and verify the SHA-256 chain
blocks = httpx.get(f"{URL}/v1/pads/{pad_id}/blocks",
                   params={"ticket": read_ticket}).json()["blocks"]
print(f"pad={pad_id}  blocks={len(blocks)}  chain_valid={verify_chain(blocks, sealed['head_hash'])}")
