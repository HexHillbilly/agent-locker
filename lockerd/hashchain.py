"""Tamper-evident hash chain and the handoff envelope."""
from __future__ import annotations

import hashlib
import json

ENVELOPE_SCHEMA = "locker.handoff.v1"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_hash(prev_hash: str, payload: bytes) -> str:
    """curr_hash = sha256(prev_hash.encode() + payload_bytes).hexdigest()"""
    return hashlib.sha256(prev_hash.encode("utf-8") + payload).hexdigest()


def is_envelope(payload: bytes) -> bool:
    """Block 0 must be a locker.handoff.v1 envelope (JSON object with matching schema)."""
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(obj, dict) and obj.get("schema") == ENVELOPE_SCHEMA
