"""Tamper-evident hash chain and the strict handoff envelope."""
from __future__ import annotations

import hashlib
import json

ENVELOPE_SCHEMA = "locker.handoff.v1"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_hash(prev_hash: str, payload: bytes) -> str:
    """curr_hash = sha256(prev_hash.encode() + payload_bytes).hexdigest()"""
    return hashlib.sha256(prev_hash.encode("utf-8") + payload).hexdigest()


def _nonempty_str(v) -> bool:
    return isinstance(v, str) and v != ""


def _str_list(v) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _dict_list(v) -> bool:
    return isinstance(v, list) and all(isinstance(x, dict) for x in v)


def _float_or_none(v) -> bool:
    return v is None or (isinstance(v, (int, float)) and not isinstance(v, bool))


# Strictly required fields of the locker.handoff.v1 envelope (block 0).
REQUIRED_FIELDS = {
    "task_id": _nonempty_str,
    "from_agent": _nonempty_str,
    "to_agent": _nonempty_str,
    "constraints": _str_list,
    "artifacts": _dict_list,
    "budget_usd": _float_or_none,
}


def envelope_error(payload: bytes) -> str | None:
    """Return a validation error string if ``payload`` is not a valid
    ``locker.handoff.v1`` envelope, else ``None``."""
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return "payload must be JSON"
    if not isinstance(obj, dict):
        return "payload must be a JSON object"
    if obj.get("schema") != ENVELOPE_SCHEMA:
        return f"schema must be {ENVELOPE_SCHEMA!r}"
    for field, check in REQUIRED_FIELDS.items():
        if field not in obj:
            return f"missing required field {field!r}"
        if not check(obj[field]):
            return f"field {field!r} has an invalid type/value"
    return None


def is_envelope(payload: bytes) -> bool:
    return envelope_error(payload) is None
