"""Redaction helpers for the reproduction scripts.

These scripts write captured output to files that are committed as evidence. Capabilities
(`pad_id`, `write_key`, `read_ticket`) are secrets: an error result legitimately carries them
back to the caller that made the request, and they must never reach a log, a report or a
saved evidence file. Every script here scrubs its captured output through these helpers
before printing.

A pad *identifier* is not a capability on its own — writes need the write key and reads need
a ticket — but it is still withheld, because the operator directive for this release treats
known pad identifiers and capabilities alike in captured evidence.
"""
from __future__ import annotations

import re

CAPABILITY_KEYS = {"pad_id", "write_key", "read_ticket", "ticket", "capabilities",
                   "capability_warning"}

# A bare URL-safe token long enough to be a ticket, write key or pad id.
_TOKEN = re.compile(r"^[A-Za-z0-9_\-]{20,}$")
# A sha256 hex digest is a content reference, not a secret: it is published by design.
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_HEX_ID = re.compile(r"/v1/pads/([0-9a-f]{16,})")


def scrub(obj):
    """Recursively replace capabilities with a length marker, keeping everything else."""
    if isinstance(obj, dict):
        return {k: ("<redacted>" if k in CAPABILITY_KEYS else scrub(v))
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub(v) for v in obj]
    if isinstance(obj, str):
        if _TOKEN.match(obj) and not _DIGEST.match(obj):
            return f"<redacted: {len(obj)} chars>"
        return _HEX_ID.sub("/v1/pads/<pad_id>", obj)
    return obj


def mark(value) -> str:
    """A capability's shape without its value."""
    if value is None:
        return "none"
    if isinstance(value, str):
        return f"<redacted: {len(value)} chars>"
    return "<redacted>"
