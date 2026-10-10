#!/usr/bin/env python
"""Look for PARTIAL capability material in history, not just whole values.

A token-shape scan that requires an exact 43-character match will miss a truncated prefix.
The pre-redaction reproduction scripts printed capability prefixes (``value[:16] + "…"``), so
this script reports every url-safe run of 16..42 characters in the historical reproduction
outputs, with the run replaced by <RUN> in the printed context. Values are never printed.

    .venv/bin/python repro/0.1.5/scan_partial_capabilities.py
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import sys

REPO = "/home/lucky/agent-locker"
BASE = "d59efaccd3cd6cd825518a0c907761a49df2d8d8"
RUN = re.compile(rb"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{16,42})(?![A-Za-z0-9_-])")
SHA256 = re.compile(rb"(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])")
PAD32 = re.compile(rb"(?<![0-9a-f])([0-9a-f]{32})(?![0-9a-f])")

# Words that are plainly not credentials, so the report stays readable. Anything not listed
# is printed for judgement; the list is deliberately short.
BENIGN = re.compile(
    rb"^(acknowledged_prefix_head|acknowledged_prefix_note|append_acknowledgment_mismatch|"
    rb"creation_outcome_unknown|creation_capabilities_unreadable|expected_head_mismatch|"
    rb"verification_failed|locally_computed|chain_inconsistent|representation_mismatch|"
    rb"server_head_hash|automatic_recovery|capabilities_note|classification_basis|"
    rb"RemoteProtocolError|ReadTimeout|locker_daemon_error|read_only_connection|"
    rb"internal_consistency_only|payload_utf8_source|unknown|not_created|partial|"
    rb"seal_outcome_unknown|seal_head_mismatch|append_outcome_unknown|append_rejected|"
    rb"seal_rejected|creation_refused|not_applicable|capabilities_returned|"
    rb"capabilities_not_received|preload|evaluation)$")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True,
                          check=True).stdout


def main() -> int:
    commits = git("rev-list", f"{BASE}..HEAD").split()
    seen: dict[tuple[str, str, str], int] = {}
    print("=== url-safe runs of 16..42 chars in historical blobs, none of them benign ===")
    for commit in commits:
        for path in filter(None, git("ls-tree", "-r", "--name-only", commit).split("\n")):
            blob = subprocess.run(["git", "cat-file", "blob", f"{commit}:{path}"], cwd=REPO,
                                  capture_output=True).stdout
            digests = set(SHA256.findall(blob))
            pads = {p for p in PAD32.findall(blob) if not any(p in d for d in digests)}
            for raw in RUN.findall(blob):
                if raw in digests or any(raw in d for d in digests) or raw in pads:
                    continue
                if BENIGN.match(raw):
                    continue
                line = next((l for l in blob.split(b"\n") if raw in l), b"")
                context = line.replace(raw, b"<RUN>").decode("utf-8", "replace").strip()[:110]
                key = (path, hashlib.sha256(raw).hexdigest()[:8], context)
                seen[key] = seen.get(key, 0) + 1
    if not seen:
        print("  none")
    for (path, digest, context), n in sorted(seen.items()):
        print(f"  {path}")
        print(f"      run {digest} (x{n})  in: {context}")

    print("\n=== the two whole values, and where they live ===")
    for name, pat, length in (("read ticket", re.compile(rb"[A-Za-z0-9_-]{43}"), 43),
                              ("pad id", re.compile(rb"[0-9a-f]{32}"), 32)):
        hits: dict[tuple[str, str], int] = {}
        for commit in commits:
            for path in filter(None, git("ls-tree", "-r", "--name-only", commit).split("\n")):
                if "repro/0.1.5/out_" not in path:
                    continue
                blob = subprocess.run(["git", "cat-file", "blob", f"{commit}:{path}"],
                                      cwd=REPO, capture_output=True).stdout
                digests = set(SHA256.findall(blob))
                for m in pat.findall(blob):
                    if m in digests or any(m in d for d in digests):
                        continue
                    if name == "pad id" and any(len(d) == 64 and m in d for d in digests):
                        continue
                    hits[(commit[:10], path)] = hits.get((commit[:10], path), 0) + 1
        print(f"  {name}: {sum(hits.values())} occurrence(s)")
        for (commit, path), n in sorted(hits.items()):
            print(f"      {commit}  {path}  x{n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
