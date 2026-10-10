#!/usr/bin/env python
"""Prove the publication branch carries none of the private branch's capability values.

The two values are read from the private commit's blobs and searched for by exact bytes
across every blob in the publication branch's history. NOTHING is printed except counts and
fingerprints: the values themselves never appear in the output.

    .venv/bin/python repro/0.1.5/verify_publication_branch_is_clean.py
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import sys

REPO = "/home/lucky/agent-locker"
BASE = "d59efaccd3cd6cd825518a0c907761a49df2d8d8"
PRIVATE = "security/0.1.5-writer-verification"
PUBLIC = "release/0.1.5-public"
# where the pre-redaction captures lived on the private branch
SOURCES = {
    "read ticket": "repro/0.1.5/out_ticket_dash.txt",
    "pad id": "repro/0.1.5/out_partial_deposit_prepatch.txt",
}
EXPOSING_COMMIT_HINT = "e4138481"
C43 = re.compile(rb"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])")
H64 = re.compile(rb"(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])")
H32 = re.compile(rb"(?<![0-9a-f])([0-9a-f]{32})(?![0-9a-f])")


def git(*args: str, text: bool = True):
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=text,
                          check=True).stdout


def blobs(rev: str):
    for path in filter(None, git("ls-tree", "-r", "--name-only", rev).split("\n")):
        yield path, subprocess.run(["git", "cat-file", "blob", f"{rev}:{path}"], cwd=REPO,
                                   capture_output=True).stdout


def main() -> int:
    # 1. recover the values from the private branch, without printing them
    exposing = [c for c in git("rev-list", f"{BASE}..{PRIVATE}").split()
                if c.startswith(EXPOSING_COMMIT_HINT)]
    assert exposing, "the exposing commit was not found"
    commit = exposing[0]
    values: dict[str, bytes] = {}
    for label, path in SOURCES.items():
        blob = subprocess.run(["git", "cat-file", "blob", f"{commit}:{path}"], cwd=REPO,
                              capture_output=True).stdout
        digests = set(H64.findall(blob))
        if label == "read ticket":
            cands = [t for t in C43.findall(blob) if t not in digests]
        else:
            cands = [p for p in H32.findall(blob) if not any(p in d for d in digests)]
        assert len(cands) == 1, f"expected exactly one {label} in {path}, got {len(cands)}"
        values[label] = cands[0]
    for label, v in values.items():
        print(f"  recovered {label}: length {len(v)}, fingerprint "
              f"{hashlib.sha256(v).hexdigest()[:8]}  (value not printed)")

    # 2. exact-byte search across the publication branch's history
    print("\n=== exact search across every blob on the publication branch ===")
    hits = {label: [] for label in values}
    commits = git("rev-list", f"{BASE}..{PUBLIC}").split()
    count = 0
    for c in commits:
        for path, blob in blobs(c):
            count += 1
            for label, v in values.items():
                if v in blob:
                    hits[label].append(f"{c[:10]}:{path}")
    print(f"  searched {count} blob(s) across {len(commits)} commit(s)")
    for label, found in hits.items():
        print(f"  {label}: {'ABSENT' if not found else 'PRESENT -> ' + str(found)}")

    # 3. and the same shapes, for completeness
    shapes = {"credential-shaped 43-char": 0, "pad-id-shaped 32-hex": 0}
    for c in commits:
        for _path, blob in blobs(c):
            d = set(H64.findall(blob))
            shapes["credential-shaped 43-char"] += sum(1 for t in C43.findall(blob)
                                                      if t not in d)
            shapes["pad-id-shaped 32-hex"] += sum(1 for p in H32.findall(blob)
                                                  if not any(p in x for x in d))
    print("\n=== shapes on the publication branch (a shape is not proof either way) ===")
    for k, v in shapes.items():
        print(f"  {k}: {v}")

    ok = all(not found for found in hits.values())
    print(f"\nRESULT: {'the publication branch carries none of those values' if ok else 'EXPOSURE PRESENT'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
