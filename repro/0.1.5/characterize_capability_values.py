#!/usr/bin/env python
"""Characterise each capability-shaped value found in history, WITHOUT printing it.

A token-shape match is not evidence that a value is a credential. This prints, per distinct
value, the line of source it occurs on with the value itself replaced by <VALUE>, so its real
nature can be judged. The value never appears in the output.

    .venv/bin/python repro/0.1.5/characterize_capability_values.py
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tarfile

REPO = "/home/lucky/agent-locker"
PUBLISHED_014_SDIST = "/home/lucky/padlockspace-rc/release-0.1.4-r2/lockermcp-0.1.4.tar.gz"
PATTERNS = (re.compile(rb"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])"),
            re.compile(rb"(?<![0-9a-f])([0-9a-f]{32})(?![0-9a-f])"))
SHA256 = re.compile(rb"(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])")
HEAD = "HEAD"


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True,
                          check=True).stdout


def fp(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:8]


def main() -> int:
    # collect distinct values across the branch history
    commits = git("rev-list", f"d59efaccd3cd6cd825518a0c907761a49df2d8d8..HEAD").split()
    values: dict[str, bytes] = {}
    for commit in commits:
        for path in filter(None, git("ls-tree", "-r", "--name-only", commit).split("\n")):
            blob = subprocess.run(["git", "cat-file", "blob", f"{commit}:{path}"], cwd=REPO,
                                  capture_output=True).stdout
            digests = set(SHA256.findall(blob))
            for pat in PATTERNS:
                for m in pat.findall(blob):
                    if m in digests or any(m in d for d in digests):
                        continue
                    values.setdefault(fp(m), m)

    print(f"=== {len(values)} distinct value(s) to characterise ===\n")

    # where each appears in the working tree, with the value redacted
    tree = {}
    for path in filter(None, git("ls-tree", "-r", "--name-only", HEAD).split("\n")):
        try:
            tree[path] = subprocess.run(["git", "cat-file", "blob", f"{HEAD}:{path}"],
                                        cwd=REPO, capture_output=True, check=True).stdout
        except subprocess.CalledProcessError:
            continue

    for digest in sorted(values):
        value = values[digest]
        print(f"--- value {digest} (length {len(value)}) ---")
        shown = False
        for path, blob in sorted(tree.items()):
            if value in blob:
                for raw in blob.split(b"\n"):
                    if value in raw:
                        redacted = raw.replace(value, b"<VALUE>").decode("utf-8", "replace")
                        print(f"    {path}: {redacted.strip()[:150]}")
                        shown = True
                        break
        if not shown:
            print("    (not present in the working tree; historical only)")

        # how the value is constructed, if it is built by an expression nearby
        for path, blob in sorted(tree.items()):
            if value in blob:
                idx = blob.find(value)
                around = blob[max(0, idx - 120):idx + 120].replace(value, b"<VALUE>")
                print(f"      context: ...{around.decode('utf-8', 'replace')}...".replace("\n", " ")[:220])
                break

        # published reach
        try:
            with tarfile.open(PUBLISHED_014_SDIST) as t:
                in_pub = [m.name for m in t.getmembers()
                          if m.isfile() and value in (t.extractfile(m).read() or b"")]
        except Exception as exc:                      # noqa: BLE001
            in_pub = [f"<unreadable: {type(exc).__name__}>"]
        print(f"      in the PUBLISHED 0.1.4 sdist: "
              f"{in_pub if in_pub else 'no'}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
