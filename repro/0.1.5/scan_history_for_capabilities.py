#!/usr/bin/env python
"""Locate capability-shaped values in this repository's history and artifacts.

Prints NO secret value: every value is identified by a sha256 fingerprint prefix (8 hex) so
it can be referenced in a report without being reproduced. Reports, per commit and path, how
many values are present and of which kind.

    .venv/bin/python repro/0.1.5/scan_history_for_capabilities.py
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tarfile
import zipfile

REPO = "/home/lucky/agent-locker"
# secrets.token_urlsafe(32) -> 43 chars of url-safe base64; pad ids are 32 hex.
TICKET_LIKE = re.compile(rb"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])")
PAD_ID = re.compile(rb"(?<![0-9a-f])([0-9a-f]{32})(?![0-9a-f])")
SHA256 = re.compile(rb"(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])")
BASE = "d59efaccd3cd6cd825518a0c907761a49df2d8d8"


def fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:8]


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True,
                          check=True).stdout


def scan_bytes(blob: bytes) -> dict[str, set[bytes]]:
    """Values that are credentials/identifiers, with digests excluded."""
    digests = set(SHA256.findall(blob))
    tickets = {m for m in TICKET_LIKE.findall(blob)} - digests
    pads = {m for m in PAD_ID.findall(blob)}
    # a 32-hex run that is really part of a 64-hex digest is not a pad id
    pads = {p for p in pads if not any(p in d for d in digests)}
    return {"token": tickets, "pad_id": pads}


def main() -> int:
    commits = git("rev-list", "--reverse", f"{BASE}..HEAD").split()
    branch = git("rev-parse", "--abbrev-ref", "HEAD").strip()
    print(f"branch {branch}; {len(commits)} commit(s) after the public baseline {BASE[:8]}")

    findings: dict[str, dict[str, dict[str, set[bytes]]]] = {}
    for commit in commits:
        files = git("ls-tree", "-r", "--name-only", commit).split("\n")
        per_file: dict[str, dict[str, set[bytes]]] = {}
        for path in files:
            if not path:
                continue
            try:
                blob = subprocess.run(["git", "cat-file", "blob", f"{commit}:{path}"],
                                      cwd=REPO, capture_output=True, check=True).stdout
            except subprocess.CalledProcessError:
                continue
            found = scan_bytes(blob)
            if found["token"] or found["pad_id"]:
                per_file[path] = found
        if per_file:
            findings[commit] = per_file

    print("\n=== commits carrying values ===")
    for commit, per_file in findings.items():
        subject = git("log", "-1", "--format=%s", commit).strip()
        total_tok = sum(len(v["token"]) for v in per_file.values())
        total_pad = sum(len(v["pad_id"]) for v in per_file.values())
        print(f"  {commit[:10]}  {subject[:60]}")
        print(f"      {total_tok} credential-shaped, {total_pad} pad-id-shaped, "
              f"in {len(per_file)} file(s)")
        for path, v in sorted(per_file.items()):
            print(f"        {path}: {len(v['token'])} credential(s) "
                  f"[{', '.join(sorted(fingerprint(t) for t in v['token']))[:90]}] "
                  f"{len(v['pad_id'])} pad id(s) "
                  f"[{', '.join(sorted(fingerprint(p) for p in v['pad_id']))[:60]}]")

    # every distinct value across history
    all_tokens: set[bytes] = set()
    all_pads: set[bytes] = set()
    for per_file in findings.values():
        for v in per_file.values():
            all_tokens |= v["token"]
            all_pads |= v["pad_id"]
    print(f"\n=== distinct values ever committed: {len(all_tokens)} credential-shaped, "
          f"{len(all_pads)} pad-id-shaped ===")
    for t in sorted(all_tokens, key=fingerprint):
        print(f"  credential {fingerprint(t)}  length {len(t)}")
    for p in sorted(all_pads, key=fingerprint):
        print(f"  pad id     {fingerprint(p)}  length {len(p)}")

    print("\n=== are those values in any built artifact? (exact match, not a shape scan) ===")
    arts = [
        "/home/lucky/padlockspace-rc/release-0.1.5/lockermcp-0.1.5-py3-none-any.whl",
        "/home/lucky/padlockspace-rc/release-0.1.5/lockermcp-0.1.5.tar.gz",
        "/home/lucky/padlockspace-rc/release-0.1.4-r2/lockermcp-0.1.4-py3-none-any.whl",
        "/home/lucky/padlockspace-rc/release-0.1.4-r2/lockermcp-0.1.4.tar.gz",
    ]
    for art in arts:
        try:
            if art.endswith(".whl"):
                with zipfile.ZipFile(art) as z:
                    members = [(n, z.read(n)) for n in z.namelist() if not n.endswith("/")]
            else:
                with tarfile.open(art) as t:
                    members = [(m.name, t.extractfile(m).read())
                               for m in t.getmembers() if m.isfile()]
        except Exception as exc:                      # noqa: BLE001
            print(f"  {art}: unreadable ({type(exc).__name__})")
            continue
        hits = []
        for name, blob in members:
            for kind, values in (("credential", all_tokens), ("pad id", all_pads)):
                for v in values:
                    if v in blob:
                        hits.append(f"{kind} {fingerprint(v)} in {name}")
        print(f"  {art.split('/')[-1]}: {len(members)} member(s), "
              f"{len(hits)} exact hit(s)")
        for h in hits:
            print(f"      {h}")

    print("\n=== which released commits contain those blobs? ===")
    tags = git("tag").split()
    for tag in tags:
        for commit, per_file in findings.items():
            if git("merge-base", "--is-ancestor", commit, tag).strip() == "" and \
                    subprocess.run(["git", "merge-base", "--is-ancestor", commit, tag],
                                   cwd=REPO).returncode == 0:
                print(f"  {tag} contains {commit[:10]}  <-- reachable from a release tag")
    print("  (no output above means no release tag reaches those commits)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
