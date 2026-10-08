#!/usr/bin/env python
"""check_integrity.py — read-only consistency and accounting report for a locker database.

Answers "is anything in this store structurally wrong?" without changing anything. It
opens the database read-only, walks every pad's stored chain, and prints what it finds.
It never writes, never repairs, and never deletes: an inconsistency is evidence, and
normalising it would destroy the evidence.

    python scripts/check_integrity.py /path/to/locker.db [--json]

Exit codes: 0 all pads consistent, 1 problems found, 2 could not read the database.

**[C] What this can and cannot prove.** It checks the rows that are *present*: contiguity,
hash linkage, the stored head, and byte accounting. It cannot tell you whether data was
ever lost, because a pad keeps no independent record of what it acknowledged. A chain
that was written correctly and then had acknowledged tail data discarded looks exactly
like a short-but-consistent chain. To catch that, compare against the caller's own
acknowledgment records — every 201 response's (pad_id, seq, curr_hash) — which is the
only thing that can witness a write that is no longer there.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lockerd import config as cfg  # noqa: E402


def open_readonly(path: str) -> sqlite3.Connection:
    """Open the database read-only, and say so clearly if that is not possible."""
    uri = f"file:{path}?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True)
    except sqlite3.OperationalError as exc:
        raise SystemExit(f"cannot open {path} read-only: {exc}") from None
    con.row_factory = sqlite3.Row
    # Anything that tries to write through this connection fails rather than succeeding.
    con.execute("PRAGMA query_only = ON")
    return con


def check_pad(con: sqlite3.Connection, pad: sqlite3.Row) -> list[str]:
    problems: list[str] = []
    rows = con.execute(
        "SELECT seq, prev_hash, curr_hash, payload FROM blocks WHERE pad_id=? ORDER BY seq",
        (pad["id"],)).fetchall()

    prev = cfg.ZERO_HASH
    nbytes = 0
    for i, r in enumerate(rows):
        if r["seq"] != i:
            problems.append(f"block at position {i} stores seq={r['seq']}: the sequence is not a contiguous 0-based run "
                            "(a gap is where an acknowledged write would have gone)")
        if r["prev_hash"] != prev:
            problems.append(f"block {i}: prev_hash does not link to the previous block's curr_hash")
        payload = bytes(r["payload"])
        nbytes += len(payload)
        expect = hashlib.sha256(prev.encode() + payload).hexdigest()
        if r["curr_hash"] != expect:
            problems.append(f"block {i}: stored curr_hash does not match its payload and predecessor")
        prev = r["curr_hash"]

    if pad["head_hash"] != prev:
        problems.append("stored head_hash does not match the last stored block's curr_hash")
    if pad["current_bytes"] != nbytes:
        problems.append(f"current_bytes is {pad['current_bytes']} but the stored payloads total {nbytes}")
    if not rows and pad["state"] in ("sealed",) and pad["head_hash"] != cfg.ZERO_HASH:
        problems.append("sealed pad has a non-genesis head but no blocks")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description="Read-only locker integrity report.")
    ap.add_argument("db", help="path to the locker SQLite database")
    ap.add_argument("--json", action="store_true", help="emit a machine-readable report")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"no such database: {args.db}", file=sys.stderr)
        return 2
    con = open_readonly(args.db)
    try:
        pads = con.execute("SELECT * FROM pads ORDER BY created_at").fetchall()
        report = {"database": args.db, "pads": [], "problems": 0, "checked": 0}
        for pad in pads:
            issues = check_pad(con, pad)
            report["checked"] += 1
            report["problems"] += len(issues)
            report["pads"].append({
                "pad_id": pad["id"], "state": pad["state"],
                "blocks": con.execute("SELECT COUNT(*) FROM blocks WHERE pad_id=?",
                                      (pad["id"],)).fetchone()[0],
                "current_bytes": pad["current_bytes"], "ok": not issues, "problems": issues,
            })
    finally:
        con.close()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"database: {args.db}  (read-only, nothing was modified)")
        print(f"pads checked: {report['checked']}   problems: {report['problems']}")
        for p in report["pads"]:
            mark = "ok  " if p["ok"] else "FAIL"
            print(f"  {mark} {p['pad_id']}  state={p['state']} blocks={p['blocks']} bytes={p['current_bytes']}")
            for issue in p["problems"]:
                print(f"        - {issue}")
        if report["problems"]:
            print()
            print("Problems above are reported as found. Nothing was repaired, recomputed or")
            print("deleted: the stored rows are the evidence. A short but consistent chain")
            print("cannot be distinguished from a lossy one here -- compare against your own")
            print("acknowledgment records (each 201's pad_id, seq, curr_hash) for that.")
    return 1 if report["problems"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
