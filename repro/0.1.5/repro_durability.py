#!/usr/bin/env python
"""Phase 1C evidence: acknowledged-write durability across a PROCESS KILL.

This is a process-kill test. It is NOT a power-loss test, and this script never claims to
be one: SIGKILL removes the process, not the operating system, so the page cache and the
storage device's own write cache are untouched. Power-loss durability depends on the
`synchronous` setting and on the device, and is discussed in the findings, not measured
here.

Run:  .venv/bin/python repro/0.1.5/repro_durability.py

Exit 0 always: this records behaviour, it does not assert a desired outcome.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

import httpx

REPO = "/home/lucky/agent-locker"
ENVELOPE = json.dumps({"schema": "locker.handoff.v1", "task_id": "durability-1",
                       "from_agent": "writer", "to_agent": "reader", "constraints": [],
                       "artifacts": [], "budget_usd": None}).encode()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_daemon(db: str, port: int) -> subprocess.Popen:
    env = dict(os.environ, LOCKER_DB_PATH=db, LOCKER_MODE="open",
               LOCKER_HOST="127.0.0.1", LOCKER_PORT=str(port))
    proc = subprocess.Popen([sys.executable, "-m", "lockerd"], cwd=REPO, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(400):
        try:
            httpx.get(base + "/health", timeout=0.5)
            return proc
        except Exception:
            if proc.poll() is not None:
                raise RuntimeError(f"daemon exited early with {proc.returncode}")
            time.sleep(0.05)
    raise RuntimeError("daemon did not become ready")


def pragmas(db: str) -> dict:
    """What a SEPARATE connection observes.

    `journal_mode` is a property of the database file, so it is what the daemon set.
    `synchronous` is per-connection: a fresh stdlib connection reports SQLite's default
    (2 = FULL) and says nothing about the daemon's own connection, which sets NORMAL.
    `busy_timeout` is likewise the stdlib default, not something the daemon configures.
    """
    con = sqlite3.connect(db)
    out = {
        "journal_mode (file property, so the daemon's)":
            con.execute("PRAGMA journal_mode").fetchone()[0],
        "synchronous (a NEW connection: the default, NOT the daemon's)":
            con.execute("PRAGMA synchronous").fetchone()[0],
        "busy_timeout (stdlib default, not configured by the daemon)":
            con.execute("PRAGMA busy_timeout").fetchone()[0],
    }
    con.close()
    return out


def main() -> int:
    db = tempfile.mktemp(prefix="repro_dura_", suffix=".db")
    port = free_port()
    base = f"http://127.0.0.1:{port}"

    print("=== settings observed from a separate connection ===")
    proc = start_daemon(db, port)
    for k, v in pragmas(db).items():
        print(f"  {k:<58}: {v}")
    print("  Daemon's own store connection sets (from lockerd/db.py connect()):")
    print("    PRAGMA journal_mode = WAL / foreign_keys = ON / synchronous = NORMAL")

    created = httpx.post(base + "/v1/pads", json={"ttl_seconds": 3600, "max_blocks": 32},
                         timeout=10).json()
    pad_id, wk, ticket = created["pad_id"], created["write_key"], created["read_ticket"]
    auth = {"Authorization": f"Bearer {wk}"}

    acks = []
    r = httpx.post(f"{base}/v1/pads/{pad_id}/append", content=ENVELOPE,
                   headers={**auth, "Content-Type": "application/json"}, timeout=10)
    acks.append(r.json())
    for i in range(1, 6):
        r = httpx.post(f"{base}/v1/pads/{pad_id}/append", content=f"block-{i}".encode(),
                       headers=auth, timeout=10)
        acks.append(r.json())
    seal = httpx.post(f"{base}/v1/pads/{pad_id}/seal", headers=auth, timeout=10).json()
    print(f"\n=== {len(acks)} appends acknowledged, then sealed ===")
    print(f"  seal head        : {seal['head_hash'][:16]}…  state={seal['state']}")
    for a in acks:
        print(f"    ack seq={a['seq']} curr_hash={a['curr_hash'][:16]}…")

    print("\n=== SIGKILL the daemon process (no graceful shutdown) ===")
    os.kill(proc.pid, signal.SIGKILL)
    proc.wait(timeout=10)
    print(f"  killed pid {proc.pid} with SIGKILL; exit status {proc.returncode}")

    print("\n=== restart on the same database and read back ===")
    proc2 = start_daemon(db, port)
    manifest = httpx.get(f"{base}/v1/pads/{pad_id}/manifest", timeout=10).json()
    blocks = httpx.get(f"{base}/v1/pads/{pad_id}/blocks",
                       headers={"Authorization": f"Bearer {ticket}"}, timeout=10).json()
    served = {b["seq"]: b["curr_hash"] for b in blocks.get("blocks", [])}
    missing = [a["seq"] for a in acks if served.get(a["seq"]) != a["curr_hash"]]
    print(f"  manifest state   : {manifest['state']}  blocks={manifest['block_count']}")
    print(f"  head after restart: {manifest['head_hash'][:16]}…")
    print(f"  head survived    : {manifest['head_hash'] == seal['head_hash']}")
    print(f"  acknowledged blocks missing or changed: {missing or 'none'}")
    print(f"\n  RESULT: every acknowledged write survived a process kill: {not missing}")

    # a write acknowledged but then mutated on disk is a different question; show the
    # journal sidecars exist so the crash-recovery path is the WAL, not a rollback journal
    print("\n=== files present next to the database ===")
    for suffix in ("", "-wal", "-shm"):
        p = db + suffix
        print(f"  {p.split('/')[-1]:<28} exists={os.path.exists(p)}"
              f"  bytes={os.path.getsize(p) if os.path.exists(p) else 0}")
    print("\nNOTE: this is a process-kill test. It does not measure OS or power-loss "
          "durability; see the findings for what `synchronous = NORMAL` does and does "
          "not promise.")

    proc2.terminate()
    try:
        proc2.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc2.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
