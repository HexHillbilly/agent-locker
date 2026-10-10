#!/usr/bin/env python
"""Prove the mechanism behind the flaky baseline test: a ticket whose first character is
a dash makes `inspect_pad.py --ticket <ticket>` fail at argparse.

The read ticket is URL-safe base64, so `-` is in its alphabet and a ticket can begin with
one. This script does not wait for a lucky draw: it mints tickets until it finds one that
starts with `-`, then invokes the shipped CLI exactly as the test does.

    .venv/bin/python repro/0.1.5/repro_ticket_dash.py
"""
from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import threading
import time

import httpx
import uvicorn

from _redact import mark

from lockerd import config as cfg
from lockerd.main import create_app


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    db = tempfile.mktemp(prefix="repro_dash_", suffix=".db")
    app = create_app(cfg.Config(db_path=db, auth_mode=cfg.AUTH_OPEN))
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        try:
            httpx.get(base + "/health", timeout=0.5)
            break
        except Exception:
            time.sleep(0.05)

    draws = 0
    dash_ticket = None
    pad_id = None
    while dash_ticket is None and draws < 500:
        created = httpx.post(base + "/v1/pads", json={"ttl_seconds": 3600, "max_blocks": 8},
                             timeout=10).json()
        draws += 1
        if created["read_ticket"].startswith("-"):
            dash_ticket = created["read_ticket"]
            pad_id = created["pad_id"]

    print(f"tickets drawn until one begins with '-': {draws}")
    if dash_ticket is None:
        print("RESULT: not observed in 500 draws (expected about 1 in 64)")
        server.should_exit = True
        thread.join(timeout=10)
        return 1
    # The value is never printed: a read ticket is a capability and this output is
    # committed as evidence. Its shape is what the case is about.
    print(f"ticket                 : {mark(dash_ticket)}"
          f"  starts with '-': {dash_ticket.startswith('-')}")

    argv = [sys.executable, "scripts/inspect_pad.py", pad_id, "--ticket", dash_ticket,
            "--url", base]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60,
                          cwd="/home/lucky/agent-locker")
    print(f"returncode             : {proc.returncode}")
    print(f"stderr                 : {proc.stderr.strip()[:200]}")

    eq_argv = [sys.executable, "scripts/inspect_pad.py", pad_id, f"--ticket={dash_ticket}",
               "--url", base]
    proc2 = subprocess.run(eq_argv, capture_output=True, text=True, timeout=60,
                           cwd="/home/lucky/agent-locker")
    print(f"with --ticket=<value>  : returncode {proc2.returncode}")
    print(f"RESULT: space-separated form exit {proc.returncode}, "
          f"'=' form exit {proc2.returncode}. Pre-fix the first was 2 at argparse; "
          f"post-fix both should be 0.")
    server.should_exit = True
    thread.join(timeout=10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
