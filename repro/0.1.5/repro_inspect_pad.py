#!/usr/bin/env python
"""Reproduce the baseline failure: inspect_pad.py rejects `--ticket <value>`.

Run from the repo root with the project venv:

    .venv/bin/python repro/0.1.5/repro_inspect_pad.py

Starts the real app on a real socket, mints and seals a pad through HTTP exactly as
`tests/test_phase2_security_fixes.py::_seed_pad` does, then invokes the shipped
`scripts/inspect_pad.py` with the same argv that test uses.
"""
from __future__ import annotations

import json
import re
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
    db = tempfile.mktemp(prefix="repro_inspect_", suffix=".db")
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

    created = httpx.post(base + "/v1/pads", json={"ttl_seconds": 3600, "max_blocks": 8},
                         timeout=10).json()
    pad_id, write_key, ticket = created["pad_id"], created["write_key"], created["read_ticket"]
    envelope = json.dumps({"schema": "locker.handoff.v1", "task_id": "t", "from_agent": "a",
                           "to_agent": "b", "constraints": [], "artifacts": [],
                           "budget_usd": None}).encode()
    auth = {"Authorization": f"Bearer {write_key}"}
    httpx.post(f"{base}/v1/pads/{pad_id}/append", content=envelope,
               headers={**auth, "Content-Type": "application/json"}, timeout=10)
    httpx.post(f"{base}/v1/pads/{pad_id}/append", content=b"payload", headers=auth, timeout=10)
    httpx.post(f"{base}/v1/pads/{pad_id}/seal", headers=auth, timeout=10)

    argv = [sys.executable, "scripts/inspect_pad.py", pad_id, "--ticket", ticket, "--url", base]
    print("ticket          :", mark(ticket))
    print("argv[3]         :", "<redacted: --ticket's flag>")
    print("ticket starts - :", ticket.startswith("-"))
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60,
                          cwd="/home/lucky/agent-locker")
    print("returncode      :", proc.returncode)
    print("stderr          :", proc.stderr.strip()[:400])
    # inspect_pad prints the pad id, so its output is scrubbed before it is captured here.
    print("stdout first 3  :", [re.sub(r"[0-9a-f]{32}", "<pad_id>", line)
                                for line in proc.stdout.strip().splitlines()[:3]])
    print("ticket in output:", ticket in (proc.stdout + proc.stderr))
    print("(the ticket value is never printed by this script)")
    server.should_exit = True
    thread.join(timeout=10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
