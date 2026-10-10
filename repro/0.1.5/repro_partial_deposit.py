#!/usr/bin/env python
"""Phase 1B evidence: the deposit is a sequence of requests, and what a failure leaves.

Stands a real daemon on a real socket, puts a stage-failing HTTP shim in front of it, and
runs the real client (``lockermcp.server.locker_deposit``). For each failure point the
script records what the CALLER receives and what actually exists on the daemon.

Also prints the real MCP tool metadata (via the server's own list_tools) so the
model-visible description is inspected rather than paraphrased.

    .venv/bin/python repro/0.1.5/repro_partial_deposit.py

Exit 0 always: this records behaviour, it does not assert a desired outcome.
"""
from __future__ import annotations

import asyncio
import http.server
import json
import logging
import socket
import sqlite3
import tempfile
import threading
import time

import httpx
import uvicorn

from _redact import scrub

import lockermcp.server as mcp
from lockerd import config as cfg
from lockerd.main import create_app

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

ENVELOPE = {"schema": "locker.handoff.v1", "task_id": "repro-1b", "from_agent": "writer",
            "to_agent": "reader", "constraints": [], "artifacts": [], "budget_usd": None}
ARTIFACTS = ['{"step": 1}', '{"step": 2}']

# Which request the case fails on, and how.
#   ("refuse", n)      answer 503 without forwarding  -> the operation never happened
#   ("fail_after", n)  forward it, then answer 500    -> the operation DID happen
#   ("drop_after", n)  forward it, then close with no response -> ambiguous outcome
CASES = {
    "before creation":        ("refuse", "POST /v1/pads"),
    "envelope append":        ("fail_after", "append#1"),
    "artifact append":        ("fail_after", "append#2"),
    "sealing":                ("fail_after", "seal"),
    "seal response lost":     ("drop_after", "seal"),
}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_daemon(db_path: str):
    app = create_app(cfg.Config(db_path=db_path, auth_mode=cfg.AUTH_OPEN))
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(300):
        try:
            httpx.get(base + "/health", timeout=0.5)
            break
        except Exception:
            time.sleep(0.05)
    return server, thread, base


def start_shim(upstream: str, how: str, target: str):
    state = {"appends": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _hit(self, method: str, path: str) -> str | None:
            if target == "POST /v1/pads" and method == "POST" and path == "/v1/pads":
                return "create"
            if target.startswith("append#") and path.endswith("/append"):
                state["appends"] += 1
                if f"append#{state['appends']}" == target:
                    return "append"
            if target == "seal" and path.endswith("/seal"):
                return "seal"
            return None

        def _forward(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host", "content-length", "connection")}
            hit = self._hit(method, self.path)
            if hit and how == "refuse":
                payload = json.dumps({"detail": "shim refused before forwarding"}).encode()
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            r = httpx.request(method, upstream + self.path, content=body or None,
                              headers=headers, timeout=30)
            if hit and how == "fail_after":
                payload = json.dumps({"detail": "shim failed after forwarding"}).encode()
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if hit and how == "drop_after":
                self.close_connection = True
                return  # no response at all: the outcome is ambiguous to the caller
            payload, status = r.content, r.status_code
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self._forward("GET")

        def do_POST(self):
            self._forward("POST")

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", free_port()), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def daemon_state(db_path: str) -> list[dict]:
    """What exists on the daemon, described without naming the pad."""
    con = sqlite3.connect(db_path)
    rows = con.execute("SELECT id, state, head_hash FROM pads WHERE id != 'demo-pad-v1'").fetchall()
    out = []
    for index, (pad_id, state, head) in enumerate(rows, start=1):
        n = con.execute("SELECT COUNT(*) FROM blocks WHERE pad_id=?", (pad_id,)).fetchone()[0]
        t = con.execute("SELECT COUNT(*) FROM tickets WHERE pad_id=?", (pad_id,)).fetchone()[0]
        out.append({"pad": f"#{index} (id withheld)", "state": state, "blocks": n,
                    "tickets": t, "head": head[:12] + "…"})
    con.close()
    return out


def run_case(label: str, how: str, target: str) -> dict:
    db = tempfile.mktemp(prefix="repro_1b_", suffix=".db")
    server, thread, up = start_daemon(db)
    httpd, shim = start_shim(up, how, target)
    mcp.LOCKER_URL = shim
    out = {"case": label}
    try:
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
        if "error" in result:
            out["caller_received"] = "error object"
            out["error_detail"] = scrub(result["error"])
            out["capabilities_returned"] = sorted(
                k for k in (result.get("partial", {}).get("capabilities") or {}))
        else:
            out["caller_received"] = "success"
            out["capabilities_returned"] = sorted(result)
        out["daemon"] = daemon_state(db)
    finally:
        mcp.LOCKER_URL = "http://127.0.0.1:8000"
        httpd.shutdown()
        server.should_exit = True
        thread.join(timeout=10)
    return out


def tool_metadata() -> list[dict]:
    async def go():
        tools = await mcp.server.list_tools()
        return [{"name": t.name, "description": t.description} for t in tools]
    return asyncio.run(go())


def main() -> int:
    print("=== MCP tool metadata as the model sees it ===")
    for t in tool_metadata():
        desc = " ".join((t["description"] or "").split())
        mark = "  <-- claims atomicity" if "atomic" in desc.lower() else ""
        print(f"  {t['name']}: {desc[:200]}{mark}")

    print("\n=== partial-deposit failure points ===")
    results = [run_case(label, how, target) for label, (how, target) in CASES.items()]
    for r in results:
        print(f"\n  case: {r['case']}")
        print(f"    caller received            : {r['caller_received']}")
        if r["caller_received"] == "error object":
            print(f"    error returned             : {r['error_detail']}")
        print(f"    capabilities in the result : {r['capabilities_returned'] or 'none'}")
        if not r["daemon"]:
            print("    on the daemon              : nothing created")
        for p in r["daemon"]:
            print(f"    on the daemon              : {p['pad']} state={p['state']} "
                  f"blocks={p['blocks']} tickets={p['tickets']} head={p['head']}")
    print("\nSummary")
    for r in results:
        live = r["daemon"]
        print(f"  {r['case']:<20} caller={r['caller_received']:<12} "
              f"caps={len(r['capabilities_returned'])} "
              f"remote_pads={len(live)} "
              f"state={live[0]['state'] if live else '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
