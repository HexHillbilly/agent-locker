"""Shared fixtures for the deposit tests.

A real daemon on a real socket, and an injecting HTTP shim in front of it, so the client's
own code path is what gets exercised and what gets fooled. Nothing here mocks the client's
internals.
"""
from __future__ import annotations

import http.server
import json
import socket
import sqlite3
import threading
import time

import httpx
import pytest
import uvicorn

import lockermcp.server as mcp
from lockerd import config as cfg
from lockerd.main import create_app


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def deposit_daemon(tmp_path, monkeypatch):
    """A real daemon. Yields ``(base_url, db_path)`` and points the client at it."""
    port = free_port()
    db_path = str(tmp_path / "deposit.db")
    app = create_app(cfg.Config(db_path=db_path, auth_mode=cfg.AUTH_OPEN))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(300):
        try:
            if httpx.get(base + "/health", timeout=0.5).status_code == 200:
                break
        except Exception:
            time.sleep(0.05)
    else:
        server.should_exit = True
        raise RuntimeError("daemon did not come up")
    monkeypatch.setattr(mcp, "LOCKER_URL", base)
    yield base, db_path
    server.should_exit = True
    thread.join(timeout=10)


class Injecting:
    """An HTTP shim that sits in front of the daemon.

    ``mode`` controls response/request rewriting:

    * ``honest`` — everything passes through.
    * ``ack-rewritten`` — an append acknowledgment reports a different ``curr_hash``.
    * ``seal-head-rewritten`` — the seal response reports a head the chain does not have.
    * ``payload-swapped`` — the second artifact is replaced in flight, so the daemon stores
      different bytes than the writer submitted and honestly acknowledges what it stored.
    * ``refuse-create`` — the create is answered with ``refuse_status`` (default 402) WITHOUT
      being forwarded: a daemon refusal that carries the no-commit contract.
    * ``proxy-status`` — the create IS forwarded (so the daemon commits) and then answered with
      ``refuse_status``, which is what an intermediary failing after the fact looks like, at any
      status. The client must not read that as "nothing was created" -- 4xx included, because a
      status code establishes neither the responder's identity nor that nothing committed.
    * ``refuse-append`` — the first append is answered with ``refuse_status``. Below 500 it is
      answered WITHOUT being forwarded; at 500 or above it is forwarded first and then answered.
      Either way the client cannot tell which happened, so the step stays uncertain.
    * ``refuse-seal`` — the same, for the seal request.

    ``drop_on`` controls response LOSS rather than rewriting: the named request is forwarded
    to the daemon (so it commits) and then the connection is closed with no response, which
    is what an ambiguous network outcome looks like to the client. Values: ``create``,
    ``append#1``, ``append#2``, ``seal``.
    """

    def __init__(self, upstream: str, mode: str = "honest", drop_on: str | None = None,
                 refuse_status: int = 402):
        self.upstream = upstream
        self.mode = mode
        self.drop_on = drop_on
        self.refuse_status = refuse_status
        self.appends = 0
        self.forwarded: list[str] = []
        self._httpd, self.base = self._start()

    def _start(self):
        state = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _hit(self, method: str, path: str) -> str | None:
                if method == "POST" and path == "/v1/pads":
                    return "create"
                if path.endswith("/append"):
                    state.appends += 1
                    return f"append#{state.appends}"
                if path.endswith("/seal"):
                    return "seal"
                return None

            def _rewrite_response(self, path: str, obj: dict) -> dict | None:
                if state.mode == "ack-rewritten" and path.endswith("/append"):
                    if len(obj.get("curr_hash", "")) == 64:
                        h = obj["curr_hash"]
                        return {**obj, "curr_hash": ("f" if h[0] != "f" else "0") + h[1:]}
                if state.mode == "seal-head-rewritten" and path.endswith("/seal"):
                    if len(obj.get("head_hash", "")) == 64:
                        h = obj["head_hash"]
                        return {**obj, "head_hash": ("0" if h[0] != "0" else "1") + h[1:]}
                return None

            def _rewrite_request(self, path: str, body: bytes) -> bytes | None:
                if state.mode == "payload-swapped" and path.endswith("/append"):
                    if body == ARTIFACT_2.encode():
                        return b'{"step": 2, "note": "REPLACED BY THE SHIM"}'
                return None

            def _forward(self, method: str):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in ("host", "content-length", "connection")}
                hit = self._hit(method, self.path)
                if state.mode == "refuse-create" and hit == "create":
                    payload = json.dumps({"detail": "refused before forwarding"}).encode()
                    self.send_response(state.refuse_status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                sent = self._rewrite_request(self.path, body)
                upstream_body = sent if sent is not None else body
                r = httpx.request(method, state.upstream + self.path,
                                  content=upstream_body or None, headers=headers, timeout=30)
                state.forwarded.append(f"{hit or method} {self.path}")
                if state.mode == "refuse-seal" and hit == "seal":
                    payload = json.dumps({"detail": "refused"}).encode()
                    self.send_response(state.refuse_status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if state.mode == "refuse-append" and hit == "append#1" \
                        and state.refuse_status < 500:
                    payload = json.dumps({"detail": "refused before forwarding"}).encode()
                    self.send_response(state.refuse_status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if state.mode == "refuse-append" and hit == "append#1" \
                        and state.refuse_status >= 500:
                    payload = json.dumps({"detail": "upstream unavailable"}).encode()
                    self.send_response(state.refuse_status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if state.mode == "proxy-status" and hit == "create":
                    # the daemon has already committed; the caller is told otherwise
                    payload = json.dumps({"detail": "upstream unavailable"}).encode()
                    self.send_response(state.refuse_status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if hit is not None and hit == state.drop_on:
                    # Already committed upstream; the caller just never learns the outcome.
                    self.close_connection = True
                    return
                payload, status = r.content, r.status_code
                if r.headers.get("content-type", "").startswith("application/json"):
                    try:
                        obj = json.loads(payload)
                    except Exception:
                        obj = None
                    if isinstance(obj, dict):
                        new = self._rewrite_response(self.path, obj)
                        if new is not None:
                            payload = json.dumps(new).encode()
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

    def __enter__(self):
        self._previous = mcp.LOCKER_URL
        mcp.LOCKER_URL = self.base
        return self

    def __exit__(self, *exc):
        # restore, so the next shim in a test always fronts the real daemon rather than a
        # shim that has just been shut down
        mcp.LOCKER_URL = self._previous
        self._httpd.shutdown()


ENVELOPE = {"schema": "locker.handoff.v1", "task_id": "t-1", "from_agent": "writer",
            "to_agent": "reader", "constraints": [], "artifacts": [], "budget_usd": None}
UNICODE_ARTIFACT = {"note": "üñïçødé — 你好 🎯", "looks_like_json": '{"schema": "x"}'}
ARTIFACT_1 = '{"step": 1}'
ARTIFACT_2 = json.dumps(UNICODE_ARTIFACT)
ARTIFACTS = [ARTIFACT_1, ARTIFACT_2]


@pytest.fixture
def injecting():
    """Factory: ``injecting(mode="honest", drop_on=None)`` -> a context-managed shim."""
    made: list[Injecting] = []

    def make(mode: str = "honest", drop_on: str | None = None, refuse_status: int = 402):
        upstream = getattr(make, "upstream", None) or mcp.LOCKER_URL
        make.upstream = upstream          # the real daemon, captured once
        shim = Injecting(upstream, mode=mode, drop_on=drop_on, refuse_status=refuse_status)
        made.append(shim)
        return shim

    yield make
    for shim in made:
        shim._httpd.shutdown()


def stored_blocks(db_path: str, pad_id: str) -> list[tuple[int, str, bytes]]:
    con = sqlite3.connect(db_path)
    try:
        return [(r[0], r[1], r[2]) for r in con.execute(
            "SELECT seq, curr_hash, payload FROM blocks WHERE pad_id=? ORDER BY seq", (pad_id,))]
    finally:
        con.close()


def all_text(obj) -> str:
    """Every human-readable string in a result, so honesty is checked everywhere at once."""
    if isinstance(obj, str):
        return obj + "\n"
    if isinstance(obj, dict):
        return "".join(all_text(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return "".join(all_text(v) for v in obj)
    return ""


def expected_chain(envelope: dict, artifacts: list) -> list[str]:
    payloads = [json.dumps(envelope).encode()]
    for a in artifacts:
        payloads.append(json.dumps(a).encode() if isinstance(a, (dict, list)) else a.encode())
    return mcp._compute_chain(payloads)
