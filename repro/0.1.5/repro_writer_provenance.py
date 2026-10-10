#!/usr/bin/env python
"""Phase 1A evidence: what does the WRITER actually commit to?

Stands a real daemon on a real socket, puts an injecting HTTP shim in front of it, points
the real client (``lockermcp.server``) at the shim, and runs ``locker_deposit`` through the
client's own code path. The shim is deliberately not a mock of the client's internals.

Cases, all measured rather than argued:

  1. honest            the shim forwards everything unchanged
  2. ack-rewritten     an append acknowledgment reports a different curr_hash than stored
  3. seal-head-rewritten  the seal response reports a head the chain does not have
  4. payload-swapped   the shim stores different bytes than the writer submitted, and the
                       daemon acks honestly about what it actually stored
  5. rewritten-chain   after an honest deposit, the stored chain is rewritten AND fully
                       rehashed (internally consistent, different head), then read back

    .venv/bin/python repro/0.1.5/repro_writer_provenance.py

Exit 0 always: this records behaviour, it does not assert a desired outcome.
"""
from __future__ import annotations

import hashlib
import http.server
import json
import socket
import sqlite3
import tempfile
import threading
import time

import logging

import httpx
import uvicorn

from _redact import mark, scrub

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("lockerd.main").setLevel(logging.WARNING)

import lockermcp.server as mcp
from lockerd import config as cfg, hashchain
from lockerd.main import create_app

ENVELOPE = {"schema": "locker.handoff.v1", "task_id": "repro-1", "from_agent": "writer",
            "to_agent": "reader", "constraints": [], "artifacts": [], "budget_usd": None}
ARTIFACTS = [
    '{"step": 1, "note": "first artifact"}',
    '{"step": 2, "note": "second artifact — üñïçødé 你好 🎯"}',
]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- daemon ---

def start_daemon(db_path: str) -> tuple[uvicorn.Server, threading.Thread, str]:
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


# ----------------------------------------------------------------------------- shim ---

class ShimState:
    def __init__(self, upstream: str, case: str):
        self.upstream = upstream
        self.case = case
        self.seen: list[dict] = []

    def rewrite_response(self, method: str, path: str, req: bytes, obj: dict) -> dict | None:
        if self.case == "ack-rewritten" and path.endswith("/append"):
            if "curr_hash" in obj and len(obj["curr_hash"]) == 64:
                h = obj["curr_hash"]
                obj = dict(obj)
                obj["curr_hash"] = ("f" if h[0] != "f" else "0") + h[1:]
                return obj
        if self.case == "seal-head-rewritten" and path.endswith("/seal"):
            if "head_hash" in obj and len(obj["head_hash"]) == 64:
                h = obj["head_hash"]
                obj = dict(obj)
                obj["head_hash"] = ("0" if h[0] != "0" else "1") + h[1:]
                return obj
        return None

    def rewrite_request(self, method: str, path: str, body: bytes) -> bytes | None:
        # The second artifact append is replaced in flight, so the daemon stores different
        # bytes than the writer submitted and honestly acks what it stored.
        if self.case == "payload-swapped" and path.endswith("/append"):
            if body == ARTIFACTS[1].encode():
                return b'{"step": 2, "note": "REPLACED BY THE SHIM"}'
        return None


def start_shim(upstream: str, state: ShimState) -> tuple[http.server.ThreadingHTTPServer, str]:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # silence
            pass

        def _forward(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host", "content-length", "connection")}
            sent = state.rewrite_request(method, self.path, body)
            upstream_body = sent if sent is not None else body
            r = httpx.request(method, upstream + self.path,
                              content=upstream_body if upstream_body else None,
                              headers=headers, timeout=30)
            payload, status = r.content, r.status_code
            if r.headers.get("content-type", "").startswith("application/json"):
                try:
                    obj = json.loads(payload)
                except Exception:
                    obj = None
                if isinstance(obj, dict):
                    new = state.rewrite_response(method, self.path, upstream_body, obj)
                    if new is not None:
                        payload = json.dumps(new).encode()
            state.seen.append({"method": method, "path": self.path, "req": upstream_body,
                               "resp": payload[:400]})
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
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


# ---------------------------------------------------------------------- chain maths ---

GENESIS = "0" * 64


def expected_chain(envelope: dict, artifacts: list[str]) -> list[str]:
    """The chain a writer can compute for itself from the exact bytes it will submit."""
    hashes = []
    prev = GENESIS
    for payload in [json.dumps(envelope).encode()] + [a.encode() for a in artifacts]:
        prev = hashchain.compute_hash(prev, payload)
        hashes.append(prev)
    return hashes


def rewrite_stored_chain(db_path: str, pad_id: str, table_payload: bytes) -> str:
    """Rewrite block 1's payload and rehash the WHOLE chain, updating the stored head."""
    con = sqlite3.connect(db_path)
    rows = con.execute("SELECT seq, payload FROM blocks WHERE pad_id=? ORDER BY seq",
                       (pad_id,)).fetchall()
    prev = GENESIS
    new_head = prev
    for seq, _payload in rows:
        payload = table_payload if seq == 1 else _payload
        nxt = hashchain.compute_hash(prev, payload)
        con.execute(
            "UPDATE blocks SET prev_hash=?, curr_hash=?, payload=? WHERE pad_id=? AND seq=?",
            (prev, nxt, payload, pad_id, seq))
        prev = nxt
        new_head = nxt
    con.execute("UPDATE pads SET head_hash=? WHERE id=?", (new_head, pad_id))
    con.commit()
    con.close()
    return new_head


# ----------------------------------------------------------------------------- run ---

def run_case(case: str) -> dict:
    db = tempfile.mktemp(prefix=f"repro_{case}_", suffix=".db")
    server, thread, up = start_daemon(db)
    state = ShimState(up, case)
    httpd, shim = start_shim(up, state)
    mcp.LOCKER_URL = shim
    out: dict = {"case": case}
    try:
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
        out["deposit_error"] = bool("error" in result and result.get("error"))
        # Capabilities are scrubbed before anything is printed: this output is committed
        # as evidence and must not carry a ticket, a write key or a pad id.
        out["deposit"] = scrub({k: v for k, v in result.items() if k != "blocks"})
        expected = expected_chain(ENVELOPE, ARTIFACTS)
        out["local_head"] = expected[-1]
        out["returned_head"] = result.get("head_hash")
        out["head_matches_local"] = result.get("head_hash") == expected[-1]
        out["head_source_field"] = result.get("head_source") or result.get("head_provenance")

        # what the daemon actually stored
        stored = sqlite3.connect(db).execute(
            "SELECT seq, curr_hash, payload FROM blocks WHERE pad_id=? ORDER BY seq",
            (result.get("pad_id"),)).fetchall()
        out["stored_hashes"] = [r[1][:16] + "…" for r in stored]
        out["stored_matches_local"] = [r[1] for r in stored] == expected
        out["stored_payloads_are_what_was_sent"] = [
            r[2].decode("utf-8", "replace") for r in stored] == \
            [json.dumps(ENVELOPE)] + ARTIFACTS

        # a reader checking against the reference the writer returned
        if not out["deposit_error"]:
            pad_id = result["pad_id"]
            if case == "rewritten-chain":
                new_head = rewrite_stored_chain(db, pad_id, b"pay Mallory 9999 USDC")
                out["rewritten_head"] = new_head
            read = mcp.locker_read_blocks(pad_id=pad_id, ticket=result["read_ticket"],
                                          from_block=0, to_block=9,
                                          expected_head_hash=result["head_hash"])
            out["reader_verdict"] = (read.get("integrity", {}).get("verdict")
                                     if "error" not in read else f"error:{read['error'].get('kind')}")
            out["reader_blocks_present"] = "blocks" in read
    finally:
        mcp.LOCKER_URL = "http://127.0.0.1:8000"
        httpd.shutdown()
        server.should_exit = True
        thread.join(timeout=10)
    return out


def main() -> int:
    cases = ["honest", "ack-rewritten", "seal-head-rewritten", "payload-swapped",
             "rewritten-chain"]
    results = [run_case(c) for c in cases]
    for r in results:
        print(f"\n=== case: {r['case']} ===")
        print(f"  deposit returned an error : {r['deposit_error']}")
        if r["deposit_error"]:
            print(f"  error (capabilities scrubbed): {scrub(r['deposit'])}")
            continue
        print(f"  returned head matches the chain computed from the SUBMITTED bytes: "
              f"{r['head_matches_local']}")
        print(f"  client-reported head source: {r['head_source_field']!r} "
              f"(absent = the client says nothing about provenance)")
        print(f"  daemon stored exactly the bytes submitted: "
              f"{r['stored_payloads_are_what_was_sent']}")
        print(f"  daemon's stored chain equals the locally computed chain: "
              f"{r['stored_matches_local']}")
        if "rewritten_head" in r:
            print(f"  rewritten (rehashed) head  : {r['rewritten_head'][:16]}…")
        print(f"  reader verdict against the returned reference: {r['reader_verdict']}")
        print(f"  reader received blocks     : {r['reader_blocks_present']}")
    print("\nSummary")
    for r in results:
        ok = "ERROR" if r["deposit_error"] else ("head==local" if r["head_matches_local"]
                                                else "head!=local")
        print(f"  {r['case']:<20} deposit={ok:<16} stored_as_sent={r['stored_payloads_are_what_was_sent']}"
              f"  reader={r.get('reader_verdict')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
