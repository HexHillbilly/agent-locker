"""Phase 3 — trusted-head verification (local).

The gap this closes. The hash chain is *self*-consistent: a host that rewrites a
pad's history and recomputes every hash produces a chain that verifies perfectly
against itself. Nothing inside the pad can reveal that, so internal consistency
alone cannot detect a comprehensive rewrite. The only thing that can is a head
obtained from the writer over a **separately trusted channel** and handed back to
the reader as ``expected_head_hash``.

These tests build the real case rather than a mock of it: a pad is written and
sealed through the real daemon, the true head is captured from the seal response,
and then a shim in front of the daemon serves a **rewritten and fully rehashed**
chain. The shim's own self-check asserts the rewritten chain is internally
consistent, so the detection test that follows cannot pass vacuously.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import socket
import threading
import time
import urllib.parse

import httpx
import pytest
import uvicorn

from lockerd import config as cfg
from lockerd.main import create_app
from lockermcp import server as mcp

ZERO_HASH = "0" * 64
ENVELOPE = {
    "schema": "locker.handoff.v1", "task_id": "phase3", "from_agent": "writer",
    "to_agent": "reader", "constraints": [], "artifacts": [], "budget_usd": None,
}


# --------------------------------------------------------------------------- #
# fixtures / helpers
# --------------------------------------------------------------------------- #

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_daemon(tmp_path, monkeypatch):
    """A real daemon on a real socket, with the client pointed at it."""
    port = _free_port()
    app = create_app(cfg.Config(db_path=str(tmp_path / "p3.db"), auth_mode=cfg.AUTH_OPEN))
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(200):
        try:
            httpx.get(f"{base}/health", timeout=0.5)
            break
        except Exception:
            time.sleep(0.05)
    else:
        raise RuntimeError("daemon did not come up")
    monkeypatch.setattr(mcp, "LOCKER_URL", base)
    yield base
    srv.should_exit = True
    thread.join(timeout=5)


def _create(base: str, max_blocks: int = 8) -> dict:
    return httpx.post(f"{base}/v1/pads",
                      json={"ttl_seconds": 3600, "max_blocks": max_blocks}).json()


def _append(base: str, pad_id: str, write_key: str, data: bytes, ctype: str) -> None:
    httpx.post(f"{base}/v1/pads/{pad_id}/append",
               headers={"Authorization": f"Bearer {write_key}", "Content-Type": ctype},
               content=data)


def _seal(base: str, pad_id: str, write_key: str) -> str:
    r = httpx.post(f"{base}/v1/pads/{pad_id}/seal",
                   headers={"Authorization": f"Bearer {write_key}"})
    return r.json()["head_hash"]


def _pad(base: str, payloads: list[bytes], seal: bool = True) -> tuple[str, str, str | None]:
    """Write a real pad. Returns (pad_id, read_ticket, sealed_head_hash|None)."""
    c = _create(base)
    pad_id, wk, ticket = c["pad_id"], c["write_key"], c["read_ticket"]
    _append(base, pad_id, wk, json.dumps(ENVELOPE).encode(), "application/json")
    for p in payloads:
        _append(base, pad_id, wk, p, "application/octet-stream")
    head = _seal(base, pad_id, wk) if seal else None
    return pad_id, ticket, head


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # keep the test output clean
        pass

    def do_GET(self):
        host = self.server.host  # type: ignore[attr-defined]
        parts = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parts.query)

        if parts.path == f"/v1/pads/{host.pad_id}/blocks":
            blocks = host.rewritten_blocks()
            if not blocks:
                body, status = json.dumps({"pad_id": host.pad_id, "count": 0,
                                           "blocks": []}).encode(), 200
            else:
                start = int(query.get("from", ["0"])[0])
                end = int(query.get("to", [str(len(blocks) - 1)])[0])
                body = json.dumps({"pad_id": host.pad_id, "from": start, "to": end,
                                   "count": len(blocks[start:end + 1]),
                                   "blocks": blocks[start:end + 1]}).encode()
                status = 200
        elif parts.path == f"/v1/pads/{host.pad_id}/manifest":
            m = dict(host.upstream_manifest())
            if host.rehash:
                m["head_hash"] = host.fake_head()
            body, status = json.dumps(m).encode(), 200
        else:
            r = httpx.get(host.upstream + self.path, headers=dict(self.headers), timeout=10)
            body, status = r.content, r.status_code

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RewritingHost:
    """A host that serves one pad's history rewritten.

    With ``rehash=True`` every ``prev_hash``/``curr_hash`` is recomputed and the
    advertised manifest head is updated too, so the chain the client walks is
    internally consistent end to end — the rewrite is invisible to a chain-only
    check. With ``rehash=False`` only the payload changes, so the chain breaks
    where the payload was altered.
    """

    def __init__(self, upstream: str, pad_id: str, ticket: str, seq: int,
                 new_payload: bytes, rehash: bool = True):
        self.upstream = upstream
        self.pad_id = pad_id
        self.ticket = ticket
        self.seq = seq
        self.new_payload = new_payload
        self.rehash = rehash
        self._raw = None
        self._rewritten = None
        self._manifest = None

        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.host = self  # type: ignore[attr-defined]
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self._httpd.server_address[1]}"

    # -- upstream -----------------------------------------------------------

    def upstream_manifest(self) -> dict:
        if self._manifest is None:
            self._manifest = httpx.get(
                f"{self.upstream}/v1/pads/{self.pad_id}/manifest", timeout=10).json()
        return self._manifest

    def _upstream_blocks(self) -> list[dict]:
        if self._raw is None:
            n = self.upstream_manifest()["block_count"]
            r = httpx.get(f"{self.upstream}/v1/pads/{self.pad_id}/blocks",
                          params={"from": 0, "to": max(0, n - 1)},
                          headers={"Authorization": f"Bearer {self.ticket}"}, timeout=10)
            self._raw = r.json()["blocks"]
        return self._raw

    # -- the rewrite --------------------------------------------------------

    def rewritten_blocks(self) -> list[dict]:
        if self._rewritten is None:
            prev = ZERO_HASH
            out = []
            for b in self._upstream_blocks():
                payload = base64.b64decode(b["payload_b64"])
                if b["seq"] == self.seq:
                    payload = self.new_payload
                if self.rehash:
                    curr = hashlib.sha256(prev.encode() + payload).hexdigest()
                    out.append({**b, "prev_hash": prev, "curr_hash": curr,
                                "payload_b64": base64.b64encode(payload).decode()})
                    prev = curr
                else:
                    # payload altered, hashes left exactly as the writer made them
                    out.append({**b, "payload_b64": base64.b64encode(payload).decode()})
            self._rewritten = out
        return self._rewritten

    def fake_head(self) -> str:
        blocks = self.rewritten_blocks()
        return blocks[-1]["curr_hash"] if blocks else ZERO_HASH

    def close(self):
        self._httpd.shutdown()
        self._httpd.server_close()


@pytest.fixture
def rehost(live_daemon):
    """Factory for rewriting hosts, torn down with the test."""
    made: list[RewritingHost] = []

    def _make(pad_id: str, ticket: str, seq: int, new_payload: bytes,
              rehash: bool = True) -> RewritingHost:
        h = RewritingHost(live_daemon, pad_id, ticket, seq, new_payload, rehash)
        made.append(h)
        return h

    yield _make
    for h in made:
        h.close()


# --------------------------------------------------------------------------- #
# required regression 1 — untouched chain + correct expected head passes
# --------------------------------------------------------------------------- #

def test_untouched_sealed_chain_with_the_correct_expected_head_passes(live_daemon):
    pad_id, ticket, true_head = _pad(live_daemon, [b"pay Alice 10 USDC"])
    assert true_head and true_head != ZERO_HASH

    r = mcp.locker_read_blocks(pad_id, ticket, from_block=0, to_block=9,
                               expected_head_hash=true_head)
    assert "error" not in r, r
    integ = r["integrity"]
    assert integ["chain_valid"] is True
    assert integ["verdict"] == mcp.VERDICT_TRUSTED_HEAD
    assert integ["expected_head"]["supplied"] is True
    assert integ["expected_head"]["checked"] is True
    assert integ["expected_head"]["matches"] is True
    assert integ["expected_head"]["expected"] == true_head
    assert integ["expected_head"]["observed"] == true_head
    assert base64.b64decode(r["blocks"][1]["payload_b64"]) == b"pay Alice 10 USDC"

    m = mcp.locker_manifest(pad_id, ticket, expected_head_hash=true_head)
    assert "error" not in m, m
    assert m["integrity"]["verdict"] == mcp.VERDICT_TRUSTED_HEAD


# --------------------------------------------------------------------------- #
# required regression 2 — payload altered without rehashing fails internally
# --------------------------------------------------------------------------- #

def test_payload_alteration_without_rehashing_fails_internal_consistency(live_daemon, rehost):
    pad_id, ticket, true_head = _pad(live_daemon, [b"pay Alice 10 USDC"])
    host = rehost(pad_id, ticket, seq=1, new_payload=b"pay Mallory 9999 USDC", rehash=False)
    mcp.LOCKER_URL = host.base

    r = mcp.locker_read_blocks(pad_id, ticket, from_block=0, to_block=9)
    integ = r["integrity"]
    assert integ["chain_valid"] is False
    assert integ["blocks_verified"] == 1          # broke at the altered block
    assert integ["verdict"] == mcp.VERDICT_FAILED
    assert r["blocks"][0]["curr_hash"]                 # block 0 still returned
    assert b"Mallory" in base64.b64decode(r["blocks"][1]["payload_b64"])

    # And a correct expected head must not rescue it.
    r2 = mcp.locker_read_blocks(pad_id, ticket, expected_head_hash=true_head)
    assert "error" in r2
    assert r2["error"]["kind"] == "verification_failed"
    assert "blocks" not in r2


# --------------------------------------------------------------------------- #
# required regression 3 — the central case: altered AND fully rehashed
# --------------------------------------------------------------------------- #

def test_rewritten_and_rehashed_chain_passes_internal_consistency(live_daemon, rehost):
    """Self-check for the next test: the rewrite really is invisible to a
    chain-only check, so detection below cannot be vacuous."""
    pad_id, ticket, true_head = _pad(live_daemon, [b"pay Alice 10 USDC"])
    host = rehost(pad_id, ticket, seq=1, new_payload=b"pay Mallory 9999 USDC", rehash=True)
    mcp.LOCKER_URL = host.base

    assert host.fake_head() != true_head          # it IS a different history
    r = mcp.locker_read_blocks(pad_id, ticket, from_block=0, to_block=9)
    assert "error" not in r
    integ = r["integrity"]
    assert integ["chain_valid"] is True           # ... yet it verifies
    assert integ["blocks_verified"] == 2
    assert integ["expected_head"]["observed"] == host.fake_head()
    assert integ["verdict"] == mcp.VERDICT_INTERNAL_ONLY
    assert integ["expected_head"]["checked"] is False


def test_rewritten_and_rehashed_chain_fails_against_the_true_head(live_daemon, rehost):
    """The regression that matters: only the separately held head detects it."""
    pad_id, ticket, true_head = _pad(live_daemon, [b"pay Alice 10 USDC"])
    host = rehost(pad_id, ticket, seq=1, new_payload=b"pay Mallory 9999 USDC", rehash=True)
    mcp.LOCKER_URL = host.base

    r = mcp.locker_read_blocks(pad_id, ticket, from_block=0, to_block=9,
                               expected_head_hash=true_head)
    assert "error" in r, r
    assert r["error"]["kind"] == "verification_failed"
    assert r["error"]["detail"].startswith("verification failed:")
    assert r["integrity"]["verdict"] == mcp.VERDICT_FAILED
    assert r["integrity"]["expected_head"]["checked"] is True
    assert r["integrity"]["expected_head"]["matches"] is False
    assert r["integrity"]["expected_head"]["expected"] == true_head
    assert r["integrity"]["expected_head"]["observed"] == host.fake_head()
    # a failed verification never hands back payloads
    assert "blocks" not in r

    m = mcp.locker_manifest(pad_id, ticket, expected_head_hash=true_head)
    assert "error" in m, m
    assert m["integrity"]["expected_head"]["matches"] is False


# --------------------------------------------------------------------------- #
# required regression 4 — wrong and malformed expected heads
# --------------------------------------------------------------------------- #

def test_wrong_but_wellformed_expected_head_fails(live_daemon):
    pad_id, ticket, true_head = _pad(live_daemon, [b"payload"])
    wrong = "a" * 64
    assert wrong != true_head

    r = mcp.locker_read_blocks(pad_id, ticket, expected_head_hash=wrong)
    assert "error" in r
    assert r["integrity"]["expected_head"]["supplied"] is True
    assert r["integrity"]["expected_head"]["checked"] is True
    assert r["integrity"]["expected_head"]["matches"] is False
    assert r["integrity"]["verdict"] == mcp.VERDICT_FAILED
    assert "blocks" not in r


@pytest.mark.parametrize("bad", [
    "",
    "not-a-hash",
    "0" * 63,                      # too short
    "0" * 65,                      # too long
    "A" * 64,                      # uppercase is not the canonical form
    "g" * 64,                      # not hex
    " " * 64,
    "0x" + "0" * 62,               # prefixed
    "  " + "0" * 64,               # padded
    12345,                         # not a string
    None.__class__,                # a type
])
def test_malformed_expected_head_is_rejected_not_ignored(live_daemon, bad):
    """A malformed value is a caller error. It must not silently degrade to
    'no expected head supplied', which would report a weaker check than asked."""
    pad_id, ticket, _ = _pad(live_daemon, [b"payload"])

    r = mcp.locker_read_blocks(pad_id, ticket, expected_head_hash=bad)
    assert "error" in r, f"{bad!r} was accepted"
    assert r["error"]["kind"] == "verification_failed"
    assert r["integrity"]["expected_head"]["supplied"] is True
    assert r["integrity"]["expected_head"]["checked"] is False
    assert r["integrity"]["verdict"] == mcp.VERDICT_FAILED
    assert "blocks" not in r

    m = mcp.locker_manifest(pad_id, ticket, expected_head_hash=bad)
    assert "error" in m


# --------------------------------------------------------------------------- #
# required regression 5 — no supplied head reports "not checked"
# --------------------------------------------------------------------------- #

def test_no_expected_head_reports_not_compared_rather_than_failed(live_daemon):
    pad_id, ticket, _ = _pad(live_daemon, [b"payload"])

    r = mcp.locker_read_blocks(pad_id, ticket)
    assert "error" not in r
    integ = r["integrity"]
    assert integ["chain_valid"] is True              # the chain was still walked
    assert integ["expected_head"]["supplied"] is False
    assert integ["expected_head"]["checked"] is False
    assert integ["expected_head"]["matches"] is None  # "not checked", not False
    assert integ["verdict"] == mcp.VERDICT_INTERNAL_ONLY
    assert "not compared against any independently held reference" in \
        integ["expected_head"]["detail"].lower()


def test_manifest_without_ticket_reports_not_checked(live_daemon):
    pad_id, ticket, _ = _pad(live_daemon, [b"payload"])
    m = mcp.locker_manifest(pad_id)          # no ticket: no chain walked
    assert "error" not in m
    assert m["integrity"]["chain_valid"] is None
    assert m["integrity"]["verdict"] == mcp.VERDICT_NOT_CHECKED
    assert m["integrity"]["expected_head"]["checked"] is False


def test_expected_head_without_a_ticket_never_substitutes_the_manifest_head(live_daemon):
    """The daemon's own manifest head is not an independent reference."""
    pad_id, ticket, true_head = _pad(live_daemon, [b"payload"])
    m = mcp.locker_manifest(pad_id, expected_head_hash=true_head)   # no ticket
    assert "error" in m, "the daemon's manifest head was used as the reference"
    assert "read_ticket" in m["error"]["detail"]
    assert m["integrity"]["verdict"] == mcp.VERDICT_FAILED


# --------------------------------------------------------------------------- #
# required regression 6 — partial reads, empty pads, mutable vs sealed
# --------------------------------------------------------------------------- #

def test_partial_read_still_compares_against_the_whole_chain(live_daemon, rehost):
    """The returned slice is Block 0 only, but the rewrite is in Block 2."""
    pad_id, ticket, true_head = _pad(live_daemon, [b"first", b"second", b"third"])
    host = rehost(pad_id, ticket, seq=3, new_payload=b"tampered", rehash=True)
    mcp.LOCKER_URL = host.base

    r = mcp.locker_read_blocks(pad_id, ticket, from_block=0, to_block=0,
                               expected_head_hash=true_head)
    assert "error" in r
    assert r["integrity"]["expected_head"]["matches"] is False

    # without a reference the same partial read looks fine
    ok = mcp.locker_read_blocks(pad_id, ticket, from_block=0, to_block=0)
    assert ok["count"] == 1
    assert ok["integrity"]["chain_valid"] is True
    assert ok["integrity"]["verdict"] == mcp.VERDICT_INTERNAL_ONLY


def test_empty_pad_behaviour_is_explicit(live_daemon):
    c = _create(live_daemon)
    pad_id, ticket = c["pad_id"], c["read_ticket"]

    # a pad with no blocks has the genesis head, and it is not an error
    r = mcp.locker_read_blocks(pad_id, ticket)
    assert "error" not in r
    assert r["total_blocks"] == 0 and r["count"] == 0 and r["blocks"] == []
    assert r["integrity"]["chain_valid"] is True
    assert r["integrity"]["verdict"] == mcp.VERDICT_INTERNAL_ONLY
    assert r["integrity"]["expected_head"]["observed"] == ZERO_HASH

    # the genesis head is checkable, and a wrong head still fails
    ok = mcp.locker_read_blocks(pad_id, ticket, expected_head_hash=ZERO_HASH)
    assert "error" not in ok
    assert ok["integrity"]["verdict"] == mcp.VERDICT_TRUSTED_HEAD

    bad = mcp.locker_read_blocks(pad_id, ticket, expected_head_hash="b" * 64)
    assert "error" in bad
    assert bad["integrity"]["verdict"] == mcp.VERDICT_FAILED


def test_mutable_pad_head_moves_so_an_old_reference_goes_stale(live_daemon):
    """Documented behaviour: for an unsealed pad the head is a moving target, so
    an expected head captured earlier legitimately stops matching."""
    c = _create(live_daemon)
    pad_id, wk, ticket = c["pad_id"], c["write_key"], c["read_ticket"]
    _append(live_daemon, pad_id, wk, json.dumps(ENVELOPE).encode(), "application/json")

    first = mcp.locker_read_blocks(pad_id, ticket)
    head_before = first["integrity"]["expected_head"]["observed"]
    assert head_before and head_before != ZERO_HASH
    assert mcp.locker_read_blocks(
        pad_id, ticket, expected_head_hash=head_before)["integrity"]["verdict"] \
        == mcp.VERDICT_TRUSTED_HEAD

    _append(live_daemon, pad_id, wk, b"appended later", "text/plain")

    stale = mcp.locker_read_blocks(pad_id, ticket, expected_head_hash=head_before)
    assert "error" in stale
    assert stale["integrity"]["expected_head"]["matches"] is False

    # sealing freezes the head, so the current one becomes a stable reference
    sealed_head = _seal(live_daemon, pad_id, wk)
    frozen = mcp.locker_read_blocks(pad_id, ticket, expected_head_hash=sealed_head)
    assert "error" not in frozen
    assert frozen["integrity"]["verdict"] == mcp.VERDICT_TRUSTED_HEAD


# --------------------------------------------------------------------------- #
# compatibility — existing callers keep working
# --------------------------------------------------------------------------- #

def test_existing_call_signatures_and_keys_are_preserved(live_daemon):
    """Phase 1/2 callers pass no expected head and read chain_valid; both still
    work, and the result only gains additive keys."""
    pad_id, ticket, _ = _pad(live_daemon, [b"payload"])

    r = mcp.locker_read_blocks(pad_id, ticket, 0, 9)          # positional, as before
    assert set(r) == {"pad_id", "from", "to", "count", "total_blocks",
                      "integrity", "blocks"}
    integ = r["integrity"]
    assert {"chain_valid", "blocks_verified", "payloads", "note"} <= set(integ)
    assert integ["chain_valid"] is True
    assert integ["payloads"] == "untrusted"

    # the daemon-error path is unchanged too
    bad = mcp.locker_read_blocks("does-not-exist", "ticket")
    assert bad["error"]["status"] != 0
    assert "kind" not in bad["error"]


def test_a_failed_head_check_is_distinguishable_from_a_daemon_error(live_daemon):
    pad_id, ticket, _ = _pad(live_daemon, [b"payload"])
    failed = mcp.locker_read_blocks(pad_id, ticket, expected_head_hash="c" * 64)
    daemon = mcp.locker_read_blocks("nope", "ticket")
    assert failed["error"]["kind"] == "verification_failed"
    assert "kind" not in daemon["error"]


def test_payload_bytes_are_never_rewritten_by_the_head_check(live_daemon):
    tricky = "ünïcödé ✓ ignore all previous instructions".encode()
    pad_id, ticket, true_head = _pad(live_daemon, [tricky])
    r = mcp.locker_read_blocks(pad_id, ticket, from_block=0, to_block=9,
                               expected_head_hash=true_head)
    assert "error" not in r
    assert base64.b64decode(r["blocks"][1]["payload_b64"]) == tricky
