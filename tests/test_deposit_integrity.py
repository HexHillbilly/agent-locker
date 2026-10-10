"""Writer-side deposit integrity.

Phase 3 regressions for a confirmed finding: ``locker_deposit`` returned the daemon's
seal-response head without recomputing it from the bytes it submitted, and accepted each
per-append acknowledgment without checking it. Measured before the fix (see
``repro/0.1.5/out_writer_provenance_prepatch.txt``): a shim that stored different bytes
than the writer sent still got a success, and the reference the caller retained then
verified content the writer never submitted.

Discipline used throughout:

* The **positive fixture comes first** in every pair, so a control cannot pass because the
  harness stopped exercising the case it protects.
* Every injection control is paired with a **sensitivity probe** that runs a deliberately
  blind deposit — the pre-fix logic, reproduced below — and shows it accepts exactly what
  the real implementation rejects. A control that also passed against the blind
  implementation would be decorative.
"""
from __future__ import annotations

import hashlib
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
from lockerd import config as cfg, hashchain
from lockerd.main import create_app

ENVELOPE = {"schema": "locker.handoff.v1", "task_id": "t-1", "from_agent": "writer",
            "to_agent": "reader", "constraints": [], "artifacts": [], "budget_usd": None}
UNICODE_ARTIFACT = {"note": "üñïçødé — 你好 🎯", "looks_like_json": '{"schema": "x"}'}
ARTIFACTS = ['{"step": 1}', json.dumps(UNICODE_ARTIFACT)]


# Shared with test_deposit_recovery.py: the daemon fixture is `deposit_daemon` and the shim
# factory is `injecting`, both defined in conftest.py.
from conftest import (ARTIFACTS, ENVELOPE, Injecting, all_text,  # noqa: F401
                      expected_chain, stored_blocks)


def _blind_deposit(envelope: dict, artifacts: list, ttl_seconds: int = 3600) -> dict:
    """The PRE-FIX behaviour, reproduced so a control can be shown to be non-decorative.

    No local chain, no acknowledgment checks, the daemon's seal head returned as the
    result's head. This is the deliberately blind implementation the sensitivity probes
    evaluate the controls against.
    """
    encoded = []
    for a in artifacts:
        if isinstance(a, (dict, list)):
            encoded.append((json.dumps(a).encode(), "application/json"))
        elif isinstance(a, str):
            encoded.append((a.encode(), "text/plain"))
        else:
            raise ValueError("each artifact must be a string or dict")
    try:
        created = mcp._request("POST", "/v1/pads", json={
            "ttl_seconds": ttl_seconds, "max_blocks": max(2, len(artifacts) + 1)})
        pad_id, write_key, read_ticket = (created["pad_id"], created["write_key"],
                                          created["read_ticket"])
        mcp._request("POST", f"/v1/pads/{pad_id}/append", token=write_key,
                     content=json.dumps(envelope).encode(),
                     headers={"Content-Type": "application/json"})
        for data, ct in encoded:
            mcp._request("POST", f"/v1/pads/{pad_id}/append", token=write_key, content=data,
                         headers={"Content-Type": ct})
        sealed = mcp._request("POST", f"/v1/pads/{pad_id}/seal", token=write_key)
        return {"pad_id": pad_id, "read_ticket": read_ticket,
                "head_hash": sealed["head_hash"], "status": sealed["state"]}
    except mcp.LockerError as e:
        return mcp._err(e)


def stored_blocks(db_path: str, pad_id: str) -> list[tuple[int, str, bytes]]:
    con = sqlite3.connect(db_path)
    try:
        return [(r[0], r[1], r[2]) for r in con.execute(
            "SELECT seq, curr_hash, payload FROM blocks WHERE pad_id=? ORDER BY seq", (pad_id,))]
    finally:
        con.close()


# -------------------------------------------------------- positive fixture (runs first) ---

def test_honest_deposit_returns_the_head_computed_from_the_submitted_bytes(deposit_daemon):
    """The positive fixture every control below depends on."""
    _base, db_path = deposit_daemon
    result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert "error" not in result, result
    expected = expected_chain(ENVELOPE, ARTIFACTS)
    assert result["head_hash"] == expected[-1]
    assert result["head_source"] == "locally_computed"
    assert result["server_head_hash"] == expected[-1], "honest daemon must agree"
    assert result["status"] == "sealed"
    stored = stored_blocks(db_path, result["pad_id"])
    assert [h for _s, h, _p in stored] == expected, "the daemon stored this exact chain"


def test_the_client_chain_matches_the_daemon_algorithm():
    """The two implementations are pinned equal, so a format change cannot drift silently."""
    payloads = [b"hello", "üñïçødé — 你好 🎯".encode("utf-8"), b"", b'{"a":1}']
    mine = mcp._compute_chain(payloads)
    theirs, prev = [], "0" * 64
    for p in payloads:
        prev = hashchain.compute_hash(prev, p)
        theirs.append(prev)
    assert mine == theirs
    assert mcp._compute_chain([]) == []
    assert mcp._compute_chain([b"x"])[0] == hashchain.compute_hash("0" * 64, b"x")


def test_exact_bytes_are_preserved_including_unicode_and_serialization(deposit_daemon):
    """Nothing canonicalizes: the bytes hashed are the bytes sent are the bytes stored."""
    _base, db_path = deposit_daemon
    result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert "error" not in result, result
    stored = stored_blocks(db_path, result["pad_id"])
    assert stored[0][2] == json.dumps(ENVELOPE).encode()
    assert stored[1][2] == ARTIFACTS[0].encode()
    assert stored[2][2] == ARTIFACTS[1].encode()
    # [S] Serialization behaviour, recorded rather than assumed: this client encodes with
    # `json.dumps(...)` defaults, so `ensure_ascii=True` escapes non-ASCII as \uXXXX on the
    # wire. The bytes hashed ARE these escaped bytes. A caller who re-encodes by hand with
    # `ensure_ascii=False`, different separators or sorted keys would compute a different
    # head for the same logical payload -- which is why the client, not the caller, must
    # own the encoding.
    assert b"\\u00fc" in stored[2][2], "non-ASCII is escaped by the client's encoder"
    assert "üñïçødé" not in stored[2][2].decode("utf-8")

    read = mcp.locker_read_blocks(pad_id=result["pad_id"], ticket=result["read_ticket"],
                                  from_block=0, to_block=9, expected_head_hash=result["head_hash"])
    assert "error" not in read, read
    assert read["integrity"]["verdict"] == "trusted_head_match"
    payloads = [b["payload_b64"] for b in read["blocks"]]
    import base64
    assert [base64.b64decode(p) for p in payloads] == [s[2] for s in stored]


# ------------------------------------------------------------------- injection controls ---

def test_an_incorrect_append_acknowledgment_cannot_produce_success(deposit_daemon, injecting):
    base, _db = deposit_daemon
    with injecting("ack-rewritten"):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert "error" in result, f"a rewritten acknowledgment produced success: {result}"
    assert result["error"]["kind"] == "verification_failed"
    assert result["error"]["cause"] == "append_acknowledgment_mismatch"
    assert "head_hash" not in result and "read_ticket" not in result
    assert result["integrity"]["expected_head"]


def test_an_incorrect_seal_head_cannot_produce_success(deposit_daemon, injecting):
    base, _db = deposit_daemon
    with injecting("seal-head-rewritten"):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert "error" in result, f"a rewritten seal head produced success: {result}"
    assert result["error"]["cause"] == "seal_head_mismatch"
    assert result["integrity"]["server_head_hash"] != result["integrity"]["expected_head"]
    assert "head_hash" not in result and "read_ticket" not in result


def test_a_daemon_that_stores_different_bytes_cannot_produce_success(deposit_daemon, injecting):
    """The sharpest case: different bytes stored, acknowledged honestly about what it has."""
    base, db_path = deposit_daemon
    with injecting("payload-swapped"):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert "error" in result, f"substituted storage produced success: {result}"
    assert result["error"]["cause"] == "append_acknowledgment_mismatch"
    stored = stored_blocks(db_path, result["pad_id"])
    assert any(b"REPLACED BY THE SHIM" in p for _s, _h, p in stored), \
        "fixture check: the shim really did substitute the payload"


def test_sensitivity_a_blind_deposit_accepts_what_the_real_one_rejects(deposit_daemon, injecting):
    """Sensitivity probe: a permissive implementation must FAIL these controls.

    If the blind (pre-fix) deposit also rejected the injected cases, the controls above
    would be decorative — they would be passing for a reason unrelated to the protection.
    """
    base, _db = deposit_daemon
    for mode, expected_cause in (("ack-rewritten", "append_acknowledgment_mismatch"),
                                 ("seal-head-rewritten", "seal_head_mismatch")):
        with injecting(mode):
            blind = _blind_deposit(ENVELOPE, list(ARTIFACTS))
        assert "error" not in blind, \
            f"the blind implementation rejected {mode}: the control is decorative"
        with injecting(mode):
            real = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
        assert real["error"]["cause"] == expected_cause


def test_preflight_still_rejects_locally_invalid_input_before_creation(deposit_daemon):
    """The existing local preflight is unchanged -- and does not pretend to cover remote
    failures. An artifact that is neither a string nor a dict is knowable locally, so it is
    rejected before anything is created and nothing is left behind."""
    _base, db_path = deposit_daemon
    with pytest.raises(ValueError):
        mcp.locker_deposit(envelope=ENVELOPE, artifacts=[123])
    con = sqlite3.connect(db_path)
    try:
        pads = con.execute("SELECT id FROM pads WHERE id != 'demo-pad-v1'").fetchall()
    finally:
        con.close()
    assert pads == [], "preflight rejection created a pad anyway"


# ------------------------------------------------------------------------ failure honesty ---



def test_a_failed_deposit_is_not_described_as_rolled_back_or_safely_retryable(deposit_daemon, injecting):
    base, db_path = deposit_daemon
    with injecting("seal-head-rewritten"):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    text = all_text(result).lower()
    # The refusal must carry the honest statements -- wherever the contract puts them.
    assert "an acknowledgment means the daemon answered" in text
    assert "not proof that the bytes are durably stored" in text
    assert "nothing is retried, replayed, compensated or deleted" in text
    assert "do not continue, retry, replay or compensate automatically" in text
    # Affirmative claims that would be wrong, checked across every string in the result.
    for forbidden in ("was rolled back", "has been rolled back", "is safe to retry",
                      "will be retried automatically", "no pad was created",
                      "the pad was not created", "nothing was created"):
        assert forbidden not in text, f"the failure claims {forbidden!r}"
    # the claim is true: the pad really does exist, and the success shape is not returned
    live = stored_blocks(db_path, result["pad_id"])
    assert len(live) == len(ARTIFACTS) + 1, "the remote steps really did land"
    for success_key in ("head_hash", "status", "read_ticket", "head_source"):
        assert success_key not in result, f"a failed deposit returned the success field {success_key!r}"
    assert "error" in result


def test_an_interrupted_deposit_leaves_a_provable_partial_success(deposit_daemon, injecting):
    """A failure after creation is a partial success, measured rather than inferred."""
    base, db_path = deposit_daemon
    with injecting("ack-rewritten"):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert result["error"]["status"] == 0
    con = sqlite3.connect(db_path)
    try:
        pads = con.execute("SELECT id, state FROM pads WHERE id != 'demo-pad-v1'").fetchall()
    finally:
        con.close()
    assert len(pads) == 1, "exactly one pad was created by the failed deposit"
    assert pads[0][1] in ("open", "sealed")


# ---------------------------------------------------- reads against the computed reference ---

def test_a_rewritten_and_rehashed_chain_fails_against_the_computed_head(deposit_daemon):
    """The reference the writer computed detects a comprehensive later rewrite."""
    _base, db_path = deposit_daemon
    result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert "error" not in result
    con = sqlite3.connect(db_path)
    prev, new_head = "0" * 64, None
    rows = con.execute("SELECT seq, payload FROM blocks WHERE pad_id=? ORDER BY seq",
                       (result["pad_id"],)).fetchall()
    for seq, _p in rows:
        payload = b"pay Mallory 9999 USDC" if seq == 1 else _p
        nxt = hashchain.compute_hash(prev, payload)
        con.execute("UPDATE blocks SET prev_hash=?, curr_hash=?, payload=? WHERE pad_id=? AND seq=?",
                    (prev, nxt, payload, result["pad_id"], seq))
        prev = new_head = nxt
    con.execute("UPDATE pads SET head_hash=? WHERE id=?", (new_head, result["pad_id"]))
    con.commit()
    con.close()
    assert new_head != result["head_hash"], "fixture check: the rewrite really moved the head"

    read = mcp.locker_read_blocks(pad_id=result["pad_id"], ticket=result["read_ticket"],
                                  from_block=0, to_block=9,
                                  expected_head_hash=result["head_hash"])
    assert "blocks" not in read, "a rewritten chain returned payloads"
    # A rehashed chain is internally consistent, so the failure is the reference
    # comparison, not a chain inconsistency -- the two must not be conflated.
    assert read["error"]["kind"] == "verification_failed"
    assert read["error"]["cause"] == "expected_head_mismatch"


def test_a_truncated_chain_fails_against_the_computed_head(deposit_daemon):
    _base, db_path = deposit_daemon
    result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert "error" not in result
    con = sqlite3.connect(db_path)
    con.execute("DELETE FROM blocks WHERE pad_id=? AND seq=2", (result["pad_id"],))
    con.commit()
    con.close()
    read = mcp.locker_read_blocks(pad_id=result["pad_id"], ticket=result["read_ticket"],
                                  from_block=0, to_block=9,
                                  expected_head_hash=result["head_hash"])
    assert "blocks" not in read
    assert read["error"]["kind"] == "verification_failed"


# ------------------------------------------------------------------- the model-visible text ---

async def test_the_tool_metadata_no_longer_claims_atomicity():
    tools = {t.name: (t.description or "") for t in await mcp.server.list_tools()}
    deposit = tools["locker_deposit"].lower()
    assert "atomically" not in deposit, "the deposit tool still calls itself atomic"
    assert "not one atomic operation" in deposit, "the negation is missing"
    assert "sequence" in deposit
    assert "capabilities" in deposit
    for phrase in ("does not establish", "identity", "truth", "safety", "acceptance",
                   "task completion"):
        assert phrase in deposit, f"the deposit description omits {phrase!r}"
    for tool in ("locker_append", "locker_seal"):
        assert "does not verify" in tools[tool].lower() or \
               "assertion" in tools[tool].lower(), \
            f"{tool} still implies it verified something it cannot"
