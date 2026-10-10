"""The partial-deposit recovery contract.

Every case is a controlled local failure induced by the injecting shim in ``conftest.py``,
driven through the client's own code path against a real daemon. The contract under test:

1. Capabilities already received are returned to the requesting caller on failure.
2. The existing ``error`` indicator is preserved and the ordinary successful-deposit shape
   is never returned for a failed operation.
3. Acknowledged steps and uncertain remote outcomes are distinguished.
4. Integrity failures include capabilities for inspection and prohibit automatic
   continuation.
5. Nothing is retried, replayed, compensated or deleted.
"""
from __future__ import annotations

import base64
import json
import logging
import pathlib
import re

import pytest

import lockermcp.server as mcp
from conftest import ARTIFACTS, ENVELOPE, all_text, expected_chain, stored_blocks

REPO = pathlib.Path(__file__).resolve().parent.parent
SUCCESS_KEYS = ("head_hash", "status", "read_ticket", "head_source", "server_head_hash")


class _RecordingHandler(logging.Handler):
    """Collects rendered log lines so a specific value can be searched for."""

    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def _capabilities(result: dict) -> dict | None:
    return result.get("partial", {}).get("capabilities")


# ------------------------------------------------------------ 1. before creation ---

def test_a_dispatched_create_failure_is_never_not_created(deposit_daemon, injecting):
    """A status code is not a no-commit contract, so every dispatched create failure is unknown.

    The daemon's own create route raises its 4xx responses before the atomic create, so a
    genuine daemon 4xx could not follow a commit -- but the client cannot establish that the
    response came from the daemon rather than an intermediary, and it does not accept the
    status code as a substitute for that provenance. `not_created` stays reserved for a
    locally established, pre-dispatch failure, and this case is dispatched.
    """
    base, db_path = deposit_daemon
    for status in (402, 409, 422, 503):
        with injecting("refuse-create", refuse_status=status):
            result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
        assert "error" in result
        assert result["error"]["status"] == status, "the daemon's own status is preserved"
        assert result["partial"]["status"] == "unknown", (
            f"a {status} after dispatch is not proof that nothing was created")
        assert result["partial"]["status"] != "not_created"
        assert result["partial"]["uncertain"] == ["create"]
        assert result["partial"]["cause"] == "creation_outcome_unknown"
        assert _capabilities(result) is None
        assert "establishes neither" in result["partial"]["classification_basis"]


def test_a_local_pre_dispatch_refusal_raises_and_never_reports_a_remote_outcome(deposit_daemon):
    """`not_created` is reserved for a failure established locally, before dispatch.

    The current implementation raises for those instead of returning a result, so the status is
    unreachable from the result path -- which is the honest position: nothing about a remote
    operation is known, and the caller is not handed a reassuring classification.
    """
    base, db_path = deposit_daemon
    with pytest.raises(ValueError):
        mcp.locker_deposit(envelope=ENVELOPE, artifacts=[123])
    import sqlite3
    con = sqlite3.connect(db_path)
    try:
        pads = con.execute("SELECT id FROM pads WHERE id != 'demo-pad-v1'").fetchall()
    finally:
        con.close()
    assert pads == [], "a pre-dispatch refusal created something remotely"
    import sqlite3
    con = sqlite3.connect(db_path)
    try:
        pads = con.execute("SELECT id FROM pads WHERE id != 'demo-pad-v1'").fetchall()
    finally:
        con.close()
    assert pads == [], "a refused create left a pad behind"


def test_a_proxy_generated_503_after_creation_does_not_claim_not_created(deposit_daemon,
                                                                        injecting):
    """The required regression.

    The create IS forwarded, so the daemon commits, and the caller is then answered 503 by an
    intermediary. A received HTTP error is not proof that creation did not commit, so the
    result must classify the outcome as unknown -- never not_created.
    """
    import sqlite3
    base, db_path = deposit_daemon
    with injecting("proxy-status", refuse_status=503):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))

    assert "error" in result
    assert result["error"]["status"] == 503
    assert result["partial"]["status"] != "not_created", (
        "a 503 is not proof that nothing was created")
    assert result["partial"]["status"] == "unknown"
    assert result["partial"]["cause"] == "creation_outcome_unknown"
    assert result["partial"]["uncertain"] == ["create"]
    assert _capabilities(result) is None, "nothing was received, so nothing can be returned"
    assert result["partial"]["recovery"] == "capabilities_not_received"
    assert "establishes neither" in result["partial"]["classification_basis"]
    # fixture check: the daemon really did commit behind the 503
    con = sqlite3.connect(db_path)
    try:
        pads = con.execute("SELECT id FROM pads WHERE id != 'demo-pad-v1'").fetchall()
    finally:
        con.close()
    assert len(pads) == 1, "the fixture did not actually commit a create"


def test_a_proxy_generated_4xx_after_creation_remains_unknown(deposit_daemon, injecting):
    """The companion case: creation commits, and an intermediary answers a 4xx.

    A 4xx is the status most tempting to read as a refusal, and it is not one. The result must
    stay unknown, and the fixture proves the pad really was created.
    """
    import sqlite3
    base, db_path = deposit_daemon
    for status in (402, 409, 422):
        with injecting("proxy-status", refuse_status=status):
            result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
        assert result["error"]["status"] == status
        assert result["partial"]["status"] == "unknown", (
            f"a {status} from an intermediary is not proof that nothing was created")
        assert result["partial"]["uncertain"] == ["create"]
        assert _capabilities(result) is None
        assert "establishes neither" in result["partial"]["classification_basis"]
    # fixture check: each attempt committed a create behind the 4xx
    con = sqlite3.connect(db_path)
    try:
        pads = con.execute("SELECT id FROM pads WHERE id != 'demo-pad-v1'").fetchall()
    finally:
        con.close()
    assert len(pads) == 3, f"expected three committed creates, found {len(pads)}"


def test_a_proxy_generated_5xx_on_append_is_uncertain_not_certain(deposit_daemon, injecting):
    """The same mistaken inference on the append path: a forwarded-then-5xx proves nothing."""
    base, db_path = deposit_daemon
    with injecting("refuse-append", refuse_status=503):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert result["partial"]["cause"] == "append_outcome_unknown", (
        "a 5xx answered after the append was forwarded does not prove it had no effect")
    assert result["partial"]["uncertain"] == ["append 0"]
    assert "establishes neither" in result["partial"]["classification_basis"]
    # fixture check: the append really did commit before the 503 was returned
    caps = _capabilities(result)
    assert len(stored_blocks(db_path, caps["pad_id"])) >= 1


def test_a_4xx_on_append_is_uncertain_too(deposit_daemon, injecting):
    """Append goes through the same classification path, so a 4xx leaves the step uncertain.

    The daemon's append route raises its 4xx responses before the write, but the client cannot
    establish that the 4xx came from the daemon, so it does not treat it as a no-effect
    contract. Through the shim this append is REFUSED BEFORE forwarding, so nothing was in fact
    written -- and the result still must not claim that.
    """
    base, db_path = deposit_daemon
    with injecting("refuse-append", refuse_status=409):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert result["partial"]["cause"] == "append_outcome_unknown"
    assert result["partial"]["uncertain"] == ["append 0"]
    assert "establishes neither" in result["partial"]["classification_basis"]
    assert _capabilities(result) is not None


def test_a_4xx_on_seal_is_uncertain_too(deposit_daemon, injecting):
    """The seal step uses the same path."""
    base, db_path = deposit_daemon
    with injecting("refuse-seal", refuse_status=409):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert result["partial"]["cause"] == "seal_outcome_unknown"
    assert result["partial"]["uncertain"] == ["seal"]
    assert "establishes neither" in result["partial"]["classification_basis"]
    text = all_text(result).lower()
    assert "do not infer that it remains open" in text


# ------------------------------------------------- 2. creation committed, reply lost ---

def test_creation_committed_but_response_lost_is_unknown_and_unrecoverable(deposit_daemon,
                                                                          injecting):
    base, db_path = deposit_daemon
    with injecting(drop_on="create") as shim:
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))

    assert "error" in result
    assert result["partial"]["cause"] == "creation_outcome_unknown"
    assert result["partial"]["status"] == "unknown"
    assert _capabilities(result) is None, "capabilities were never received, so none exist here"
    assert result["partial"]["uncertain"] == ["create"]
    assert result["partial"]["recovery"] == "capabilities_not_received"
    assert "it may exist" in result["partial"]["detail"]
    # fixture check: the create really did commit, so "unknown" is the honest answer
    import sqlite3
    con = sqlite3.connect(db_path)
    try:
        pads = con.execute("SELECT id FROM pads WHERE id != 'demo-pad-v1'").fetchall()
    finally:
        con.close()
    assert len(pads) == 1, "the lost response hid a committed create"


# --------------------------------------------- 3. failure after capabilities arrived ---

def test_failure_after_capabilities_were_received_returns_them(deposit_daemon, injecting):
    base, db_path = deposit_daemon
    with injecting("ack-rewritten"):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))

    caps = _capabilities(result)
    assert caps is not None, "received capabilities must come back to the caller"
    assert set(caps) == {"pad_id", "write_key", "read_ticket"}
    assert result["partial"]["status"] == "partial"
    assert result["partial"]["recovery"] == "capabilities_returned"
    # the shim rewrites the first append's acknowledgment, so block 0 is the one that could
    # not be confirmed and must NOT appear as acknowledged
    assert result["partial"]["acknowledged"] == ["create"]
    assert result["partial"]["uncertain"] == ["append 0"]
    # the returned capabilities are real: they work against the daemon
    mcp.LOCKER_URL = base
    read = mcp.locker_manifest(pad_id=caps["pad_id"], ticket=caps["read_ticket"])
    assert "error" not in read, read
    assert result["partial"]["automatic_recovery"] is False


# --------------------------------------------- 4. append committed, response lost ---

def test_append_committed_but_response_lost_is_uncertain_and_says_not_to_retry(
        deposit_daemon, injecting):
    base, db_path = deposit_daemon
    with injecting(drop_on="append#2") as shim:
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))

    assert result["partial"]["cause"] == "append_outcome_unknown"
    # the client numbers blocks by their position, matching `seq`: the second append is
    # "append 1". The shim's drop_on names the Nth request, i.e. "append#2".
    assert result["partial"]["uncertain"] == ["append 1"]
    assert result["partial"]["acknowledged"] == ["create", "append 0"]
    assert _capabilities(result) is not None
    text = all_text(result).lower()
    assert "do not retry" in text or "do not retry it blindly" in text
    assert "not proof that the bytes are durably stored" in text
    assert "may already have committed" in text
    # fixture check: the dropped append really did commit upstream, so the pad holds the
    # envelope plus that one block -- and nothing after it
    caps = _capabilities(result)
    assert len(stored_blocks(db_path, caps["pad_id"])) == 2


# ----------------------------------------------- 5. seal committed, response lost ---

def test_seal_committed_but_response_lost_is_uncertain_and_not_reported_open(
        deposit_daemon, injecting):
    base, db_path = deposit_daemon
    with injecting(drop_on="seal") as shim:
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))

    assert result["partial"]["cause"] == "seal_outcome_unknown"
    assert result["partial"]["uncertain"] == ["seal"]
    assert _capabilities(result) is not None
    detail = result["partial"]["detail"].lower()
    assert "may already be sealed" in detail
    assert "do not infer that it remains open" in detail
    text = all_text(result).lower()
    for forbidden in ("the pad remains open", "the pad is still open",
                      "it is still open", "has not been sealed"):
        assert forbidden not in text, f"the result claims {forbidden!r}"
    # fixture check: the seal really did commit
    caps = _capabilities(result)
    mcp.LOCKER_URL = base
    read = mcp.locker_manifest(pad_id=caps["pad_id"], ticket=caps["read_ticket"])
    assert read["state"] == "sealed"


# ------------------------------------------------- 6. integrity failure with caps ---

def test_integrity_mismatch_includes_capabilities_and_prohibits_continuation(
        deposit_daemon, injecting):
    base, db_path = deposit_daemon
    with injecting("seal-head-rewritten"):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))

    assert result["error"]["kind"] == "verification_failed"
    assert result["error"]["cause"] == "seal_head_mismatch"
    caps = _capabilities(result)
    assert caps is not None, "capabilities are included on integrity failures, for inspection"
    assert result["partial"]["recovery"] == "capabilities_returned"
    text = all_text(result)
    assert "Do not continue, retry, replay or compensate automatically" in text
    assert "inspect the pad before acting" in text.lower()
    # the three heads are reported under distinct names and are not conflated
    integrity = result["integrity"]
    chain = expected_chain(ENVELOPE, ARTIFACTS)
    assert integrity["expected_head"] == chain[-1]
    assert integrity["server_head_hash"] != integrity["expected_head"]
    # The acknowledged prefix here covers every block, so its head legitimately EQUALS the
    # complete head. What matters is that it is a distinct, correctly derived field: it is
    # the head of the acknowledged prefix, and it would diverge the moment a block went
    # unacknowledged.
    appended = sum(1 for s in result["partial"]["acknowledged"] if s.startswith("append "))
    assert integrity["acknowledged_prefix_head"] == chain[appended - 1]
    assert "NOT the intended complete deposit" in integrity["acknowledged_prefix_note"]


def test_no_dispatched_failure_is_ever_classified_not_created(deposit_daemon, injecting):
    """A sweeping guard over every injected failure mode.

    `not_created` is reserved for a locally established, pre-dispatch failure. Every case here
    dispatches something, so none of them may report it -- whatever the status, whatever the
    step.
    """
    base, db_path = deposit_daemon
    cases = ([("refuse-create", {"refuse_status": s}) for s in (400, 402, 409, 422, 500, 503)]
             + [("proxy-status", {"refuse_status": s}) for s in (402, 422, 503)]
             + [("refuse-append", {"refuse_status": s}) for s in (401, 409, 413, 500)]
             + [("refuse-seal", {"refuse_status": 409})]
             + [("drop-create", {"drop_on": "create"}), ("drop_on-append", {"drop_on": "append#1"}),
                ("drop_on-seal", {"drop_on": "seal"})])
    seen_statuses = set()
    for mode, kwargs in cases:
        if mode.startswith("drop_on-"):
            kwargs = {"drop_on": kwargs["drop_on"]}
            mode = "honest"
        with injecting(mode, **kwargs):
            result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
        assert "error" in result, f"{mode}{kwargs} did not fail"
        partial = result["partial"]
        seen_statuses.add(partial["status"])
        assert partial["status"] != "not_created", (
            f"{mode}{kwargs} reported not_created for a dispatched request")
        assert partial["status"] in {"unknown", "partial"}
        for key in SUCCESS_KEYS:
            assert key not in result, f"{mode}{kwargs} returned the success field {key!r}"
    assert seen_statuses <= {"unknown", "partial"}


# ------------------------------------------------------- 7. existing error signal ---

def test_the_existing_error_signal_is_preserved(deposit_daemon, injecting):
    """Callers that branch on `error` must keep working, for every failure class."""
    base, db_path = deposit_daemon

    # an honest deposit has no error key at all
    ok = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert "error" not in ok and "partial" not in ok
    for key in SUCCESS_KEYS:
        assert key in ok, f"the success shape lost {key!r}"

    # a daemon refusal: the error object is the pre-existing {status, detail} shape
    with injecting("ack-rewritten"):
        integrity_failure = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert "error" in integrity_failure
    assert set(integrity_failure["error"]) == {"status", "kind", "cause", "detail"}
    assert integrity_failure["error"]["kind"] == "verification_failed"

    # a plain transport failure keeps the pre-existing status/detail pair untouched
    import socket as _socket
    with _socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
    mcp.LOCKER_URL = f"http://127.0.0.1:{dead}"
    transport = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    assert transport["error"]["status"] == 0
    assert "detail" in transport["error"]
    # and no failure result ever carries the success shape
    for result in (integrity_failure, transport):
        for key in SUCCESS_KEYS:
            assert key not in result, f"a failed deposit returned the success field {key!r}"


# --------------------------------------------- 8. capabilities never in logs/evidence ---

def test_capabilities_never_reach_logs_stdout_or_the_saved_reproduction_outputs(
        deposit_daemon, injecting, caplog, capfd):
    base, db_path = deposit_daemon
    with caplog.at_level(logging.DEBUG):
        with injecting("seal-head-rewritten"):
            result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    caps = _capabilities(result)
    assert caps is not None, "fixture check: this failure does carry capabilities"

    out, err = capfd.readouterr()
    client_records = "\n".join(r.getMessage() for r in caplog.records
                               if r.name.startswith("lockermcp"))
    # The client itself logs no capability and prints nothing, at DEBUG.
    for name in ("write_key", "read_ticket"):
        value = caps[name]
        assert value not in client_records, f"the client logged the {name}"
        assert value not in out and value not in err, f"the {name} reached stdout/stderr"
    assert caps["pad_id"] not in client_records, "the client logged a pad identifier"
    assert caps["pad_id"] not in out and caps["pad_id"] not in err

    # The saved reproduction outputs are committed evidence, so they are scanned for the two
    # shapes that matter rather than for "long words": a 43-character url-safe token is the
    # credential shape (`secrets.token_urlsafe(32)`), and a 32-hex run is a pad id. Both
    # shapes are asserted ABSENT. A digest fragment is not either -- a 32-hex run that is a
    # substring of a 64-hex digest in the same file is a head hash, which is published by
    # design.
    caps_dir = REPO / "repro" / "0.1.5"
    outputs = sorted(caps_dir.glob("out_*.txt"))
    assert outputs, "fixture check: the reproduction outputs exist and are committed"
    credential = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")
    hex32 = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")
    hex64 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
    offenders: list[str] = []
    for path in outputs:
        text = path.read_text()
        digests = hex64.findall(text)
        for found in credential.findall(text):
            offenders.append(f"{path.name}: credential-shaped ({len(found)} chars)")
        for found in hex32.findall(text):
            if not any(found in d for d in digests):
                offenders.append(f"{path.name}: pad-id-shaped {found[:8]}…")
    assert not offenders, f"capability material in committed evidence: {offenders}"


def test_daemon_side_debug_logging_exposes_ticket_values_and_can_be_silenced(deposit_daemon,
                                                                             injecting):
    """A measured operational hazard, on the daemon side rather than the client's.

    aiosqlite logs the bound SQL parameters at DEBUG, and those parameters include the ticket
    and the write-key hash. An operator running a live daemon at DEBUG therefore writes
    capability material into the log. This test records the exposure and proves the
    mitigation rather than asserting the exposure away.
    """
    base, db_path = deposit_daemon
    ticket = None

    with injecting("seal-head-rewritten"):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    caps = _capabilities(result)
    ticket = caps["read_ticket"]

    # Exposure, as measured: with the daemon's aiosqlite logger at DEBUG, the ticket value
    # appears in the log line for the INSERT that stored it.
    logging.getLogger("aiosqlite").setLevel(logging.DEBUG)
    sink = _RecordingHandler()
    root = logging.getLogger()
    old_level = root.level
    root.setLevel(logging.DEBUG)
    root.addHandler(sink)
    try:
        with injecting("seal-head-rewritten"):
            result2 = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
        leaked = caps["read_ticket"] or ""
        ticket2 = _capabilities(result2)["read_ticket"]
        exposed_at_debug = ticket2 in sink.text
    finally:
        root.removeHandler(sink)
        root.setLevel(old_level)
        logging.getLogger("aiosqlite").setLevel(logging.WARNING)

    assert exposed_at_debug, ("fixture check: at DEBUG the daemon's SQL parameter logging "
                              "should have shown the ticket, otherwise this documents nothing")

    # Mitigation, proven: with the daemon's aiosqlite logger quieted to WARNING the ticket
    # does not reach the log. That is the operational guidance, and it is verified rather
    # than asserted.
    quiet = _RecordingHandler()
    root.addHandler(quiet)
    try:
        with injecting("seal-head-rewritten"):
            result3 = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
        ticket3 = _capabilities(result3)["read_ticket"]
        assert ticket3 not in quiet.text, "the ticket still leaked with aiosqlite at WARNING"
    finally:
        root.removeHandler(quiet)


def test_the_ticket_transport_decides_whether_a_ticket_shapes_a_request_url(
        deposit_daemon, monkeypatch):
    """Measured: "no credentials in logs" holds under the HEADER transport, not the query one.

    The client's own records never carry a ticket either way. The difference is the HTTP
    transport's INFO line for the request URL: with `LOCKER_TICKET_TRANSPORT=query` the ticket
    is part of that URL and is therefore written to the log by httpx, which the application
    cannot prevent. That is why header transport is the deployment requirement.
    """
    base, _db = deposit_daemon
    mcp.LOCKER_URL = base
    created = mcp.locker_create(ttl_seconds=3600, max_blocks=8)
    pad_id, write_key, ticket = (created["pad_id"], created["write_key"],
                                 created["read_ticket"])
    mcp.locker_append(pad_id=pad_id, write_key=write_key, payload=dict(ENVELOPE))
    mcp.locker_seal(pad_id=pad_id, write_key=write_key)

    def records_for(transport: str) -> str:
        monkeypatch.setenv("LOCKER_TICKET_TRANSPORT", transport)
        sink = _RecordingHandler()
        http_logger = logging.getLogger("httpx")
        old = http_logger.level
        http_logger.setLevel(logging.INFO)
        http_logger.addHandler(sink)
        try:
            result = mcp.locker_read_blocks(pad_id=pad_id, ticket=ticket, from_block=0, to_block=9)
        finally:
            http_logger.removeHandler(sink)
            http_logger.setLevel(old)
        assert "error" not in result, result
        return sink.text

    header_log = records_for("header")
    assert ticket not in header_log, "the header transport put the ticket in a URL log"
    assert "Authorization" not in header_log, "httpx must not render request headers"

    query_log = records_for("query")
    assert ticket in query_log, (
        "fixture check: with the query transport the ticket should appear in the request URL "
        "that httpx logs -- if it does not, this test documents nothing")
    # and the default really is the safe one
    monkeypatch.delenv("LOCKER_TICKET_TRANSPORT", raising=False)
    assert mcp.ticket_transport() == "header", "the default transport must be header"


def test_asymmetric_case_a_returned_capability_is_usable_but_never_hashed_into_evidence(
        deposit_daemon, injecting):
    """The caller may act on the returned capability; the evidence must not carry it."""
    base, db_path = deposit_daemon
    with injecting("ack-rewritten"):
        result = mcp.locker_deposit(envelope=ENVELOPE, artifacts=list(ARTIFACTS))
    caps = _capabilities(result)
    ticket = caps["read_ticket"]
    mcp.LOCKER_URL = base
    # usable: the caller can inspect its own pad
    read = mcp.locker_read_blocks(pad_id=caps["pad_id"], ticket=ticket, from_block=0, to_block=9)
    assert "error" not in read, read
    payloads = [base64.b64decode(b["payload_b64"]) for b in read["blocks"]]
    assert json.loads(payloads[0])["schema"] == "locker.handoff.v1"
    # and withheld from anything that is not this call's own result
    assert result["partial"]["capabilities_note"].count("secret") == 1
