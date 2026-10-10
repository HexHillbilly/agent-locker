# Security notes — 0.1.5 (writer-side deposit integrity)

**Status: local branch only, with local release preparation. Not pushed, not tagged, not
published, not deployed.**

Baseline reviewed: public `HexHillbilly/agent-locker` at
`d59efaccd3cd6cd825518a0c907761a49df2d8d8`, package `lockermcp` 0.1.4. This branch,
`security/0.1.5-writer-verification`, is based on exactly that commit.

Labels: **[S]** supported by inspection or an executed measurement; **[U]** unresolved;
**[C]** interpretation or proposed design.

---

## 1. Findings

| # | Reported | Disposition | Basis |
|---|---|---|---|
| 1 | `locker_deposit` returns the daemon's seal head without computing it from the submitted bytes | **Confirmed** | Code inspection plus five executed cases (`repro/0.1.5/repro_writer_provenance.py`) |
| 2 | Individual append acknowledgments are accepted without verification | **Confirmed** | An injected acknowledgment whose `curr_hash` did not match the stored block still produced a successful deposit |
| 3 | The tool description calls `locker_deposit` atomic although it issues several independently committed requests | **Confirmed** | The model-visible description began "Atomically create a pad…"; read back through the MCP server's own `list_tools` |
| 4 | A failure after creation can leave a pad whose capabilities are not returned to the caller | **Confirmed** | Five failure points executed; four left a pad on the daemon and every one returned zero capabilities |
| — | A ticket whose first character is `-` breaks `scripts/inspect_pad.py --ticket <value>` | **Confirmed, not reported** | Found while reconciling the baseline; the baseline suite is not deterministic without it — see §6 |

Nothing in the reviewed baseline was found to be **already fixed**, and no reported finding
failed to reproduce.

### 1.1 What the writer established before this patch

Two different claims are easy to conflate, so they are kept apart:

1. **Detecting a later change relative to a retained head.** Already worked. A head returned
   by a deposit was, against an honest daemon, the true head, so a later comprehensive
   rewrite changed it and a reader holding it detected the change. Measured: rewrite the
   stored payload and rehash the whole chain; a read against the returned head fails with
   `verification_failed` / `expected_head_mismatch`.
2. **Independently committing to the bytes the writer intended to submit.** **Did not
   work.** The head came from the daemon. Measured: a shim that stored *different bytes*
   than the writer sent — and acknowledged them honestly — produced a successful deposit,
   and the reference the caller retained then reported `trusted_head_match` when reading
   content the writer never submitted. That is the gap this patch closes.

### 1.2 Measured, before and after

`repro/0.1.5/out_writer_provenance_prepatch.txt` and `…_postpatch.txt`:

| Case | Before | After |
|---|---|---|
| Honest daemon | success, returned head equals the locally computed head | **unchanged** — success, `head_source: "locally_computed"`, `server_head_hash` equal |
| Append acknowledgment rewritten | **success** (undetected) | `verification_failed` / `append_acknowledgment_mismatch` |
| Seal head rewritten | **success, returning a head the chain does not have** | `verification_failed` / `seal_head_mismatch` |
| Daemon stores different bytes, acks honestly | **success**; later read reported `trusted_head_match` on unsubmitted content | `verification_failed` / `append_acknowledgment_mismatch` |
| Chain rewritten and rehashed afterwards | detected against the retained head | **unchanged** — detected |

The honest path is deliberately a no-op: against a daemon that behaves, the locally
computed head and the daemon's assertion are the same value, so a successful deposit is
byte-for-byte what it was.

## 2. Changes

| File | Change |
|---|---|
| `lockermcp/server.py` | `_compute_chain()` computes the chain from the exact outgoing bytes; `_deposit_integrity_failure()` is the typed refusal; `locker_deposit` encodes once, checks every acknowledgment's `seq` and `curr_hash` and the seal response, returns `head_hash` = the locally computed value with `head_source` / `server_head_hash`, and refuses explicitly on disagreement |
| `lockermcp/server.py` | Tool descriptions corrected: the deposit description no longer claims atomicity and now states the sequence, the partial-success risk, the lost capabilities, and what verification does *not* establish; `locker_append` and `locker_seal` state that their results are the host's assertion because the client has no prior chain state to recompute from |
| `scripts/inspect_pad.py` | `_normalize_argv()` accepts a ticket whose first character is `-` |
| `README.md` | Deposit tool row updated; a new passage states that the deposit head is client-computed, what that does and does not establish, and that the failure refusal never claims the remote work was undone |
| `lockermcp/server.py` | `partial` recovery block on every failure path; `DEPOSIT_*` notes; capabilities returned when received; explicit prohibitions after verification failure |
| `tests/test_deposit_integrity.py` | 13 regressions (§7), refactored onto the shared fixtures |
| `tests/test_deposit_recovery.py` | 10 regressions covering the recovery contract (§7) |
| `tests/conftest.py` | Shared real-daemon fixture and injecting HTTP shim |
| `scripts/inspect_pad.py` | `_normalize_argv()` accepts a dash-leading ticket |
| `README.md` | Recovery contract table, the four verification statements, capability sensitivity |
| `RELEASE_NOTES.md` | The 0.1.5 entry |
| `repro/0.1.5/` | Reproduction scripts (redacting), captured outputs, and `_redact.py` |
| all four version sources | 0.1.4 → 0.1.5 |

No hash format, canonicalization, signature, package name, schema, licensing or
capability-return contract was changed.

## 3. Guarantees: before and after

**Before.** A successful deposit meant: the daemon accepted a create, some appends and a
seal, and *said* the resulting head was H. The caller could later detect a subsequent
change to that pad relative to H. It could not tell whether H described the bytes it
submitted.

**After.** A successful deposit means: the chain the client computed from the exact bytes it
sent was confirmed by every append acknowledgment and by the seal response, and the returned
`head_hash` is that computed value — with the daemon's own value beside it as
`server_head_hash`. A disagreement is an explicit failure and no success is reported.

**Still not established by a successful deposit**, before or after: writer identity; the
truth of the payload; that the daemon kept a readable copy; that the reader will be allowed
to read; that any task completed; or anything at all if the daemon is honest now and
dishonest later *and* the caller's retained head is not compared. The check converts "trust
the host to report its own work" into "the reference is the content I sent, or I get an
error".

**`locker_append` / `locker_seal` remain unverified by design.** Without the pad's current
head the client has no chain to recompute, so an acknowledgment cannot be checked. The
descriptions now say so instead of implying otherwise; making them checkable is a design
decision in §4.

## 4. Partial-deposit recovery — IMPLEMENTED in 0.1.5

**[S] Implemented** under the five operator decisions recorded below, which supersede the
proposal stage. It extends the original proposal in `SECURITY-NOTES-0.1.4.md` §3.1 rather
than replacing it.

### 4.0 The operator decisions this implements

1. Return known pad identifiers and capabilities to the requesting caller after a deposit
   failure, when they were successfully received.
2. Preserve the existing error indicator; add a structured partial/recovery block; never
   return the ordinary successful-deposit shape for a failed operation.
3. Distinguish acknowledged steps from uncertain remote outcomes. An acknowledgment is not
   proof of durable storage.
4. Include known capabilities on integrity failures for inspection, and explicitly prohibit
   automatic continuation or retry after a verification failure.
5. No operator cleanup endpoint, deletion mechanism, automatic compensation or automatic
   replay.

### 4.0b The recovery-result schema, exactly

A failed deposit returns the pre-existing error object plus one additive block:

```json
{
  "error": {"status": 0, "kind": "deposit_failed|verification_failed",
            "cause": "<stable discriminator>", "detail": "<what happened>"},
  "pad_id": "<pad id or null>",
  "partial": {
    "status": "not_created | partial | unknown",
    "cause": "<same discriminator as error.cause where the error shape carries one>",
    "detail": "<the honest explanation, carried here because a transport failure's preserved
               error object is the older {status, detail} shape>",
    "acknowledged": ["create", "append 0", "..."],
    "uncertain": ["append 1", "seal"],
    "recovery": "not_applicable | capabilities_returned | capabilities_not_received",
    "capabilities": {"pad_id": "...", "write_key": "...", "read_ticket": "..."} ,
    "automatic_recovery": false,
    "note": "An acknowledgment means the daemon answered for that step. It is not proof that
             the bytes are durably stored, still available, or readable.",
    "uncertain_note": "present only when 'uncertain' is non-empty",
    "capabilities_note": "a sensitivity warning when capabilities are present, or an
                          explanation that recovery is unavailable through this API when they
                          are not",
    "continuation": "Nothing is retried, replayed, compensated or deleted, and no automatic
                     continuation is performed. Inspect the pad yourself before acting on it."
  },
  "integrity": {"reference": "...", "expected_head": "...",
                "acknowledged_prefix_head": "...", "acknowledged_prefix_note": "...",
                "server_head_hash": "...", "checked": "...", "suffix": "..."}
}
```

`integrity` is present only on verification failures. The three heads are separate fields
precisely so they cannot be conflated: `expected_head` is the reference for the **intended
complete deposit** computed by the client; `acknowledged_prefix_head` is what the
acknowledged blocks chain to (equal to `expected_head` only when every block was
acknowledged, which is equality by construction, not a conflation); `server_head_hash` is
whatever the daemon reported.

The `error` object for a daemon or transport failure is the **pre-existing** `{status,
detail}` shape, untouched. `cause` and `detail` are therefore also carried inside `partial`,
so a caller can branch on the cause regardless of which error shape it received.

### 4.0c What each failure class returns, measured

From `repro/0.1.5/out_partial_deposit_postpatch.txt`:

| Failure point | `status` | `capabilities` | `uncertain` |
|---|---|---|---|
| The daemon refuses the create (503) | `not_created` | `null` | `[]` — the daemon answered |
| Create committed, response lost | `unknown` | `null` | `["create"]` |
| Envelope or artifact append failed | `partial` | returned | `[]` |
| Append forwarded, response lost | `partial` | returned | `["append N"]` |
| Seal failed, or seal response lost | `partial` | returned | `["seal"]` |
| Integrity mismatch | `partial` | returned | the mismatching step |

### 4.1 Residual and explicit exclusions

**[C] Not implemented, by decision 5:** no operator cleanup endpoint, no deletion mechanism,
no automatic compensation, no automatic replay, and no idempotency key. Nothing is retried on
the caller's behalf and nothing is undone.

**[U] One case the contract cannot resolve, stated plainly.** If a create committed and its
response was lost, nobody ever received the capabilities: the pad cannot be read, written,
sealed or removed through this API by anyone, including the operator. The result reports
`status: "unknown"` and `recovery: "capabilities_not_received"` rather than pretending
otherwise. Recovering such a pad needs an operator-side ability to identify incomplete pads
and is out of scope for this change.

**[C] Capability sensitivity, carried into the artifact.** A capability-bearing error result
is as sensitive as a successful creation result. It is returned to the requesting caller
only — never to a log, an exception string, a saved evidence file or a report. The
reproduction scripts scrub through `repro/0.1.5/_redact.py`, and a test scans the committed
outputs for capability-shaped tokens, so the rule is enforced rather than asserted.

## 5. Durability (Phase 1C)

Kept as four separate statements, because they are four different claims.

- **[S] Settings, inspected.** The store's own connection sets `journal_mode = WAL`,
  `foreign_keys = ON`, `synchronous = NORMAL` (`lockerd/db.py`). A *separate* stdlib
  connection reports `synchronous = 2` (FULL) — that is the default for a new connection and
  says nothing about the daemon's; the daemon's setting is the `NORMAL` above. No
  `busy_timeout` is configured by the daemon; the 5000 ms observed is the Python stdlib
  default.
- **[S] Coroutine concurrency.** One process, one connection, one `asyncio.Lock`. The lock
  is what makes a multi-statement operation atomic *with respect to other coroutines*, and
  `Store.transaction()` rolls back on any non-clean exit including cancellation. This is
  coroutine serialization, not a cross-process lock.
- **[S] Supported worker configuration.** `lockerd/__main__.py` calls `uvicorn.run(...)` with
  no `workers=` argument, so the shipped configuration is exactly one process. Nothing in
  the daemon coordinates two processes, and each process would hold its own connection and
  its own lock; running multiple workers against one database is not a supported
  configuration. **[U] The multi-process failure mode was not measured here** — the
  inspection establishes that it is unsupported, not what it does.
- **[S] Process-crash durability — measured, and only that.** `repro/0.1.5/repro_durability.py`
  acknowledges six appends and a seal, `SIGKILL`s the daemon (no graceful shutdown), restarts
  on the same database, and reads back: every acknowledged block present, the sealed state
  and head intact. Committed transactions survive a process kill.
- **[C] OS / power-loss durability — not measured, and this branch does not claim it.**
  With WAL plus `synchronous = NORMAL`, SQLite does not force a sync on every commit, so a
  power loss or OS crash can lose the most recently committed transactions. Nothing here
  tests that, and a process-kill test is not a power-loss test. Raising `synchronous` would
  change that trade-off and was **not** done: no PRAGMA was changed on the strength of a
  review suggestion.
- **[S] Ambiguous network outcomes.** Measured in §4.1: a lost seal response leaves the pad
  sealed while the caller sees an error.

## 5a. The logging boundary, stated precisely

Three separate claims, kept apart because they have different answers.

1. **[S] Credential logging at DEBUG is real and measured.** `aiosqlite` logs bound SQL
   parameters at DEBUG, and those parameters include the read ticket and the write-key hash
   (`… INSERT INTO tickets (ticket_id, pad_id, type, max_reads, created_at) VALUES (?,?,?,?,?)',
   ('<ticket>', …) completed`). The application does not control that logger. **The claim made
   here is not "capabilities are never logged at any level".** It is: at the configuration
   below they are not, and at DEBUG they are.
2. **[C] The effective logger configuration required for deployment.**
   - The daemon runs at `INFO` or above. `lockerd` configures no logging of its own — the only
     loggers it creates are `lockerd.main` and `lockerd.payments` — so it inherits the
     server's configuration, and uvicorn's default is `info`. `--log-level debug` is not safe.
   - Independently, pin `aiosqlite` to `WARNING`, so that DEBUG enabled elsewhere cannot reach
     its parameter logging. Both halves are pinned by tests.
   - `LOCKER_TICKET_TRANSPORT=header`, which is the default and is asserted by a test. Under
     `query` the ticket becomes part of the request URL.
3. **[S] Request-URL logging is a different question from credential logging.** At INFO, httpx
   logs each request URL. Measured: under header transport the ticket appears in **no** record
   and httpx renders no request headers; under query transport the ticket **is** present in the
   logged URL. A pad identifier does appear in URLs under both transports, because it is part
   of the path — and an identifier is not a credential: writes need the write key, reads need a
   ticket. Both cases are asserted by tests in `tests/test_deposit_recovery.py`.

## 6. The unreported defect found while reconciling the baseline

**[S] The baseline suite was not deterministic.** At `d59efac`, `pytest` reports
`1 failed, 184 passed`: `test_inspect_pad_script_uses_the_header_transport`, failing with
`argument --ticket/-t: expected one argument`.

Cause, measured rather than inferred: read tickets are `secrets.token_urlsafe(32)`, i.e.
URL-safe base64, so `-` is in the alphabet and roughly one ticket in 64 begins with one.
argparse then reads the value as an option. `repro/0.1.5/repro_ticket_dash.py` draws tickets
until it finds one beginning with `-` (7th draw, then 147th, in two runs), and shows the
space-separated form exiting 2 where the `--ticket=` form exits 0.

This was not one of the reported findings and is not a security defect; it is a real,
operator-visible defect in a shipped script plus a flaky gate over whether the branch is
green. `scripts/inspect_pad.py` now normalises that one argument form. Post-fix both forms
exit 0, and the previously flaky test passes.

## 6a. Capability material in reachable history — disposition

**[S] What was exposed, identified without reproducing it.** One earlier commit on the private
review branch, `e4138481656da592c3be9e07d10494d3bf13fb07`, contains two real values in its
captured reproduction output, both of which were redacted in the commits that followed:

| Value | Kind | Where | Reach |
|---|---|---|---|
| a read ticket (43 chars) | access-granting | `repro/0.1.5/out_ticket_dash.txt` | that commit only |
| a pad id (32 hex) | identifier | `repro/0.1.5/out_partial_deposit_prepatch.txt` | that commit only |

Neither value is reproduced here, and neither fingerprint is recorded here either: this
repository is public, and a digest of a value is still a value's fingerprint. Both can be
re-derived from the commit by anyone with access to it, using
`repro/0.1.5/characterize_capability_values.py`, which prints fingerprints rather than values.

No **write key** appears anywhere in this repository's history. The scan that establishes this
checked for the capability *shape* **and** for the exact bytes of every value found.

**[S] Every exposed value belonged exclusively to disposable local test data.** Both come from
`repro/0.1.5/repro_ticket_dash.py` / `repro_partial_deposit.py`, which create their daemon with
`tempfile.mktemp(prefix="repro_…", suffix=".db")`, `AUTH_OPEN`, and a uvicorn bound to
`127.0.0.1` on an ephemeral port. The ticket was searched for byte-for-byte across every
`*.db`, `*.db-wal` and `*.db-shm` under `/tmp` and the home directory: **absent**, so the
database that minted it no longer exists and the value is inert. It could not have reached a
retained or remotely reachable service: a read ticket is a random per-daemon string that only
the daemon holding that pad honours, and it was never transmitted anywhere — deliberately,
including in this investigation.

**[C] Pad identifiers and credentials are different things, and are reported separately.** A
pad id grants nothing on its own: writes require the write key and reads require a ticket. It
is withheld from evidence all the same, because the operator directive treats known pad
identifiers and capabilities alike there.

**[S] No release artifact contains either value.** An exact-byte scan of the 0.1.5 wheel and
sdist and of the published 0.1.4 wheel and sdist found neither. The four 43-character hits in
those artifacts are **test function names** — `test_hardening.py`, `test_lockerd.py`,
`test_post_012_findings.py` and `test_deposit_recovery.py` each contain a function whose name
is exactly 43 url-safe characters. **This is why a token-shape scan is not evidence:** a shape
check alone would have reported four false positives and buried the two real values. No release
tag reaches `e413848`.

**[S] The publication branch has a clean history.** `release/0.1.5-public` is based on the
public baseline `d59efac` and its commits contain neither value — verified by recovering both
values from the private commit and searching for them by exact bytes across all 72 blobs of
that branch, not by shape. Its tree is byte-identical to the private branch's final tree.

**[S] The private review branch is preserved unmodified.** It is left exactly where a reviewer
last saw it, with the exposing commit untouched. Redaction in a later commit does not sanitize
earlier history, which is precisely why the publication branch exists rather than a rebase, and
why nothing was force-pushed or silently rewritten.

## 7. Regressions added

`tests/test_deposit_recovery.py` — 10 tests, one per required validation case: failure
before creation; creation committed but response lost; failure after capabilities were
received; append committed then response lost; seal committed then response lost; integrity
mismatch with capabilities available; preservation of the existing error signal; absence of
capabilities from the client's logs, both streams, and the committed reproduction outputs;
a measured check that the daemon's DEBUG logging exposes ticket values and that quieting the
`aiosqlite` logger stops it; and a case showing a returned capability is usable by the caller
while never entering committed evidence.

`tests/test_deposit_integrity.py` — 13 tests:

- honest deposit returns the head computed from the submitted bytes (the positive fixture)
- the client chain equals the daemon's algorithm, including Unicode and an empty payload
- exact bytes are preserved, including the client's `ensure_ascii` escaping (see §8)
- an incorrect append acknowledgment cannot produce success
- an incorrect seal head cannot produce success
- a daemon that stores different bytes cannot produce success
- **sensitivity**: a deliberately blind deposit (the pre-fix logic, reproduced in the test
  file) accepts exactly what the real one rejects, so the controls above are not decorative
- a failed deposit is not described as rolled back or safely retryable, and the pad it left
  is proven to exist
- an interrupted deposit leaves a provable partial success
- a rewritten-and-rehashed chain fails against the computed head
- a truncated chain fails against the computed head
- preflight still rejects locally invalid input before creation, leaving nothing behind
- the model-visible metadata no longer claims atomicity and states the limits

## 8. Remaining limitations and open items

- **[S] Serialization is the client's, and it escapes non-ASCII.** `locker_deposit` encodes
  with `json.dumps(...)` defaults, so `ensure_ascii=True` turns `üñïçødé` into `\u00fc…` on
  the wire, and *those* escaped bytes are hashed. The bytes round-trip byte-for-byte through
  a verified read, and the same logical payload always produces the same head — but only
  through this client. A caller who re-encodes by hand with `ensure_ascii=False`, different
  separators or sorted keys would compute a different head. This is existing behaviour,
  deliberately unchanged, and it is why the client must own the encoding.
- **[U] `locker_append` and `locker_seal` cannot verify their own acknowledgments.** Adding
  an optional `expected_prev_hash` would make each checkable when the caller holds the prior
  head, mirroring `expected_head_hash` on the read side. Not implemented here: the directive
  asked for an assessment of what can be checked, and adding an optional parameter is a
  design decision for review.
- **[S] Measured operational hazard: DEBUG logging on a live daemon exposes tickets.**
  `aiosqlite` logs bound SQL parameters at DEBUG, and those parameters include the read
  ticket and the write-key hash (`… INSERT INTO tickets (ticket_id, pad_id, type, max_reads,
  created_at) VALUES (?,?,?,?,?)', ('<ticket>', …) completed`). An operator running a live
  daemon at DEBUG therefore writes capability material into the log. The client itself logs
  no capability and prints nothing, at DEBUG. The exposure and its mitigation are both
  pinned by `tests/test_deposit_recovery.py`: keep the daemon at `INFO` or above, or quiet
  the `aiosqlite` logger, and the ticket does not reach the log.
- **[S] A pad identifier does appear in request URLs logged by httpx's own transport logger
  at INFO.** The API cannot avoid it — the pad id is part of the request path. The client's
  own records carry none, and a pad id alone grants nothing: writes need the write key and
  reads need a ticket. Stated because the natural reading of "no identifiers in logs" would
  be false.
- **[U] Multi-process safety is unsupported and unmeasured** (§5).
- **[U] The recovery contract is unimplemented** and its §4.3 decisions are open.
- **[S] An unreachable pad is still unreachable.** When a deposit fails after creation and
  no capabilities were returned, the pad cannot be read, written, sealed or removed through
  this API by anyone, including the operator. This patch does not change that; it makes one
  more failure mode visible (integrity refusal) that has the same consequence.
- **[C] Passing tests are not readiness.** Everything here ran against a local daemon and a
  local shim on temporary data. Nothing was exercised against a live payment, a production
  endpoint or a remote host. The correctness of a *deployed* daemon under hostile network
  conditions is not established by any of it.
- **[C] On the hosted demo.** The directive instructs that claims about an outdated hosted
  demo are unverified, and that a version string inside stored demo content is not proof of
  the running build. No claim is made here about the running hosted build's identity: the
  only observations available from this branch are HTTP responses, and those distinguish
  observed responses from deployment records from actual running code, which this branch did
  not inspect.
