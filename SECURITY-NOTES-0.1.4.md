# Security record — 0.1.4 acknowledged-write loss and request-body limits

Unshipped working record. Preparation and publication status lives here, not in
anything a user of the package reads.

**Status: prepared, not published, not tagged, not deployed.** Branch
`security/0.1.4-ack-write-loss`, based on the released 0.1.3 source
`eddd04b631e6592d84bf9efe54ac5f8e05cea73f`.

External reviewers supplied the findings. Their mechanism descriptions were treated as
claims to reproduce; the numbers below marked **[S]** are this machine's own
measurements. The reviewers' figures are reproduced only where labelled as theirs.

## 1. Finding A — a health request could discard an acknowledged write

### 1.1 Mechanism, confirmed from source

**[S]** The store keeps one `aiosqlite` connection shared by every request, and its
methods are deliberately lock-free because the request layer is meant to serialize
compound operations with `Store.lock`. Ten call sites take that lock. **`/health` did
not**, and `health_check()` probed write capability with `BEGIN IMMEDIATE` followed by
`ROLLBACK` **on the shared connection**. A rollback landing between another coroutine's
`INSERT` and its `COMMIT` discards the insert, after which that coroutine commits only
the head update and reports `201`.

### 1.2 Deterministic reproduction

**[S]** `Store.health_check()` and `Store.append_block()` were driven unmodified, with a
pass-through wrapper around `Store.conn` deciding only *when* each side's statements
reach SQLite (harness at `/tmp/repro_a_deterministic.py`). Persisted state was read from
a separately opened `sqlite3` connection, and the check is the acknowledged
`(seq, curr_hash, payload digest)` — not `chain_valid`, which cannot see a missing tail.

| Run | Persisted blocks | Persisted head | Acknowledged write |
|---|---|---|---|
| Control — health after the append | 1 | matches the ack | persisted |
| Interleaved — health's transaction straddles the append's INSERT | **0** | **matches the ack** | **LOST** |

The interleaved row is exactly the reported residue: the block is gone while the head
and byte count say it was written, and the caller was told it succeeded.

### 1.3 Bounded concurrent workload

**[S]** Real ASGI application through `httpx.ASGITransport` (lifespan included), 20 pads ×
5 appends = 100 acknowledged appends, verified per acknowledgment from a separate
connection:

| Arm | Acknowledged | Persisted & matching | Lost | Hash/payload mismatch | Accounting anomalies | Failed requests |
|---|---|---|---|---|---|---|
| Without health polling | 100 | 100 | 0 | 0 | 0 | 0 |
| **With health polling (before fix)** | **56** | **50** | **2** | **4** | **5** | **14** |
| With health polling (after fix) | 100 | 100 | 0 | 0 | 0 | 0 |

**[S] A third symptom, not in the reviewer's report:** 14 requests failed outright with
`sqlite3.OperationalError: cannot commit transaction - SQL statements in progress` —
another coroutine's `COMMIT` landing while health's cursor was mid-flight. Health also
returned `503` during the run, because its `BEGIN IMMEDIATE` failed against a connection
busy with application work.

**[U] The reviewer's rates are not confirmed.** They reported 25–29 of 40 pads
inconsistent and 11 of 97 acknowledged appends lost. This bounded run measured 2 lost of
56 acknowledged, 5 accounting anomalies, and 14 failed requests, at these parameters.
The *mechanism* is confirmed; the *rates* are workload-dependent and remain their
figures, not mine.

### 1.4 The fix

**[C] Chosen after inspecting every shared-connection user:** the append, create-pad,
ticket-mint, lease-update, expiry, seal, manifest and read routes already took the lock;
`seed_demo_pad` runs before the server accepts requests. **`/health` was the only
serving path that did not.** A one-line lock change would therefore have covered the
reported symptom — but not the cursor-interleaving failure above, and not the
"uncommitted work leaks into a later request" case. What was implemented:

1. **Health performs no transaction control at all.** The `BEGIN IMMEDIATE` / `ROLLBACK`
   probe is gone. `database.writable` is derived from the read-only indicator, which is
   what the documented contract already promised ("200 ok / 503 if DB read-only"). The
   probe was the thing that corrupted data, and it was never part of the contract.
2. **Health reads on its own connection, opened read-only** (`PRAGMA query_only = ON`).
   A liveness probe cannot roll back, cannot break another request's `COMMIT`, needs no
   lock, and never blocks a writer.
3. **Health's single remaining shared-connection read is taken under the lock**, so the
   invariant "every statement on the shared connection is issued under the lock" holds
   without exception.
4. **`Store.transaction()`** — an explicit transaction owner used by every route. On any
   exit that is not a clean return, including cancellation, it rolls back, so a handler
   that fails part-way cannot leave statements for a later request to commit.
5. **[C] `database.writable` is documented as a capability indicator, not proof that a
   write succeeded.** A connection flag cannot witness a future write; the old probe was
   an attempt to do that and it cost data integrity.

**[S] The lock's scope is stated, not assumed:** `asyncio.Lock` serializes coroutines in
one process. Each process opens its own connection, so this is correct for the
single-process deployment described in the README; it is **not** a cross-process lock
and multi-worker access to one connection is not supported.

### 1.5 Seal defense

**[S]** Added: `POST /v1/pads/{id}/seal` checks the stored chain before sealing —
contiguous 0-based `seq`, `prev_hash` linkage from genesis, each `curr_hash` recomputed
from its predecessor and payload, the stored head equal to the last block's `curr_hash`,
and `current_bytes` equal to the stored payload total. A failure is `409
inconsistent_pad`; the pad stays `open` and its rows are untouched. **[C] Never repaired:**
recomputing a head, dropping blocks or normalizing a chain would destroy the only
evidence that an acknowledged write went missing. This supplements the transaction fix;
it is not the fix.

### 1.6 Existing data — read-only assessment

**[S]** `scripts/check_integrity.py <db>` reports the same properties for every pad,
opening the database read-only and changing nothing. Verified: a healthy store exits `0`;
a store with a deleted block exits `1` and reports the `seq` gap, the broken linkage and
the byte shortfall; a store with inflated `current_bytes` exits `1`.

**[C] The limitation, stated plainly:** a stored chain cannot prove that previously
acknowledged data was lost. It only shows what is present. A correctly written chain that
later had acknowledged tail data discarded is indistinguishable from a short-but-consistent
chain, because a pad keeps no independent record of what it acknowledged. Only the
caller's own acknowledgment records — the `pad_id`, `seq` and `curr_hash` of each `201` —
can witness a write that is no longer there.

### 1.7 Affected range — checked, not assumed

**[S]** `grep` against each tag's source: the mutating health probe is present in
**v0.1.0, v0.1.1, v0.1.2 and v0.1.3**, none of those health routes takes the store lock,
and all four use framework JSON body parsing. So the finding applies to every published
release to date. Nothing here proves or disproves the reviewers' observations about other
deployments; only 0.1.3 was exercised on this machine.

## 2. Finding B — JSON bodies bypassed the documented cap

**[S] Reproduced with a bounded measurement** (2,097,201-byte body, peak allocation
tracked with `tracemalloc` rather than by attempting exhaustion):

| Source | Response | Peak allocation | Pad created |
|---|---|---|---|
| Released 0.1.3 | **201 accepted** | **6.16 MiB** | yes |
| Fixed | **413 refused** | **0.22 MiB** | no |

**[S]** `POST /v1/pads` and `POST /v1/pads/{id}/tickets` took framework-parsed JSON body
parameters, which buffer and parse the whole body before any limit is consulted; only
`/append` used the explicit streaming cap. **[U]** The reviewer's 300 MB → ~1 GB figures
are not reproduced here — deliberately, since the order forbids allocating hundreds of
megabytes to demonstrate an exhaustion.

**[C] Fix:** both routes read at most `MAX_JSON_BODY_BYTES` (**4 KB**) of *streamed* bytes
before parsing, refuse beyond that with `413 payload_too_large`, and validate only
afterwards. The limit counts bytes actually received, so a missing, short or untrue
`Content-Length` changes nothing, and chunked input is capped identically. A route that
takes no body never reads one — an explicit policy, tested at the ASGI level by counting
`receive()` calls. The per-block (64 KB) and per-pad (256 KB) limits are unchanged.

## 3. Finding C — deposit partial failures

**[S] Confirmed from source.** `locker_deposit` creates the pad first, then appends, then
seals. The artifact type check ran **inside** the append loop, so a non-`str`/`dict`
artifact raised `ValueError` *after* the pad existed — and that exception is not caught by
the tool's `except LockerError`, so `pad_id`, `write_key` and `read_ticket` were lost with
it. The pad is then unreachable: those capabilities exist only in the return value of the
call that failed.

**[S] Corrected:** every artifact is now encoded and type-checked **before** any remote
creation, which removes that failure mode entirely. **[C] Corrected wording:** the README
described `locker_deposit` as "atomic create + append envelope + append artifacts + seal
in one call". It is one *call*, not one *transaction* — a sequence of independent
requests, each atomic on its own. The README now says so, distinguishes the daemon's
genuinely transactional create-pad/payment operation (`create_pad_with_receipt`, one
transaction) from this multi-request workflow, and documents what a raised deposit means.

**[S] Adjacent finding, reported not changed:** the create route inserts the pad and its
first read ticket as two commits. If the second fails, the pad exists with no ticket —
an orphan in the same class as Finding C. **[U] Fixing it needs a design decision**
(a combined store method, or deferring commits to the route's transaction), so it is
reported rather than changed. `create_pad_with_receipt` already shows the combined-method
pattern.

**[S] Also still true after this release:** the daemon's own checks (envelope shape,
per-block and per-pad size limits) run *after* creation, so those can still fail
part-way. The client does not carry the daemon's limit constants, so it cannot
pre-validate them without duplicating policy.

### 3.1 Proposed recovery contract — not implemented

**[U] A design question, deliberately left open.** Returning capabilities from a partial
remote success needs a stated contract before code exists. The shape to decide:

- **Which failures return capabilities.** A caller that has already paid (txid mode) or
  whose pad exists should probably receive `{pad_id, write_key, read_ticket, status:
  partial, failed_at}` rather than an error — but only when the capability genuinely
  exists, i.e. after a successful `POST /v1/pads`.
- **Where it is carried.** A structured field in the tool result, not an exception
  string; write keys and read tickets must never appear in logs, error text or generic
  responses.
- **What the caller can then do.** Choices: refuse (current behaviour), return and let
  the caller seal or abandon it, or expose an operator-only cleanup path. **Deletion is
  not authorized here** and automatic compensation, replay or repair are explicitly out
  of scope.
- **What is *not* proposed.** No automatic retry, no deletion, no compensation, no
  change to the transactional create-pad/payment path.

## 4. Compatibility effects

- **`/health`** — same status codes and body shape. `database.writable` still means "not
  read-only"; it no longer implies a live write probe succeeded. Clients that treated a
  200 as "writes will work" should treat it as "the database is not read-only".
- **`POST /v1/pads`, `POST /v1/pads/{id}/tickets`** — new `413` for bodies over 4 KB.
  Valid requests are unaffected. Invalid-but-small bodies are still `422`.
- **`POST /v1/pads/{id}/seal`** — new `409 inconsistent_pad` for a pad whose stored chain
  does not hold together. A consistent pad seals exactly as before.
- **`locker_deposit`** — an invalid artifact now raises before the pad is created instead
  of after.
- **Unchanged:** the hash format, the HTTP API shape, the database schema, all stored
  data (nothing migrated), the per-block and per-pad limits, the trusted-head /
  representation / fail-closed behaviour from 0.1.3.

## 5. Remaining risks and operator mitigation

- **[C] Existing stores may already contain lost writes**, and nothing in this release
  can prove it either way. Run `scripts/check_integrity.py` on a **copy** of the
  database; absence of problems is not absence of loss.
- **[C] Any deployment running the pre-0.1.4 daemon is exposed** while it accepts
  concurrent `/health` polling and writes. Minimal mitigation, no code change: **suspend
  concurrent health polling during writes** — poll only when idle, or disable the probe
  and rely on a process-level liveness check. Best remaining option: make health polling
  single-flight with writes (serialize them in the monitoring layer) until 0.1.4 is
  deployed.
- **[U] The separate development machine** was previously reported to run a
  write-enabled, wildcard-bound daemon. It is not touched here and its exposure is not
  assessed. If it serves writes and is health-polled, the mitigation above applies to it
  too. Public-demo containment (GET/HEAD on three paths, loopback-only binding) does not
  protect any other deployment.
