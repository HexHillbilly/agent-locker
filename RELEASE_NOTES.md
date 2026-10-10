# Release notes

Point-in-time observations about deployed instances. These are dated snapshots,
not standing facts — re-observe before relying on them. Deployment state is
deliberately kept out of the installation instructions in `README.md` because it
goes stale faster than the code does.

## 0.1.5

**The writer's reference is now its own, and a failed deposit returns what it can.** No
hash-format, schema or stored-data change; read the compatibility note at the end.

- **`locker_deposit` returned the daemon's seal-response head without checking it against
  the bytes it submitted, and accepted each append acknowledgment unchecked.** Measured
  with an injecting HTTP shim in front of a real daemon, driving the client's own code
  path: a shim that stored *different bytes* than the writer sent — and acknowledged them
  honestly — produced a successful deposit, and the reference the caller then retained
  reported `trusted_head_match` when reading content the writer never submitted. The client
  now encodes the envelope and each artifact once, computes the expected chain from exactly
  those outgoing bytes, checks every acknowledgment's `seq` and `curr_hash` and the seal
  response against it, and returns that locally computed value as `head_hash` with
  `head_source: "locally_computed"` and the daemon's own value beside it as
  `server_head_hash`. Against an honest daemon the two agree, so a successful deposit is
  unchanged. A disagreement is an explicit `verification_failed` refusal — nothing is
  retried, compensated or claimed undone.

- **The deposit tool no longer describes itself as atomic.** It is a sequence of
  independently committed requests. The description now says so, states the partial-success
  risk, and states what verification does not establish. `locker_append` and `locker_seal`
  now say plainly that their results are the daemon's assertion, because without the pad's
  prior chain state the client has nothing to recompute against.

- **Classification corrected:** an HTTP failure on a *dispatched* request leaves the outcome
  **uncertain**, whatever the status. A 4xx does not establish that the response came from the
  daemon rather than an intermediary, nor that the upstream operation did not commit, so it is
  not treated as a no-commit contract; `not_created` is reserved for a locally established,
  pre-dispatch failure. Nor is it true that the daemon "cannot return 5xx" — the routes never
  return 5xx deliberately on these paths, but an unhandled exception inside a route is turned
  into a 500 by the framework, which can follow a commit.
- **A failed deposit now returns the capabilities it received, in a structured block.**
  The `error` indicator is unchanged, so callers that branch on it keep working, and the
  ordinary success shape is never returned for a failure. Alongside the error, every
  failure carries `partial`: a `status` (`not_created` / `partial` / `unknown`), a stable
  `cause`, the steps `acknowledged`, the steps `uncertain`, a `recovery` classification, the
  `capabilities` when they were genuinely received (else `null`), and
  `automatic_recovery: false`. A lost create response is reported as an **unknown** outcome
  with recovery unavailable through this API, because nothing was received to hand back. A
  lost seal response is reported as **uncertain** — the pad may already be sealed — and
  never as "still open". An uncertain append may already have committed and the result says
  not to retry it blindly.

  **[C] A capability-bearing error result is as sensitive as a successful creation
  result.** It goes only to the caller that made the request: never a log line, an exception
  string, captured evidence or a report.

- **A shipped CLI defect, found while reconciling the reviewed baseline.** Read tickets are
  URL-safe base64, so about one in sixty-four begins with `-`, and
  `scripts/inspect_pad.py --ticket <value>` then failed at argument parsing. The script now
  accepts that form. This also made one baseline test fail nondeterministically.

**[C] What the check does and does not prove.** It establishes that the daemon's account of
the bytes agrees with the bytes the writer submitted. It does **not** establish durable
storage, availability, writer identity, the truth of the payload, or task completion. A
later reader can check the bytes it retrieves against a reference it was given
independently, and that remains the only way to detect a comprehensive rewrite.

**[C] Compatibility.** Additive only. Successful deposits keep their existing keys and add
`head_source` and `server_head_hash`; failures keep the `error` object they always had and
add `partial`. Nothing is removed, no daemon API changed, no stored data changed, and the
hash format is untouched. `locker_create`, `locker_append` and `locker_seal` are unchanged
apart from their descriptions.

**[C] Operational note, measured — the logging boundary.** Three separate settings, and
none of them alone is sufficient:

- **Run the daemon at `INFO` or above.** `aiosqlite` logs bound SQL parameters at `DEBUG`,
  and those parameters include read tickets. `lockerd` configures no logging of its own, so it
  inherits the server's; uvicorn's default `info` is safe and `--log-level debug` is not.
- **Pin `aiosqlite` to `WARNING` as well**, so that DEBUG enabled for some other component
  cannot reach its parameter logging.
- **Keep `LOCKER_TICKET_TRANSPORT=header`** (the default). Under `query` the ticket becomes
  part of the request URL, and httpx logs request URLs at `INFO`, so the ticket would be
  written to the log by the HTTP client — which this application cannot prevent.

Request-URL logging is a separate question from credential logging: a pad identifier does
appear in logged URLs under either transport, because it is part of the path, and an
identifier is not a credential — writes need the write key and reads need a ticket. The
application itself logs no capability and prints nothing, at DEBUG. All three statements are
pinned by tests rather than asserted.

## 0.1.4

**Data-integrity fix, plus a request-body limit and a seal check.** Read the first item
before upgrading a write-enabled daemon.

- **A concurrent `/health` request could discard an acknowledged write.** The daemon
  serves every request from one SQLite connection, and `health_check()` probed write
  capability by issuing `BEGIN IMMEDIATE` followed by `ROLLBACK` **on that shared
  connection, without the lock that every other route takes**. A rollback landing between
  another request's `INSERT` and its `COMMIT` discarded the insert while the request went
  on to commit the head update and return `201` — an acknowledged block that is not
  there. The same unlocked access could also make an unrelated request fail outright, and
  the failure could go unnoticed because the surviving prefix is still a perfectly valid
  chain. Health no longer performs **any** transaction control, reads on its own
  read-only connection, and issues its remaining shared-connection read under the lock.
  Every route now also owns its transaction explicitly, so a handler that fails or is
  cancelled mid-way can no longer leave statements for a later request to commit.
  **What this changes for you:** `database.writable` on `/health` still means "the
  database is not read-only" — it is a capability indicator, not proof that a write will
  succeed, and it no longer implies a live write probe ran.
- **Request bodies on `POST /v1/pads` and `POST /v1/pads/{id}/tickets` are now capped at
  4 KB.** They previously used framework body parsing, which buffers and parses the whole
  body before any limit is consulted; a measured 2 MB body was accepted and cost ~6 MiB.
  The cap is applied to the bytes actually received, before parsing, so a missing or
  untrue `Content-Length` changes nothing and chunked input is capped identically. Over
  the limit is `413 payload_too_large`, refused before any pad, ticket, receipt or block
  is created. Routes that take no body never read one — an explicit policy. The per-block
  (64 KB) and per-pad (256 KB) limits are unchanged.
- **Sealing now checks the stored chain first.** `POST /v1/pads/{id}/seal` verifies
  contiguous sequence numbers, hash linkage, the stored head and byte accounting, and
  refuses with `409 inconsistent_pad` if they do not hold — leaving the pad open and its
  rows untouched. It never repairs: recomputing a head or dropping blocks would destroy
  the evidence that an acknowledged write went missing.

**What this does not fix.** A store that already lost acknowledged writes is not
repaired, and nothing here can prove whether it did: a correctly written chain that later
lost its tail looks exactly like a short-but-consistent chain, because a pad keeps no
independent record of what it acknowledged. `scripts/check_integrity.py <db>` reports
what is structurally wrong in a store, read-only, and changes nothing — it can find
inconsistency, never absence. If you suspect loss on a live store, stop concurrent health
polling and writes and copy the database with its `-wal`/`-shm` files before anything
else touches it.

`locker_deposit` is one tool call, not one transaction: a failure part-way can leave a pad
created with capabilities that only existed in the return value of the call that failed.
Every artifact is now validated before the pad is created, which removes the common case;
the daemon's own checks still run after creation. See README "Partial deposit".

## 0.1.3

**Security fix.** Two behavioural changes in the MCP client; read them before upgrading.

0.1.2 could *detect* a broken chain but would still hand you its payloads.

- **A broken chain now fails closed.** If a block's recorded hashes do not match the
  bytes it carries, both read tools return `error.kind = "verification_failed"` with
  `cause: "chain_inconsistent"` and **no `blocks` key at all**. In 0.1.2 that failure
  was reported only inside the `integrity` block: an unanchored read
  (`locker_read_blocks` without `expected_head_hash`) returned the tampered payloads
  in the normal result shape, so a caller that did not inspect the integrity metadata
  consumed them. That is no longer possible, and it holds whether or not an expected
  head was supplied.
- **Callers must check for an error before touching blocks.** Code that read
  `result["blocks"]` after a failed chain now finds no such key.
  `result.get("blocks", [])` yields an empty list; unconditional indexing raises.
  Test `"error" in result` first. Callers that already inspect `integrity.verdict`
  are unaffected — the same verdict values are produced.
- **`content_type` is no longer returned by the MCP read tools.** The daemon still
  stores and serves it, and the hash never covered it. It is a *processing
  instruction*, so a value like `text/html` beside a verified payload invited callers
  to treat verified bytes as active content. It is omitted rather than replaced with
  an asserted type; callers needing it must fetch it from the daemon and treat it as
  unverified.
- **Direct HTTP behaviour is unchanged.** Only the MCP client's responses changed.
  The daemon's routes, request and response schemas, stored data and reported version
  are untouched — anyone talking to `lockerd` over HTTP sees exactly what 0.1.2
  served.
- **`head_provenance` makes the three possible heads explicit.** `locker_manifest`
  returns a new additive object naming `manifest_head` (asserted by the daemon, marked
  `verified_by_client: false` unless a full chain was walked and this client's own
  recomputation landed on it), `recomputed_head` (this client's own computation) and
  `expected_head` (supplied by the caller). The existing `head_hash` field is
  unchanged.
- **What this does not fix.** A valid unanchored read still cannot detect a pad whose
  entire history was rewritten *and* fully rehashed — such a chain is internally
  perfect. **An independently trusted `expected_head_hash`, obtained from the writer
  over a channel the daemon does not control, remains necessary for that protection.**
  Do not obtain it from the daemon you are checking.

**[C] This is a client behaviour change, not a daemon or hash-format migration.** The
hash format, the database schema and the HTTP API are all unchanged, and no stored
data is migrated.

## 0.1.2 (2026-10-08)

Changes since `0.1.1`. Retention and ticket-lifecycle policy is deliberately
**not** included; that work waits on operator decisions and has no code in this
release.

- **Trusted-head verification.** `locker_read_blocks` and `locker_manifest` accept
  an optional `expected_head_hash` — a 64-character lowercase hex sha256 digest the
  caller obtained from the writer over a separately trusted channel, normally the
  `head_hash` returned by `locker_seal` or `locker_deposit`. The client recomputes
  the head from the chain it fetched and compares. This is the only check that
  detects a chain rewritten **and** rehashed so that it verifies against itself;
  internal consistency alone cannot. The daemon's own manifest head is never
  substituted for the caller's reference.
- **A verdict instead of a boolean.** Reads return `integrity.verdict` —
  `trusted_head_match`, `internal_consistency_only`, `not_checked` or `failed` —
  plus an additive `integrity.expected_head` block (`supplied`, `checked`,
  `matches`, `expected`, `observed`, `detail`). A malformed or mismatching head
  **fails verification and returns no payloads** (`error.kind ==
  "verification_failed"`).
- **Returned text is derived from the verified bytes.** The daemon supplies
  `payload_utf8` as a parallel derivation; the client previously returned it
  unverified, so a host could serve bytes that hash correctly alongside different
  text. The client now recomputes the text from the payload bytes it verified
  (strict UTF-8, else `null`) and **fails closed** if the daemon's claim disagrees
  (`cause: representation_mismatch`). Blocks gain
  `payload_utf8_source: "client-derived"`; `payload_b64` is preserved exactly.
- **Incomplete or inconsistent retrieval fails closed.** A short page, an unusable
  `block_count`, a `total_blocks` that disagrees with the manifest or changes
  between pages, a `seq` that is not the block's position, a foreign `pad_id` echo,
  or an undecodable payload now produce an error with no payloads (`cause:
  incomplete_retrieval` / `inconsistent_blocks`) instead of a verified read. The
  pre-existing hash-chain-break path (`chain_valid: false`, blocks returned, no
  expected head) is unchanged.
- **Unknown `LOCKER_MODE` stops the daemon.** An explicitly supplied but
  unrecognised value raises `ConfigError` at startup instead of silently falling
  back to `open`, which would have disabled payment enforcement without a word.
  Unset or empty still means the documented default.
- **Read tickets travel in the `Authorization` header.** The MCP client sends
  `Authorization: Bearer <ticket>` rather than a `?ticket=` query parameter, so
  tickets stay out of URLs and logs. `LOCKER_TICKET_TRANSPORT=query` remains an
  explicit opt-in and the daemon still accepts both. `scripts/inspect_pad.py` moved
  to the header as well.
- **Payloads are framed as untrusted.** Tool descriptions, server instructions and
  every returned integrity block state that payloads are data, not instructions,
  and that chain consistency establishes neither authorship nor truth.
- **The shipped Compose file no longer publishes the daemon to the world.** It
  bound `"8000:8000"` — the wildcard address on IPv4 *and* IPv6 — which makes any
  control at a proxy in front of the daemon bypassable by talking to the origin
  port directly. It now binds `127.0.0.1:8000:8000`. Remote clients are therefore
  not served by that file: publishing the daemon beyond its host requires a
  deliberately configured reverse proxy or another intentional deployment
  arrangement, which is a deployment decision rather than a shipped default.
- **Lifecycle behaviour is now documented rather than implied.** `README.md`
  states what expiry does and does not do (write expiry stops writes and neither
  stops reads nor authorizes deletion), that sealing closes a pad to appends and
  is **not** a promise of permanent storage, that nothing in the daemon deletes
  payloads, that payment receipts are retained indefinitely as the replay key, and
  that deleting from a live database does not delete from backups or WAL.
- **No hash-format change.** `curr_hash = sha256(prev_hash ++ payload_bytes)` is
  untouched in this release, and the hash functions are not modified.

## 0.1.1 (2026-10-07)

Changes since `0.1.0`:

- **Licensing.** Added the verbatim GNU AGPL v3 text as `LICENSE` and wired it
  into the packaging metadata (`License-Expression: AGPL-3.0-or-later`,
  `License-File: LICENSE`), so both the wheel and the sdist carry it.
  `README.md` now documents the dual license and states that commercial
  licenses are available on request.
- **Version.** `0.1.0` → `0.1.1` in `pyproject.toml`, both packages'
  `__version__`, and the MCP server identity. `/health` reports the package
  version, so the reported version moves with the package.
- **Documentation.** `README.md` now separates the installed-package,
  source-distribution and repository workflows; documents the
  `POST /v1/pads/{id}/tickets` endpoint implemented in this revision; states the
  integrity guarantees and, separately, their limits; and drops the hard-coded
  test count.
- **Source distribution contents.** Added `MANIFEST.in` so the sdist carries the
  files the documented source-install and example workflows need — `scripts/`,
  `demo_handoff.py`, `mcp_config.example.json`, `Dockerfile`,
  `docker-compose.yml`, `.env.example` and these notes. Host deployment
  materials under `deploy/` are deliberately excluded.
- **Release tooling.** Added `scripts/release_build.py`: a repeatable
  export-and-build command that takes an explicit commit, builds from a fresh
  export of that commit, and records a source manifest, provenance and artifact
  hashes.

## 2026-10-07 — hosted instance trails the source revision

Observed while reconciling release state (Phase S1). Recorded as an observation,[S]
not a supported configuration.

| Surface | Observed | Note |
|---------|----------|------|
| `https://api.padlockspace.org/health` | `200`, `version 0.1.0`, payload uses `active_pads` | responding |
| `https://api.padlockspace.org/openapi.json` | 6 routes, **no** `/v1/pads/{pad_id}/tickets` | predates the ticket endpoint in this tree |
| `https://api.padlockspace.org/v1/pads/demo-pad-v1/blocks` | `200` (no ticket required) | demo pad is served |
| `POST .../demo-pad-v1/append` with `demo-write-key` | **`401`** | source revision returns **`409 Conflict`** (verified locally) |
| `https://padlockspace.org/` | `404`, zero-length body, `server: Caddy` | static site is **not** deployed |
| `www.padlockspace.org` | does not resolve | no DNS record observed |
| `POST /v1/pads` documented responses | `201`, `422` only — no `402` | hosted build consistent with `LOCKER_MODE=open`; payment rail not evidenced as enabled |

Consequences, stated plainly:

- The hosted revision **does not match this source tree** and does not expose the
  ticket endpoint. Do not describe the hosted service as matching HEAD.
- The `demo-write-key` → `409` behaviour documented in `README.md` is correct for
  **this revision**; the live host returns `401` because it is older. That is a
  deployment gap, not a documentation error.
- The `llms.txt` served by the host advertises the ticket endpoint and the `409`
  behaviour; both are ahead of what that host actually runs.

No redeployment was performed or authorised.

## 2026-10-08 — corrections to the 2026-10-07 observations

Two corrections to the snapshot above. The original text is left in place: it is
the record of what was believed on that date.

- **The `llms.txt` claim was wrong.** The 2026-10-07 entry states that the
  `llms.txt` served by the host "advertises the ticket endpoint and the `409`
  behaviour". Read directly from the host, the file it served (1450 bytes)
  listed six endpoints and contained **no** `POST /v1/pads/{id}/tickets`; the
  only matches for "ticket" were the phrase "read ticket", the `read_ticket`
  field of the create response, and the `?ticket=` query parameter. The file
  that *does* advertise the ticket endpoint is this repository's own copy at
  `deploy/padlockspace/www/llms.txt` (2754 bytes) — that copy, not the host, was
  the source of the error.
- **The static site is deployed.** The `https://padlockspace.org/` → `404` row
  above was accurate on 2026-10-07 and is now stale. The site has since been
  deployed. Its files are maintained in a **separate, private repository**; the
  copies under `deploy/padlockspace/www/` are historical and are not what is
  served.

Re-observed on 2026-10-08, otherwise unchanged: `https://api.padlockspace.org/health`
→ `200`, `version 0.1.0`; `/openapi.json` → 6 routes, **no**
`/v1/pads/{pad_id}/tickets`; the demo pad reads `200` without a ticket.

### A caution about the version string

`/health` reports the package version, but a version number does not identify a
commit. In this repository `0.1.0` spans several commits — the `v0.1.0` tag
points at the commit that *introduced* `POST /v1/pads/{id}/tickets` — while the
hosted instance reports `0.1.0` and does not expose that route. Which commit the
host runs is therefore **not established** by its reported version; treat that
number as a hint, not an identifier.

No redeployment, version change, artifact rebuild, tag move, or runtime code
change is part of this correction.
