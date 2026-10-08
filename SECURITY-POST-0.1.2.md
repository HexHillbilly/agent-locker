# Security record — post-0.1.2 review findings

Bounded change made after the 0.1.2 release in response to an independent review.
**Local branch only: not published, not tagged, not deployed, no version bump, no
artifact rebuild.**

Branch: `security/post-0.1.2-findings`, based on the released source
`a98924c0bdb87e2e14d4cb049b36056e3be2545b` (the `v0.1.2` tag target).

Labels: **[S]** captured output/source · **[U]** unverified · **[C]** constraint or
decision.

**[C] The reviewer's other suggestions are out of scope** and were not adopted:
deletion, ticket expiry, rate limiting, deployment, release process, handoff-bundle
convenience, document relocation, Trusted Publishing and lifecycle alternatives.
The recorded Phase 4 rulings are unchanged.

---

## 1. Finding A — a broken chain returned payloads without an expected head

### 1.1 Reproduction against the released source

**[S]** A real daemon, a real pad (`envelope`, then `pay Alice 10 USDC`), sealed. Then
block 1's `payload` was altered in the database **without recomputing the chain**,
and the pad read through the MCP tools:

| Read | Result before the fix |
|------|----------------------|
| with the true expected head | `error` `verification_failed` / `chain_inconsistent` — already correct |
| **without an expected head** | **no top-level error**, `chain_valid: False`, `verdict: failed`, **2 blocks returned** |
| `locker_manifest`, no expected head | **no top-level error**, `verdict: failed` |

**[S]** The tampered text reached the caller verbatim: block 1's `payload_utf8` was
`'pay Mallory 9999 US'` where the writer had written `'pay Alice 10 USDC'`.

So the finding is real. The exposure is not that verification failed — it did — but
that the failure was advisory. A caller had to *inspect a metadata field* to avoid
consuming tampered content, and a caller that did not inspect it received the
tampered payload in the normal result shape.

### 1.2 Fix

**[C]** Chain-verification failure now fails closed in **both** read tools, anchored
or not. One shared decision point, `_resolve_trust`, is used by `locker_read_blocks`
and `locker_manifest` so the two cannot drift apart:

- the chain is internally consistent and no reference was supplied →
  `internal_consistency_only`, payloads returned;
- the chain is internally consistent and the reference matched → `trusted_head_match`,
  payloads returned;
- **the chain is not internally consistent → `verification_failed` /
  `chain_inconsistent`, no payloads**, whether or not a reference was supplied;
- the reference did not match or was malformed → `verification_failed`, no payloads
  (unchanged).

**[S]** The failure response carries no payload representation of any kind: no
`blocks` key, no `payload_b64`, no `payload_utf8`, and no excerpt of the
attacker-supplied bytes in the detail. Tested by asserting a distinctive marker
string appears nowhere in the serialised response.

### 1.3 Compatibility impact

**[C]** This is an intentional response-contract change, and it is the change that
matters for callers:

- **A caller that read `result["blocks"]` after a failed chain now gets an error with
  no `blocks` key.** Code doing `result.get("blocks", [])` receives an empty list
  instead of tampered content — strictly safer, but code that indexed
  `result["blocks"][n]` unconditionally will now raise. That is the intended
  direction of the change.
- **A caller that already inspected `integrity.verdict` is unaffected**: the same
  verdict values are produced, and `chain_inconsistent` was already the cause on the
  anchored path.
- The old behaviour was documented in `SECURITY-PHASE3.md` §9 as deliberately
  preserved for the e2e tamper test. **[C] That justification is now withdrawn** —
  preserving unsafe output to keep a test green is the wrong trade, and the test was
  updated instead (`scripts/test_handoff_e2e.py`, and the unit test in
  `tests/test_phase3_trusted_head.py`).

---

## 2. Finding B — server-controlled `content_type` beside verified bytes

### 2.1 Trace

**[S]** Where the field comes from and goes:

| Stage | `content_type` |
|-------|----------------|
| daemon `POST /append` | supplied by the writer, stored in `blocks.content_type` |
| daemon `GET /blocks` | emitted per block from the DB (`lockerd/main.py`) — **unchanged by this pass** |
| MCP client read path | passed through to the caller **without being read** |
| MCP client write path | `locker_append(..., content_type=...)` — a *parameter*, unrelated to the returned field |

**[S] Nothing on the read path consumes it.** The only occurrences of `content_type`
in `lockermcp/server.py` are the write parameter, the docstring, and the removal set
added by this change. No client behaviour depends on the returned value, so removing
it cannot change how the client processes a payload.

### 2.2 Reproduction

**[S]** With payload bytes, the whole chain and the expected head all left exactly as
the writer made them, and only `blocks.content_type` changed from `text/plain` to
`text/html`:

- `verdict: trusted_head_match` — unchanged;
- the returned block carried `content_type: 'text/html'` next to a payload whose
  bytes the hash verifies.

**[C] The hash does not cover `content_type`**, so a host can set it freely. Beside a
verified payload that is a *processing instruction*: a caller that honours it may
render or parse verified bytes as active content. The reviewer's framing — that
presenting the field encourages using an unverified value as an instruction — is
correct, and the harm is in the presentation, not in the bytes.

### 2.3 Fix

**[S]** `content_type` is removed from the blocks the MCP reader returns, for both
read tools. It is **removed, not replaced**: substituting an asserted original type
would be the same mistake pointing the other way.

**[S] Verified payload bytes and client-derived text are unchanged** — `payload_b64`
still carries the verified bytes, and `payload_utf8` is still derived locally from
them with `payload_utf8_source: "client-derived"`.

**[C] Not changed:** the daemon's stored data, the daemon's HTTP block schema, and the
hash format. Only the MCP reader's presentation changed.

### 2.4 Compatibility impact

- **A caller reading `block["content_type"]` loses that field.** Remedy: fetch the
  type from the daemon directly and treat it as unverified. This is a smaller change
  than it sounds, since the value was never trustworthy.
- `block` now carries: `seq`, `prev_hash`, `curr_hash`, `payload_b64`, `payload_utf8`,
  `payload_utf8_source`, `created_at`. Exactly one field was removed.

---

## 3. Adjacent findings — same presentation issue elsewhere

**[C] Reported, not changed.** The line drawn: fields that can act as *processing
instructions* were removed; descriptive metadata is reported here. No general
response-schema redesign was undertaken.

1. **Per-block `created_at`.** Unverified server assertion presented beside verified
   content — the same class as `content_type`. Kept: it is descriptive, not an
   instruction, so a wrong value does not change how a caller processes bytes.
2. **`locker_manifest` returns `state`, `total_bytes`, `sealed_at`, `created_at`,
   `expires_at`.** All unverified. `total_bytes` in particular need not equal the
   bytes actually served; it is the host's own accounting.
3. **`head_hash` in the manifest result is the *server's* claim.** The head the client
   actually computed lives at `integrity.expected_head.observed`. On an unanchored
   read these two can differ with nothing in the `head_hash` field itself marking it
   as an assertion. **[C]** This is the closest remaining analogue of Finding B and the
   most plausible next candidate for the same treatment.
4. **Per-block `seq` is checked but not hash-bound.** It is required to equal the
   block's position, so it is constrained, but a host that renumbered blocks would
   not be detected by the hash. Presented as the block index.
5. **Response-level `total_blocks` is cross-checked** against the manifest's
   `block_count` and must stay constant across pages — consistency-checked, not
   hash-bound. `pad_id` is caller-supplied and echo-checked.
6. **Correctly verified, for contrast:** `payload_b64` and `prev_hash`/`curr_hash` are
   the material of the verification; `payload_utf8` is now client-derived; `from`,
   `to`, `count` and `integrity` are computed client-side.

---

## 4. Tests

**[S] Focused:** `tests/test_post_012_findings.py` — **12 tests**, all passing:

- broken chain without an expected head → `verification_failed` / `chain_inconsistent`
  and no payload;
- broken chain with an expected head → same;
- **both tools** consistent across four call shapes (reader and manifest, anchored and
  unanchored), each asserting `kind`, `cause`, forced `verdict: failed` and no
  `blocks`;
- error responses do not echo the attacker's payload — not as text, not base64, and
  with no `payload_b64` / `payload_utf8` keys;
- valid unanchored read → `internal_consistency_only`, payload intact;
- correctly anchored read → `trusted_head_match`;
- expected-head mismatch → fails closed;
- **complete rewrite** (payload altered *and* the whole chain rehashed) → internally
  consistent and readable unanchored, still rejected against the original head;
- `content_type` absent from every returned block;
- **substituting `content_type` changes nothing**: the same read with `text/plain` and
  with `text/html` serialises **byte-identically**, and neither `content_type` nor
  `text/html` appears in the output;
- substituted `payload_utf8` still rejected (`representation_mismatch`, no payload);
- only `content_type` was removed — the remaining block keys are asserted exactly.

**[S] Updated expectations:** one unit test in `tests/test_phase3_trusted_head.py`
renamed to `test_payload_alteration_without_rehashing_fails_closed` and re-asserted
against the new contract, with a comment recording that it previously asserted the
opposite; and the e2e tamper step in `scripts/test_handoff_e2e.py`.

**[S] Full suite: 142 passed.** **[S] MCP e2e:** passes, reporting
`[tamper] verification_failed (cause=chain_inconsistent) — no payload returned, tamper
detected`.

---

## 5. Remaining limitations

- **[C] The four states above are only as strong as the expected head.** An unanchored
  read cannot detect a complete rewrite; that was true of 0.1.2 and is unchanged.
- **[C] A broken chain is now a hard failure, so a partially corrupt pad is entirely
  unreadable through the MCP tools** — including its intact leading blocks. That is
  the intended trade, but it is a real loss of partial-access capability for a
  diagnostic use case. `scripts/inspect_pad.py` and direct HTTP access remain
  available for forensics.
- **[C] Adjacent findings 1–5 above are unresolved**, by scope. Finding 3
  (server-asserted `head_hash` presented without a marker) is the most plausible next
  change.
- **[U] No live probing was done**, per the authorization. Everything here is local.
- **[C] `content_type` is still returned by the daemon's HTTP API.** A caller using
  the HTTP API directly gets the same unverified field. This change is MCP-reader-only,
  as scoped.
- **[U]** The change is client-side only, so it protects callers using this client. A
  caller that talks to the daemon directly is unaffected either way.

---

## 6. Release-candidate readiness

**[C] Assessment: ready to be considered as a separate release-candidate decision, not
ready to publish.**

Supporting it: two reproduced findings, both closed; 12 focused tests including
adversarial cases the original suite lacked; the full suite and the MCP e2e green;
the response-contract change documented in `README.md` and the tool descriptions; no
hash-format change, no daemon change, no version bump, no artifact rebuild.

Before a release candidate is cut, the operator would need to decide:

1. whether the response-contract change ships as `0.1.3` (patch) given it can break a
   caller that indexed returned blocks on a failed chain — the intended direction, but
   a behaviour change a consumer should notice;
2. whether adjacent finding 3 (`head_hash`) is folded into the same change or issued
   separately;
3. whether a release note is published explaining the fail-closed change, since
   consumers of 0.1.2 have not been told.

**[C] Not done in this pass, by authorization:** no public GitHub push, no PyPI
publication, no tag, no live deployment, no version bump, no artifact rebuild, no
Phase 4 runtime work.
