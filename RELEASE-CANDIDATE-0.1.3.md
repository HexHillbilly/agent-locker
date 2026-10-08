# lockermcp 0.1.3 — security release candidate

Prepared under the operator's 0.1.3 decision. **Local branch only: not published, not
tagged, not pushed to public GitHub, not deployed.**

This record is a *documentation* commit made after the build. The artifacts were built
from the frozen source commit below and were not rebuilt afterwards.

## 1. Source

| | |
|---|---|
| Branch | `security/post-0.1.2-findings` |
| **Frozen source commit** | `cd7e4ad1d224e5cd42b2cdd44f36f435ac2d5395` |
| Parent / released baseline | `a98924c0bdb87e2e14d4cb049b36056e3be2545b` (the `v0.1.2` tag target) |
| Version | `0.1.3` |

Version sources updated consistently, all five of them: `pyproject.toml`,
`lockermcp/__init__.py`, `lockerd/__init__.py`, the `version=` passed to the MCP server
in `lockermcp/server.py`, and the README's sdist example.

## 2. Artifact identity

Built from the frozen commit by `scripts/release_build.py`, which exports the commit
with `git archive` into a temporary tree outside the working directory and builds there
in an isolated environment — so the build cannot pick up uncommitted state.

| Artifact | Size | SHA-256 |
|---|---|---|
| `lockermcp-0.1.3-py3-none-any.whl` | 50,539 bytes | `a4acfc7ced77b51473acabed5264bdf083efca24ed8d681e686ad7c31a1e5434` |
| `lockermcp-0.1.3.tar.gz` | 95,776 bytes | `96ba142d1aad61eac77833b7156d8f270d12d597c07dbdebe4be4a0de24aaf84` |

Provenance, recorded by the builder:

| Evidence | Value |
|---|---|
| Source manifest | `source-manifest-cd7e4ad1d224.json`, sha256 `5b25233f2b6157326134fc9d86ef3e11c26f325bbdfc784bbfe285ba33eefb52` |
| Provenance record | `PROVENANCE-cd7e4ad1d224.json` |
| Exported source | 43 files, 368,671 bytes, via `git archive` |
| Member-content digests | `MEMBER-DIGESTS-0.1.3.txt` (17 wheel members, 40 sdist members), sha256 `e2b9970497a2efa6b278fff37b02e0f41df9c48204e9c84734c213cdef025b9d` |

**[C]** Member-content digests are supplementary evidence. Artifact identity is the
artifact sha256 above, not any member digest, and not the commit — non-reproducibility
does not let commit identity substitute for artifact identity.

## 3. Contents

| ID | Change | Kind |
|---|---|---|
| Finding A | A detected chain-verification failure now returns an error and no payloads, whether or not `expected_head_hash` was supplied | client behaviour |
| Finding B | Server-supplied `content_type` is omitted from MCP read results rather than replaced | client behaviour |
| Clarification | `locker_manifest` results carry `head_provenance`, naming each head and its source | additive |

**[C] Unchanged:** the hash format, the daemon's code, the HTTP API and its schemas,
the database schema, all stored data (nothing migrated), the `head_hash` field, and
valid unanchored reads (still `internal_consistency_only`).

## 4. Verification evidence

**[S] Test suites, run on the frozen candidate before the commit:**

| Suite | Result |
|---|---|
| `tests/test_post_012_findings.py` (focused) | 17 passed |
| Full suite | 147 passed |
| `scripts/test_handoff_e2e.py` (MCP end-to-end) | PASSED |

**[S] Installed-wheel smoke test**, run against the wheel installed into a scratch
virtualenv outside the checkout, with a provenance guard that fails the run if any
module resolves under the checkout: **25/25 checks passed**, covering the six required
areas —

1. a broken unanchored chain returns `verification_failed` / `chain_inconsistent` with
   no `blocks` key, the error does not echo the tampered payload, the anchored read
   fails identically, the manifest tool fails closed too, and a valid unanchored read
   still succeeds as `internal_consistency_only`;
2. a correct trusted head still succeeds;
3. a fully rewritten *and* rehashed chain passes unanchored but is rejected against the
   original head;
4. a substituted `payload_utf8` under a matching head is refused with
   `representation_mismatch` and the substituted text appears nowhere in the response;
5. substituting `content_type` leaves the returned result byte-identical and
   `content_type` absent from every returned block;
6. the manifest provenance distinction holds in all three cases, including a manifest
   request with no read ticket.

**[S] Artifact checks:** wheel is 17 members with `Version: 0.1.3` in METADATA and both
packages present; the sdist has a single `lockermcp-0.1.3/` root, ships
`RELEASE_NOTES.md` carrying the 0.1.3 entry, declares `version = "0.1.3"`, and packages
`docker-compose.yml` binding `127.0.0.1:8000:8000`.

**[C] Two defects were found in the smoke script itself and fixed before it passed** —
an envelope missing the required `locker.handoff.v1` fields, and a chain built with
`bytes.fromhex(prev)` where the daemon's rule is `sha256(prev_hex_ascii + payload)`.
Both were the harness's error, not the product's; neither masks a real failure, since
the corrected run exercises the same paths.

## 5. Compatibility changes, exactly

**Finding A.** `error.kind = "verification_failed"`, `error.cause = "chain_inconsistent"`,
and **no `blocks` key** — for both read tools, anchored or not. A caller that read
`result["blocks"]` after a failed chain now finds no such key: `result.get("blocks", [])`
yields `[]`; unconditional indexing raises. Callers already inspecting
`integrity.verdict` are unaffected. No payload, payload representation, or
attacker-controlled excerpt appears in the error.

**Finding B.** `content_type` no longer appears on returned blocks. The block now
carries `seq`, `prev_hash`, `curr_hash`, `payload_b64`, `payload_utf8`,
`payload_utf8_source`, `created_at`. Verified bytes and client-derived text unchanged.

**Clarification.** `locker_manifest` gains a top-level `head_provenance` object with
`manifest_head` (marked `verified_by_client: false` unless a full chain was walked and
the client's own recomputation landed on it), `recomputed_head`, `expected_head`, and a
`note`. Additive; `head_hash` is untouched.

## 6. Bypass inspection for the head clarification

**[S] No verification bypass was found** — the defect is presentation ambiguity, so the
bounded clarification proceeded without scope expansion. The comparison operand is
`expected == observed`, and `observed` is built by iterative recomputation over the
payload bytes from `ZERO_HASH`. The manifest's `head_hash` appears in exactly one
executable position, `if chain_valid and prev != head_hash: chain_valid = False` — an
*input* to the internal-consistency test, never the target a caller's reference is
compared against.

## 7. Website

**[C] No website change is necessary to keep claims accurate, and none was made.**
Every version claim on the live site is about the **published** package, which is still
0.1.2: the live `llms.txt` states "the published package `lockermcp` 0.1.2" and
"New in 0.1.2 — trusted-head verification…", both still true. Publishing 0.1.3 will
require two edits, prepared but **not applied**:

- the published-version references (0.1.2 → 0.1.3), and
- the read-tool paragraph: add that a broken chain now fails closed with no payloads,
  and that `content_type` is no longer returned.

## 8. Not done, deliberately

No public GitHub push, no PyPI upload, no tag, no live deployment, no daemon change,
no hash-format change, no schema change, no migration, no Phase 4 runtime work. No
existing branch was rewritten and nothing was force-pushed.
