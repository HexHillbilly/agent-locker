# Release candidate — lockermcp 0.1.5

**Status: prepared locally. Not pushed, not tagged, not published, not deployed.**

This file is deliberately unshipped (the source distribution carries only `README.md` and
`RELEASE_NOTES.md`), so the release record can be extended without changing the artifacts.

## Source

| Item | Value |
|---|---|
| Build-source commit | `ec23d4e4f8dbddf930c8de932f5e3303aaa4916f` |
| Tag target | the build-source commit above — this is the ONLY commit `v0.1.5` may identify |
| Later evidence-only commits | documentation only; they must be described separately from the build source and must not be what the tag points at |
| Subject | logging boundary stated precisely, and the release/deployment plan recorded |
| Branch | `release/0.1.5-public`, based on the public baseline `d59efac`, no capability material in its history |
| Exported | 73 files, 728,399 bytes (clean export of the committed tree) |
| Source manifest | `source-manifest-ec23d4e4f8db.json`, sha256 `9e0c3969b0e1749c9d2fc367914d1d0dd912219ab09f73dbc8a44cc4389eec85` (73 files, 737,511 B) |
| Provenance | `PROVENANCE-ec23d4e4f8db.json` |

## Artifacts

| File | Bytes | SHA-256 |
|---|---|---|
| `lockermcp-0.1.5-py3-none-any.whl` | 65,435 | `1ca08fe9910ab27250dd978507846d0e3b73a98bf50074826963bd1ba2720539` |
| `lockermcp-0.1.5.tar.gz` | 156,323 | `273af07211170b324dc3daf16b796de86e9dba2645c7503b83f328739efc6ef7` |

Supplementary: `MEMBER-DIGESTS-0.1.5.txt` (sha256
`31b1dc172de1816cea581cd9b4720364e409aea20d2171cd6b3f57959c9b0996`) holds the per-member
content digests — 17 wheel members, 46 sdist members.

**[S] Superseded.** An earlier candidate, built from `130da41` before the create-failure
classification fix and before this publication branch existed, is preserved at
`/home/lucky/padlockspace-rc/superseded/release-0.1.5-candidate-built-from-130da41/` with a
`SUPERSEDED.txt` marker. **Do not publish it.**

## Included files, verified

- **Wheel:** `lockerd/` (8 modules), `lockermcp/` (3 modules), and the `dist-info` metadata.
  Nothing else.
- **Sdist:** the same sources plus `tests/` (10 files), `scripts/` (5 files),
  `pyproject.toml`, `LICENSE`, `MANIFEST.in`, `README.md`, `RELEASE_NOTES.md` and the
  Docker/example files. `deploy/` (host deployment material) and `repro/` (this phase's
  reproduction evidence) are **not** shipped, matching the 0.1.4 sdist.
- **Versions:** `version = "0.1.5"` in `pyproject.toml` and `__version__ = "0.1.5"` in both
  `lockermcp/__init__.py` and `lockerd/__init__.py`; the wheel metadata reports `0.1.5` and
  the MCP server advertises `0.1.5`.

## Verification evidence

| Check | Result |
|---|---|
| Full test suite | **216 passed** (baseline at the reviewed commit: 184 passed + 1 nondeterministic failure) |
| MCP end-to-end | **PASSED** |
| Installed-artifact checks, fresh venv outside the checkout | **78/78 passed** — `INSTALLED-VERIFICATION-0.1.5.txt`, including the corrected 4xx classification on the installed wheel |
| Reproduction evidence | `repro/0.1.5/` — five scripts and their captured outputs, capability-redacted |

The installed-artifact run exercises the wheel, not the checkout: provenance, version,
the honest deposit path, anchored reads, fail-closed behaviour, manifest head provenance,
`content_type` absence, client-derived text, and the recovery contract for a rewritten seal
head, a rewritten append acknowledgment and a lost create response — including that returned
capabilities work against the daemon and that no failure claims a rollback or a safe retry.

## Compatibility implications

**Additive only; no migration.**

- A **successful** deposit keeps every key it had (`pad_id`, `read_ticket`, `head_hash`,
  `status`) and gains `head_source` and `server_head_hash`. Against an honest daemon the
  values agree, so existing callers see the same result values.
- A **failed** deposit keeps the `error` object it always had — the `{status, detail}` shape
  for daemon and transport failures, `{status, kind, cause, detail}` for verification
  failures — and gains `partial` and, on verification failures, a richer `integrity` block.
  No key is removed, so callers that branch on `error` are unaffected.
- **No daemon API change**, no stored-data change, no schema change, no hash-format change,
  no package rename, no dependency change, no licensing change.
- `locker_create`, `locker_append`, `locker_seal` and the read tools are unchanged apart
  from `locker_append`/`locker_seal` descriptions, which now state that their results are the
  daemon's assertion.
- One shipped script changed behaviour: `scripts/inspect_pad.py` now accepts
  `--ticket --like-this` as well as `--ticket=--like-this`. Previously it failed at argument
  parsing for roughly one ticket in sixty-four.

## Remaining limitations

- A matched acknowledgment establishes that the daemon's account agrees with the bytes
  submitted. It does **not** establish durable storage, availability, writer identity, the
  truth of the payload, or task completion.
- `locker_append` and `locker_seal` still cannot verify their own acknowledgments; without
  the pad's prior head there is no chain to recompute. An optional `expected_prev_hash` would
  make each checkable and is **not** part of this change.
- A create whose response was lost leaves a pad nobody can reach through this API. The result
  reports it as `unknown` with recovery unavailable rather than concealing it, and no
  operator cleanup path exists (decision 5).
- Multi-process operation remains unsupported and unmeasured.
- Measured operational hazard: `aiosqlite` logs bound SQL parameters at `DEBUG`, so a live
  daemon at `DEBUG` writes read tickets into its log. Keep it at `INFO` or quiet the
  `aiosqlite` logger; the exposure and the mitigation are both pinned by a test.
- Everything was exercised against local daemons and a local shim on temporary data. No live
  payment, no remote host, no production endpoint.

## Build lineage — what supersedes what

| # | Build source | State |
|---|---|---|
| 1 | `130da4163f99d6dfded35194fb9bc1bc8b4576f3` | **superseded, preserved** at `superseded/release-0.1.5-candidate-built-from-130da41/` with a `SUPERSEDED.txt`. Its hashes must not be uploaded. |
| 2 | `8441a739279f0285eca02ed6e441a4feedcfc72b` | **superseded and overwritten — a process failure I am reporting.** The next build wrote into the directory that already held it, so its two artifacts are gone. Its source commit and its recorded hashes survive in git history, and it was never published, but a rebuild of that commit is **not** guaranteed to reproduce those bytes, so those recorded hashes must not be used for an upload. |
| 3 | `ec23d4e4f8dbddf930c8de932f5e3303aaa4916f` | **the candidate of record.** These are the only artifacts proposed for upload, and the only commit `v0.1.5` may identify. |

The rule this establishes: **build each candidate into a directory named for its source commit,
and never rebuild into a directory that already holds a candidate.** Superseding means moving
the old directory aside under a marker, not writing over it.

Nothing in this lineage has been published, tagged, pushed or deployed.

## Proposed release and deployment plan

**Status: a proposal. Nothing below has been executed, and publication and deployment remain
unapproved.** The three actions are deliberately separable: any one can be approved, deferred
or refused without the others.

### Action A — publish to PyPI (separate approval)

| Item | Value |
|---|---|
| Exact artifacts | the two files named above, uploaded as built, with no rebuild |
| Upload | an explicitly provisioned credential, entered interactively by the operator; never searched for, never in argv, env or a file |
| Verification | index-recorded digests and sizes compared against the table above, both files downloaded and re-hashed, then `pip install` of the index version into a fresh environment outside the checkout with the installed-artifact checks re-run |

### Action B — git refs (separate approval)

| Item | Value |
|---|---|
| Destinations | private Gitea `Lagoon/agent-locker`, public GitHub `HexHillbilly/agent-locker` |
| Branch | `release/0.1.5-public`, based on the public baseline `d59efac`, a clean history containing no capability material |
| `main` | fast-forward to the build-source commit on both remotes, after re-checking ancestry and that no divergent commits exist |
| Tag | one annotated `v0.1.5` targeting that same commit, message self-contained with both artifact hashes inline; report the tag object and its dereferenced commit separately; existing tags `v0.1.0`–`v0.1.4` must not move |
| Private branch | `security/0.1.5-writer-verification` is preserved as private review evidence and is **not** pushed to the public remote |

### Action C — hosted service (NOT proposed for this release)

**[C] No change is proposed to the hosted service.** This release is client-focused: the
recovery contract and the writer-side verification live in `lockermcp`, and the daemon-side
changes are the description text and the `inspect_pad.py` argument handling, neither of which
the hosted instance exposes.

- **Observed state only.** The hosted API answers `GET /health` and reports `0.1.0`; exactly
  three paths are public at the edge and only `GET`/`HEAD`; everything else returns `403`. That
  is an observation of responses, not of running code.
- **[U] The running build identity is NOT established here.** A version string inside stored
  demo content is not proof of the running build, and this branch did not inspect the daemon's
  process, image or filesystem. The deployment records say one thing, the responses say
  another, and neither is running-code identity. Any future deployment assessment must resolve
  those three separately.
- **If a hosted upgrade is ever proposed**, it would need its own approval and its own plan:
  target host, the currently observed state re-checked, the installation method, the effective
  logging and ticket-transport settings from §5a, a fresh backup with its path and digest
  recorded before anything changes, smoke checks, and a rollback path — none of which is
  specified here.

### Action D — website (separate approval)

**[C] No website edit is proposed.** The site currently describes `lockermcp` 0.1.4. A 0.1.5
wording update would be a separate change with its own bundle, rehearsal and approval, exactly
as the 0.1.4 correction was. It is listed here only so it is not conflated with publishing.

## Not done here, and what approval would entail

**[U] Untouched by this preparation:** no remote push, no tag, no publication, no
deployment, no live payment, no credential change, no schema change, no production data.
Tags `v0.1.0`–`v0.1.4` are unmoved, `main` is still at `d59efac`, and the 0.1.4 artifacts
and live site are unchanged.

Approving these artifacts and a deployment plan would be the next step, in the shape the
0.1.3/0.1.4 releases used: fast-forward both remotes' `main` to the build-source commit,
publish the two artifacts with an explicitly provisioned (never searched-for) credential,
annotated-tag that same commit on both remotes with the hashes inline, verify the index
digests and an index install outside the checkout, and prepare — separately — any website
wording. This release does not touch the hosted daemon, which stays the contained read-only
0.1.0 demo.
