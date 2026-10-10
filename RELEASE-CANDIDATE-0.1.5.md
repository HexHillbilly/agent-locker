# Release candidate — lockermcp 0.1.5

**Status: prepared locally. Not pushed, not tagged, not published, not deployed.**

This file is deliberately unshipped (the source distribution carries only `README.md` and
`RELEASE_NOTES.md`), so the release record can be extended without changing the artifacts.

## Source

| Item | Value |
|---|---|
| Build-source commit | `130da4163f99d6dfded35194fb9bc1bc8b4576f3` |
| Subject | remove a stray duplicate capture from repro/0.1.5 |
| Branch | `security/0.1.5-writer-verification` (off the reviewed baseline `d59efac`) |
| Exported | 65 files, 615,832 bytes (clean export of the committed tree) |
| Source manifest | `source-manifest-130da4163f99.json`, sha256 `166547f29c87b3ccc7d0a82772bd65be2cb2518f9abab7402d226936342faad2` |
| Provenance | `PROVENANCE-130da4163f99.json` |

## Artifacts

| File | Bytes | SHA-256 |
|---|---|---|
| `lockermcp-0.1.5-py3-none-any.whl` | 64,714 | `3662873e9fc8a2e25e1b9199cf2c38d5cf040cdfbed0ea6645b901a5d203a410` |
| `lockermcp-0.1.5.tar.gz` | 152,473 | `87f2b217872e07ab3cb06a953ab0ec2071a855baa5024f09f4191767c777b7e0` |

Supplementary: `MEMBER-DIGESTS-0.1.5.txt` (sha256
`2c534f5492910af12ff984fcfb771606b550157680885bc0757fb47dcf9ec5f5`) holds the per-member
content digests — 17 wheel members, 42 sdist members.

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
| Full test suite | **208 passed** (baseline at the reviewed commit: 184 passed + 1 nondeterministic failure) |
| MCP end-to-end | **PASSED** |
| Installed-artifact checks, fresh venv outside the checkout | **41/41 passed** — `INSTALLED-VERIFICATION-0.1.5.txt` |
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
