# Bounded security release candidate — Phase 2 + Phase 3

**[C] Status: prepared, not released.** Nothing here is tagged, published to PyPI,
pushed to public GitHub, or deployed. Public publication and deployment are separate
approval steps that have not been taken.

Branch: `security/rc-0.1.2` (built on `main`; carries Phase 2 and Phase 3 only).

---

## 1. Everything that is still a decision

### RC-0 — the sample `docker-compose.yml` in the artifact exposes port 8000

**[S]** Raised by inspecting the built sdist rather than assuming the scope was
equivalent. The candidate does **not** include the Phase 1 containment change
(`security/p1-contain-demo`), so the `docker-compose.yml` it ships still publishes:

```yaml
ports:
  - "8000:8000"
```

Phase 1 hardened this to `127.0.0.1:8000:8000` with a comment explaining that the
wildcard bind makes every proxy-level control bypassable through the origin port.
`MANIFEST.in` deliberately carries `docker-compose.yml` into the sdist, so a
self-hoster who deploys from the release artifact gets the **un-hardened** sample —
inside a *security* release.

Options:

- **(a) Include the Phase 1 compose change in the candidate.** One line, deployment
  config only, no code path affected. Makes the shipped default the safe one.
- **(b) Ship as is, with the warning documented.** Keeps the candidate strictly two
  phases; leaves a known-unsafe default in the artifact.
- **(c) Defer the whole candidate until the containment configuration is released.**

**[C] Recommendation: (a).** It is a one-line binding change with no behavioural
risk to the library, and the alternative is shipping a security release whose own
sample deployment reintroduces the vulnerability the release exists downstream of.
**[C] Not done unilaterally** — the scope was specified as Phase 2 and Phase 3.

### RC-1 — the version number

**[S]** The candidate is at `0.1.2rc1` in `pyproject.toml`, both packages'
`__version__`, the MCP server identity, and the sdist example in `README.md`.

- **(a) `0.1.2`** — patch. Defensible: every change is a fix, and the only
  behavioural changes affect misconfigured or dishonest inputs.
- **(b) `0.2.0`** — minor. Argues that an unknown `LOCKER_MODE` now **stopping the
  daemon** is a behaviour change a deployment should notice.

**[C]** The `rc` marker is deliberate and self-protecting: PEP 440 pre-releases are
excluded from default resolution, so `pip install lockermcp` cannot pick this up by
accident even if it were published. Reversible in one line.

### RC-2 — what "released" means for the site

**[S]** `llms.txt` on the live site currently names `lockermcp 0.1.1`. If the
candidate becomes a release, the site wording must move with it — including the
post-TTL read behaviour that Phase 4 §2.2 flags as currently undocumented. **[C]**
That is a deployment step, not part of this candidate.

### RC-3 — the phase records are not in the sdist

**[S]** `SECURITY-PHASE2.md`, `SECURITY-PHASE3.md` and
`PHASE4-LIFECYCLE-POLICY.md` are not carried by `MANIFEST.in`, so they do not travel
in the artifact (matching how `0.1.1` was packaged). Their conclusions **are**
summarised in `RELEASE_NOTES.md`, which does travel. Options: add them to
`MANIFEST.in`, or leave the release notes as the carried summary. Low stakes.

---

## 2. Scope

**In the candidate** (branch `security/rc-0.1.2`, built from `main`):

| Path | Phase | What |
|------|-------|------|
| `lockermcp/server.py` | 2B, 2C, 3 | ticket transport, untrusted framing, `expected_head_hash`, verdict, locally-derived text, fail-closed retrieval |
| `lockerd/config.py`, `lockerd/__main__.py` | 2A | unknown `LOCKER_MODE` stops the daemon instead of silently falling back to `open` |
| `scripts/inspect_pad.py` | 2B | ticket moves to the `Authorization` header |
| `tests/test_phase2_security_fixes.py` | 2 | 41 tests |
| `tests/test_phase3_trusted_head.py` | 3 | 42 tests |
| `README.md` | 2, 3 | transport, strict mode, integrity guarantees and their precise limits |
| `RELEASE_NOTES.md` | rc | the `0.1.2rc1` entry |
| `SECURITY-PHASE2.md`, `SECURITY-PHASE3.md`, `PHASE4-LIFECYCLE-POLICY.md` | 2, 3, 4 | records (policy only for Phase 4) |

**Explicitly out of the candidate:**

- **Phase 1 containment configuration** — `deploy/Caddyfile`,
  `docker-compose.yml`, `deploy/CONTAINMENT.md`. Operator-executed infrastructure,
  already live. **[C]** See RC-0: one file of this is shipped in the sdist.
- **Phase 4** — no code exists. Policy decisions are still open; nothing was
  implemented and nothing was deleted.
- **Phase 5 payment binding** — not started.

**[C] No hash-format change:** `git diff main -- lockerd/hashchain.py` is empty.

---

## 3. Gates — all run, all green

**[S]**

| Gate | Result |
|------|--------|
| Full test suite on the candidate | **130 passed** (Phase 2: 41, Phase 3: 42, pre-existing: 47) |
| Two-agent handoff end to end over MCP | **PASSED** — seal, post-seal 409, lease expiry 403, tamper detected |
| Release build from the pinned commit | 41 files / 314,415 bytes exported; sdist + wheel built in an isolated env |
| Artifact smoke test from an installed wheel | **PASSED** (below) |

**[S] The smoke test ran the installed wheel, not the checkout** — scratch venv,
`cwd=/tmp`, both packages resolved from `site-packages`:

```
lockermcp    0.1.2rc1 /tmp/rc-smoke-venv/lib/python3.11/site-packages/lockermcp/__init__.py
lockerd      0.1.2rc1 /tmp/rc-smoke-venv/lib/python3.11/site-packages/lockerd/__init__.py
daemon       ok version 0.1.2rc1
handoff      sealed, read, trusted_head_match on the true head
wrong head   failed closed with cause expected_head_mismatch and no payloads
manifest     trusted_head_match
no reference verdict internal_consistency_only (not checked, not failed)
strict mode  rejected 'txdi': LOCKER_MODE='txdi' is not a recognized mode…
RC ARTIFACT SMOKE TEST PASSED
```

---

## 4. Artifacts

**[S]** Built by the repository's own `scripts/release_build.py` from an explicit
commit, into a directory outside the source tree
(`/home/lucky/padlockspace-rc/0.1.2rc1`):

| Artifact | Bytes | sha256 |
|----------|-------|--------|
| `lockermcp-0.1.2rc1-py3-none-any.whl` | 46,692 | `0a8850f998ee72a4cf20e355feeab213eea7e338e9440fce4b6d3ae5d459b3d5` |
| `lockermcp-0.1.2rc1.tar.gz` | 83,722 | `fa0de542deef1ecd3bb315de368e013f92d2749fc73147dad7e28a1b2ec6b74c` |
| `source-manifest-56ba1d55da59.json` | 6,876 | `d3693586f33f7e1ae5db24c24ebd5ebf57d45a71261dda11670e7ab47751ba77` |
| `PROVENANCE-56ba1d55da59.json` | 1,460 | — |

Source commit `56ba1d55da596dedc7e3108a73842707872f6fe5`. Build tools recorded in
provenance: uv 0.11.14, setuptools 84.0.0, build 1.6.1. **[C]** The script records
hashes for comparison and does **not** claim byte-for-byte reproducible builds, so
re-running it will produce different hashes; treat the commit, not the hash, as the
identity of the candidate.

Wheel contents: `lockerd/` (8 modules) + `lockermcp/` (3 modules) + dist-info with
`LICENSE`. No deployment configuration in the wheel.

---

## 5. To cut the release (operator-run, not executed)

**[C]** None of the following has been done. Each is a decision or an action outside
the local authorization of this work order.

```bash
# 0. resolve RC-0, RC-1 and RC-2 first.

# 1. merge the candidate onto main (fast-forward or merge, your call)
git checkout main && git merge --no-ff security/rc-0.1.2

# 2. rebuild from the merged commit — the candidate artifacts above are pinned to
#    the branch commit, so rebuild after any change and re-record the hashes
python scripts/release_build.py main --out ~/padlockspace-release/<final-version>

# 3. tag and push (this is the irreversible step)
git tag -a v<final-version> -m "lockermcp <final-version>"
git push origin main v<final-version>

# 4. publish — needs its own approval, and Trusted Publishing is still later
#    release-process work per the work order
```

**[C]** Do **not** tag or publish the `rc` commit directly; rebuild from the final
commit so the artifacts and the tag describe the same tree.

---

## 6. Not blocked on Phase 4

**[C]** Phase 2 and Phase 3 are a self-contained security release. Nothing in them
depends on retention policy, ticket lifecycle, rate limits or payment binding, and
none of those were touched. The Phase 4 decisions can be made at leisure without
holding these fixes back.
