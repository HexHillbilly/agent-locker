# Release notes

Point-in-time observations about deployed instances. These are dated snapshots,
not standing facts — re-observe before relying on them. Deployment state is
deliberately kept out of the installation instructions in `README.md` because it
goes stale faster than the code does.

## 0.1.2 — prepared, not yet published

Changes since `0.1.1`. **Built and verified as a candidate; not tagged, not
published to PyPI, not pushed to public GitHub, not deployed.** Retention and
ticket-lifecycle policy is deliberately **not** included; that work waits on
operator decisions and has no code in this release.

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
