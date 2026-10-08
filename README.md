# agent-locker

A lightweight, tamper-evident **append-only locker** for agent-to-agent task
handoff. One writer appends hash-chained blocks, seals the pad, and hands off a
read ticket; one reader verifies the chain end-to-end. Ships with a stdio MCP
server (`lockermcp`) so AI agents can drive it natively.

Python / FastAPI + aiosqlite (single-file SQLite, WAL mode). No Redis, no S3,
no external services.

## Three ways to use this project

They differ in what you get, not in how the daemon behaves.

- **Installed package** — `pip install lockermcp`, or `uvx lockermcp` to run it
  without installing. Provides the two importable packages and the `lockerd` /
  `lockermcp` console scripts. No example scripts, no tests, no Docker or
  deployment files.
- **Source distribution** — the `.tar.gz` on the package index. Adds the test
  suite, the example scripts, `demo_handoff.py`, `mcp_config.example.json`, the
  Docker files and these release notes, so the workflows documented below all
  work from an unpacked sdist.
- **Repository checkout** — everything in the sdist, **plus** `deploy/`, which
  holds host deployment materials for the hosted service: the daemon
  reverse-proxy config, and a static-site Caddyfile with historical copies of
  the website files. Deployment materials are deliberately not published in the
  source distribution.

Repository: <https://github.com/HexHillbilly/agent-locker>

## Install

### A. Installed package

```bash
uvx lockermcp                      # MCP server (stdio)
uvx --from lockermcp lockerd       # daemon
```

The same two commands are available after a normal installation:

```bash
pip install lockermcp
lockerd            # daemon
lockermcp          # MCP server (stdio)
```

### B. From the source distribution

```bash
tar xzf lockermcp-0.1.1.tar.gz && cd lockermcp-0.1.1
python -m venv .venv && source .venv/bin/activate
pip install .
```

The unpacked tree also contains `tests/`, `scripts/`, `demo_handoff.py` and
`mcp_config.example.json`, so the example workflows below run from there
directly.

### C. From a repository checkout (development)

```bash
git clone https://github.com/HexHillbilly/agent-locker && cd agent-locker
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Run the daemon

```bash
LOCKER_DB_PATH=locker.db LOCKER_MODE=open lockerd     # binds 127.0.0.1:8000
```

See `.env.example` for every runtime variable.

## Configure an MCP client

`lockermcp` is a thin client: it talks to a running daemon and its only required
configuration is `LOCKER_URL`, the daemon's base URL.

```json
{
  "mcpServers": {
    "lockermcp": {
      "command": "uvx",
      "args": ["lockermcp"],
      "env": { "LOCKER_URL": "http://127.0.0.1:8000" }
    }
  }
}
```

`mcp_config.example.json` (in the source distribution and the checkout) is that
block verbatim. Register it with Claude Code / Cursor / Open WebUI via the stdio
`mcpServers` block. If the package is installed rather than fetched by `uvx`,
use the installed entry point directly:

```json
{ "command": "lockermcp", "args": [], "env": { "LOCKER_URL": "http://127.0.0.1:8000" } }
```

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST   | `/v1/pads` | — | create a pad → `{pad_id, write_key, read_ticket}` |
| POST   | `/v1/pads/{id}/append` | `Bearer <write_key>` | append one block (≤64 KB) |
| POST   | `/v1/pads/{id}/seal` | `Bearer <write_key>` | freeze the pad, revoke writes |
| POST   | `/v1/pads/{id}/tickets` | `Bearer <write_key>` | mint an extra read ticket (`read_once` / `read_unlimited`) |
| GET    | `/v1/pads/{id}/manifest` | none (free) | state, block count, bytes, sealed_at, head hash |
| GET    | `/v1/pads/{id}/blocks` | `Authorization: Bearer <read_ticket>` (or `?ticket=`) | bounded slice of blocks |
| GET    | `/health` | none | liveness: 200 ok / 503 if DB read-only |

`demo-pad-v1` is a permanent read-only pad seeded on startup; its blocks are
readable without a ticket (`GET /v1/pads/demo-pad-v1/blocks`). Its published
test write key is `demo-write-key` — writing to it returns `409 Conflict`.

## Handoff envelope (block 0)

Block 0 must be a strict `locker.handoff.v1` envelope — rejected unless every
field is present and correctly typed:

```json
{
  "schema": "locker.handoff.v1",
  "task_id": "str",
  "from_agent": "str",
  "to_agent": "str",
  "constraints": ["str"],
  "artifacts": [{"any": "dict"}],
  "budget_usd": 1.25          // float, or null
}
```

Optional field: `allowed_paths` — a list of glob/path patterns (list[str]) or
`null`. When present, a reviewer may flag any changed file outside the patterns
as a scope violation. Absent or `null` = unconstrained (backward compatible).

## Block 1 attestation (implementation envelope)

Block 1 is free-form JSON — the daemon does not schema-validate post-block-0
payloads — but the recommended attestation shape is:

```json
{
  "task_id": "str",
  "from_agent": "str",
  "to_agent": "str",
  "status": "completed | failed | failed_dirty",
  "canonical_ref": {"repo": "owner/name", "branch": "str", "commit_sha": "str"},
  "verification": {"test_command": "str", "exit_code": 0, "tests_passed": 1, "tests_failed": 0},
  "environment": {
    "runtime": "python 3.11.8",
    "dependency_manifest": "requirements.txt",
    "dependency_hash": "sha256:..."
  },
  "artifacts": [{"type": "git_commit", "ref": "..."}, {"type": "diff_summary", "files_changed": [], "loc_added": 0, "loc_deleted": 0}]
}
```

`environment.dependency_hash` pegs the attestation to an exact dependency
snapshot, so an independent re-run reproduces the same result instead of
whatever upstream packages install today.

## Hash chain & tamper-evidence

Each block computes:

```
curr_hash = sha256(prev_hash.encode() + payload_bytes).hexdigest()
```

Block 0's `prev_hash` is the genesis value `0x00…0` (64 zeros); the pad's
`head_hash` is the `curr_hash` of the latest block. A reader walks the chain
from genesis and must land exactly on `head_hash` — any payload mutation breaks
the chain. The `/blocks` response includes `prev_hash`, `curr_hash`, and the
base64 payload (`payload_utf8` when text-decodable), so verification is
self-contained.

## Integrity guarantees and their limits

What the chain establishes:

- **Internal consistency.** Each block's hash is bound to its predecessor, so a
  single mutated payload breaks verification. The tamper-evidence is checked
  programmatically by the client before blocks enter LLM context, which prevents
  context drift and transport manipulation.
- **Change detection against a trusted head.** A reader that holds a pad's
  `head_hash` **independently of the daemon** — the value returned when the pad was
  sealed — can detect any later rewrite of the pad, including one where the whole
  chain was recomputed so that it verifies against itself. Pass it as
  `expected_head_hash`; see *Trusted-head verification* below.

**What is verified, and what is merely asserted.** Four different things live in
the same response, and they are not equally trustworthy:

**1. Chain relationships the client recomputes.** For every block, `payload_b64`
is decoded and `curr_hash` is recomputed as `sha256(prev_hash ++ payload_bytes)`;
each block's `prev_hash` must equal its predecessor's `curr_hash` (genesis for the
first), and the final `curr_hash` must equal the head the walk was aimed at. So
the relationship between the payload bytes and the recorded hashes, the block
ordering, and the linkage across the whole chain **are checked**. `prev_hash` and
`curr_hash` are not unauthenticated metadata — they are the material the check is
made of.

**2. Checked for consistency, though not covered by the hash.** `seq` must be the
block's contiguous 0-based position. The response must be coherent: the `pad_id`
echo must match the pad requested, `total_blocks` must agree with the manifest's
`block_count` and not change between pages, each page must return exactly the
number of blocks asked for, and the total retrieved must equal the claimed count.
Any failure here **fails closed** — an error and no payloads — rather than being
reported as a verified read. It is not cryptographically bound, so it constrains a
lying host without proving anything on its own.

**3. Fields excluded from the hash — pure server assertions.** Per block:
`content_type`, `created_at`. In the manifest: `state`, `total_bytes`, `sealed_at`,
`created_at`, `expires_at`. Nothing verifies these and none is an input to
verification. Treat them as claims about the pad, not facts about it.

**4. Server assertions that *drive* verification — inputs, therefore not verified by
it.** `block_count` decides how many blocks are fetched; the manifest's `head_hash`
is the target the walk must land on. The host supplies both, so the host chooses
the question. A head from the manifest is **not** a reference: only a head the
caller obtained elsewhere is, and the client never substitutes the manifest's head
for `expected_head_hash`.

**What a trusted-head match precisely covers.** Given `expected_head_hash` = *H*
supplied by the caller, `trusted_head_match` states: a contiguous chain from
genesis was retrieved, each block's payload bytes hash into the linkage, and the
recomputed head equals *H*. That binds the retrieved content byte-for-byte to *H*.
Because omitting, adding, reordering or altering any block changes the recomputed
head, a match also rules out truncation and rewriting **relative to *H***. It does
**not** cover: the authenticity of *H* itself (if the channel that carried it is
compromised the check is worthless), writer identity, anything in group 3, the
truth or safety of the content, or anything about the host's other pads.

**Availability limits.** Blocks past a claimed `block_count` are never requested,
so **without** a supplied reference a host can withhold the tail and still verify:
an empty pad and a withheld pad are indistinguishable, and a consistent prefix
looks like a whole chain. With a reference, truncation is caught, because a prefix
does not hash to the full chain's head. The client can never prove a host holds
nothing more; it can prove that what it received is coherent and — given a
reference — that it is exactly the referenced chain. A read lease expiring
mid-session (403) can also leave a read uncompletable.

**Still not established by any of this:**

- It does **not authenticate the writer.** `from_agent` / `to_agent` are
  client-supplied strings; holding the write key proves possession of the write
  key, not identity.
- It does **not make the attestation true.** Block 1 is free-form and
  unvalidated: `verification.exit_code`, `tests_passed`, and
  `canonical_ref.commit_sha` are claims the writer makes about itself.
- It does **not defend against a malicious operator.** Whoever runs the daemon
  can rewrite both the chain and the head it serves; self-verification against a
  head obtained from the same server proves nothing new. Supplying an
  `expected_head_hash` from a *separate* trusted channel does narrow this — the
  rewrite is caught unless that channel is also compromised — but it is still not
  a substitute for decentralized consensus against a hostile host, and it does not
  establish writer identity.
- The text a caller reads is **derived locally from the verified payload bytes**
  (strict UTF-8, else `null`), never taken from the daemon's parallel
  `payload_utf8` claim. If the two disagree, the read fails closed — a host
  presenting different text from the bytes it served is not a host to trust.

## Auth & tickets

- **write_key** — returned once at creation; only its sha256 hash is stored.
  `append`/`seal` verify `sha256(presented_key) == write_key_hash`.
- **read_once = a read lease.** The first successful `/blocks` read opens a
  window (default 10 minutes, `LOCKER_READ_LEASE_SECONDS`). Reads inside the
  window are unlimited; after it, the ticket returns 403. This lets a reader
  grab block 0 (the envelope) first and then the remaining blocks without
  burning the ticket.
- **read_unlimited** — minted via `POST /v1/pads/{id}/tickets` with the write
  key (`{"type": "read_unlimited"}`); it carries no lease window, so a reviewer
  can re-read a sealed pad after the pad's TTL or after a `read_once` lease has
  lapsed. `{"type": "read_once"}` mints another leased ticket. Tickets are
  scoped to their pad.
- `manifest` is free (public metadata) and does not touch the lease.

## Payments (txid)

Opt-in pay-per-pad using USDC on Base. Set `LOCKER_MODE=txid` (default `open`)
to require proof of payment on `POST /v1/pads`.

- No `X-Payment-Proof` header → `HTTP 402` with a JSON challenge
  (`error`, `network`, `chain_id` 8453, `currency`, `token_contract`, `amount`,
  `amount_units`, `recipient`, `instructions`) plus a
  `WWW-Authenticate: X402 …` header.
- With `X-Payment-Proof: <tx_hash>` → the daemon verifies on-chain via
  `eth_getTransactionReceipt`: status `0x1`, a USDC `Transfer` event to
  `PAYMENT_WALLET_ADDRESS` for ≥ `REQUIRED_USDC_UNITS`, then records the tx in the
  append-only `payment_receipts` table (`tx_hash` is the primary key → replay-proof).
- `lockermcp` `locker_create` / `locker_deposit` accept an optional `payment_tx_hash`
  and surface the structured 402 challenge in their error object.

The rail is off by default. Its tests run against mocks; **production payment
enforcement has not been exercised against a live payment and is unverified.**

## MCP server (`lockermcp`)

Six tools over stdio (Python MCP SDK v2, `MCPServer`):

- `locker_deposit(envelope, artifacts, ttl_seconds=3600)` → `{pad_id, read_ticket, head_hash, status}` — atomic create + append envelope + append artifacts + seal in one call (recommended for one-shot handoffs; avoids multi-step batching hazards)
- `locker_create(ttl_seconds, max_blocks=32)` → `{pad_id, write_key, read_ticket}`
- `locker_append(pad_id, write_key, payload, content_type="application/json")` → `{pad_id, seq, curr_hash}`
- `locker_seal(pad_id, write_key)` → `{pad_id, state, sealed_at, head_hash}`
- `locker_manifest(pad_id, ticket=None, expected_head_hash=None)` → manifest (free on the daemon)
- `locker_read_blocks(pad_id, ticket, from_block=0, to_block=0, expected_head_hash=None)` → blocks slice

`locker_read_blocks` defaults to **block 0 (the envelope) first**, so a reader
naturally starts with the envelope before requesting the rest.

`locker_manifest` (when given a ticket) and `locker_read_blocks` verify the full
hash chain in Python and return an explicit integrity block — the model never
computes SHA-256 itself:

```json
{"integrity": {"chain_valid": true, "blocks_verified": 2,
               "payloads": "untrusted",
               "expected_head": {"supplied": false, "checked": false, "matches": null,
                                 "expected": null, "observed": "5f77fb57…", "detail": "…"},
               "verdict": "internal_consistency_only"}}
```

**Trusted-head verification.** `chain_valid` is *internal* consistency only, so a
host that rewrites a pad's history and recomputes every hash produces a chain that
still verifies. To detect that, pass `expected_head_hash` — a 64-character
lowercase hex sha256 digest obtained from the writer over a **separately trusted
channel**, commonly the `head_hash` returned by `locker_seal` or `locker_deposit` at
seal time. The client recomputes the head from the chain it fetched and compares:

```json
{"integrity": {"chain_valid": true, "blocks_verified": 3,
               "expected_head": {"supplied": true, "checked": true, "matches": true,
                                 "expected": "9c1f…", "observed": "9c1f…", "detail": "…"},
               "verdict": "trusted_head_match"}}
```

`verdict` states exactly what was established: `trusted_head_match`,
`internal_consistency_only` (no reference supplied — **a full rewrite would not be
detected**), `not_checked`, or `failed`. Supplying a malformed or mismatching head
**fails verification and returns no payloads** (`error.kind == "verification_failed"`),
and the daemon's own manifest head is never substituted for your reference. A match
binds the content to *the reference you already trusted* — it does not establish
writer identity, nor that the content is safe. See `SECURITY-PHASE3.md`.

`chain_valid` reports internal consistency only; see *Integrity guarantees and
their limits* above for what it does not prove.

## Example scripts (source distribution and checkout)

These are not part of the installed wheel. They live in the repository
(<https://github.com/HexHillbilly/agent-locker>) and in the source distribution.

```bash
# Inspect a pad and verify its chain (stdlib only, no deps)
python scripts/inspect_pad.py <pad_id> --ticket <read_ticket> [--url http://127.0.0.1:8000]

# Two-agent handoff demo against a running daemon (open mode)
python demo_handoff.py [http://127.0.0.1:8000]

# Two-agent handoff over MCP, with its own daemon: planner/worker, post-seal
# rejection, read-lease expiry, tamper detection
python scripts/test_handoff_e2e.py
```

`inspect_pad.py` prints pad state, block count, total bytes, sealed status, head
hash, and an explicit SHA-256 chain verification.

Maintainers additionally have `scripts/release_build.py` (the clean-export +
build command described under *Release artifacts*) and `scripts/dogfood_llm.py`
(a live-LLM harness that drives `lockermcp` end to end with a local model).

## Release artifacts

`scripts/release_build.py` produces release artifacts from an explicit commit:

```bash
python scripts/release_build.py <commit-ish> [--out /path/outside/repo]
```

It resolves the commit to its full object ID, exports that committed source into
a fresh directory (`git archive`, so dev environments, caches, databases and
stale packaging output are excluded by construction), records a manifest of the
exported files with sizes and SHA-256 hashes, builds sdist + wheel in an isolated
environment, and writes `PROVENANCE.json` with the source commit, the manifest
hash (the manifest does not list itself), the build-tool versions, and the
artifact hashes. All output lands outside the source tree. Artifact hashes are
recorded for comparison; builds are **not** claimed to be byte-for-byte
reproducible.

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `LOCKER_MODE` | `open` | `open` (no payment; aliases `local`/`dev`) or `txid` (Base USDC receipt check; alias `x402`). An explicitly supplied value that is none of these **stops the daemon** rather than defaulting |
| `LOCKER_DB_PATH` | `locker.db` | SQLite file path |
| `LOCKER_HOST` | `127.0.0.1` | bind host (`lockerd`) |
| `LOCKER_PORT` | `8000` | bind port (`lockerd`) |
| `LOCKER_READ_LEASE_SECONDS` | `600` | read_once lease window |
| `LOCKER_URL` | `http://127.0.0.1:8000` | daemon URL for `lockermcp` (**required** for the MCP server) |
| `LOCKER_TICKET_TRANSPORT` | `header` | how `lockermcp` presents a read ticket: `header` sends `Authorization: Bearer <ticket>`; `query` uses the legacy `?ticket=` URL form. Unknown values raise |
| `PAYMENT_WALLET_ADDRESS` | (unset) | receiving EVM address (required in txid mode) |
| `BASE_RPC_URL` | `https://mainnet.base.org` | Base JSON-RPC endpoint |
| `REQUIRED_USDC_UNITS` | `2000` | minimum payment (USDC units, 6 decimals) |
| `USDC_CONTRACT` | `0x8335…A02913` | Base native USDC token contract |

Hard limits (memory-safe): 64 KB per block, 256 KB per pad (byte quota), 32
blocks default (configurable at creation, capped at 4096), 64 KB payload per
`/blocks` slice, 256 blocks per slice. Request bodies are streamed with a hard
cap, so an oversized body is rejected before it is fully buffered.

## Docker

`Dockerfile` and `docker-compose.yml` ship in the source distribution and the
checkout (not in the wheel):

```bash
docker compose up -d   # builds + runs the daemon on :8000, SQLite at /data
```

- `Dockerfile`: `python:3.11-alpine`, plain `uvicorn` (no native extras to
  compile on musl), runs as a non-root `locker` user.
- SQLite lives at `/data/locker.db` on a named volume (`locker-data`) with WAL
  mode enabled; the `-wal`/`-shm` sidecars sit in the same volume.

Host deployment materials under `deploy/` are **repository-only** and are not
published in the source distribution. They break down as:

- `deploy/Caddyfile` — reverse-proxy configuration for the daemon.
- `deploy/padlockspace/Caddyfile` — the static-site configuration for the
  `padlockspace.org` file server.
- `deploy/padlockspace/www/` — **historical copies** of the website files
  (`index.html`, `llms.txt`, `robots.txt`, `.well-known/mcp.json`) as they stood
  when this directory was written. The live website is maintained in a
  **separate, private repository**; these copies are kept for reference and are
  **not** what is served. Do not treat them as the current site.

## Testing

```bash
pytest -q                                    # full suite: API + quotas + lease + tamper + payments + hardening
.venv/bin/python scripts/test_handoff_e2e.py # two-agent handoff over MCP: planner/worker,
                                             # post-seal rejection, lease expiry, tamper
.venv/bin/python scripts/dogfood_llm.py      # live-LLM dogfood: a real model drives lockermcp as
                                             # planner + worker (Ollama; --model qwen2.5:14b recommended)
```

The live-LLM harness needs a local model and is not part of the release
verification.

## License

agent-locker is dual-licensed. The source is available under the **GNU Affero
General Public License, version 3 or (at your option) any later version**
(AGPL-3.0-or-later) — see [`LICENSE`](https://github.com/HexHillbilly/agent-locker/blob/main/LICENSE)
— matching the license declared in `pyproject.toml`. For proprietary or hosted
use where AGPL obligations do not fit, a separate commercial license is
available from the project owner. **Commercial licenses are available on
request.**

## Notes

- `LOCKER_MODE=txid` verifies a Base USDC transfer via `eth_getTransactionReceipt`
  and returns HTTP 402 with a challenge when no proof is presented.
- The DB schema carries a `tickets.lease_started_at` column; the DB file is
  gitignored/regenerable, so delete an old one rather than migrating.
- Deployment observations (which revision a given host is serving) are recorded
  in [RELEASE_NOTES.md](https://github.com/HexHillbilly/agent-locker/blob/main/RELEASE_NOTES.md),
  not here, because they go stale.
