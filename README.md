# agent-locker

A lightweight, tamper-evident **append-only locker** for agent-to-agent task
handoff. One writer appends hash-chained blocks, seals the pad, and hands off a
read ticket; one reader verifies the chain end-to-end. Ships with a stdio MCP
server (`lockermcp`) so AI agents can drive it natively.

Python / FastAPI + aiosqlite (single-file SQLite, WAL mode). No Redis, no S3,
no external services.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

LOCKER_DB_PATH=locker.db LOCKER_MODE=local python -m lockerd   # the daemon (HTTP)
LOCKER_URL=http://127.0.0.1:8000 python -m lockermcp          # the MCP server (stdio)
```

See `.env.example` for every runtime variable.

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST   | `/v1/pads` | — | create a pad → `{pad_id, write_key, read_ticket}` |
| POST   | `/v1/pads/{id}/append` | `Bearer <write_key>` | append one block (≤64 KB) |
| POST   | `/v1/pads/{id}/seal` | `Bearer <write_key>` | freeze the pad, revoke writes |
| GET    | `/v1/pads/{id}/manifest` | none (free) | state, block count, bytes, sealed_at, head hash |
| GET    | `/v1/pads/{id}/blocks` | `?ticket=<read_ticket>` | bounded slice of blocks |

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

## Auth & tickets

- **write_key** — returned once at creation; only its sha256 hash is stored.
  `append`/`seal` verify `sha256(presented_key) == write_key_hash`.
- **read_once = a read lease.** The first successful `/blocks` read opens a
  window (default 10 minutes, `LOCKER_READ_LEASE_SECONDS`). Reads inside the
  window are unlimited; after it, the ticket returns 403. This lets a reader
  grab block 0 (the envelope) first and then the remaining blocks without
  burning the ticket.
- **read_unlimited** — supported in the schema, but v1 has no endpoint to mint
  extra tickets (future work). Tickets are scoped to their pad.
- `manifest` is free (public metadata) and does not touch the lease.

## Payments (x402)

Opt-in pay-per-pad using USDC on Base. Set `LOCKER_MODE=x402` (default `local`)
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

## MCP server (`lockermcp`)

Six tools over stdio (Python MCP SDK v2, `MCPServer`):

- `locker_deposit(envelope, artifacts, ttl_seconds=3600)` → `{pad_id, read_ticket, head_hash, status}` — atomic create + append envelope + append artifacts + seal in one call (recommended for one-shot handoffs; avoids multi-step batching hazards)
- `locker_create(ttl_seconds, max_blocks=32)` → `{pad_id, write_key, read_ticket}`
- `locker_append(pad_id, write_key, payload, content_type="application/json")` → `{pad_id, seq, curr_hash}`
- `locker_seal(pad_id, write_key)` → `{pad_id, state, sealed_at, head_hash}`
- `locker_manifest(pad_id, ticket=None)` → manifest (free on the daemon)
- `locker_read_blocks(pad_id, ticket, from_block=0, to_block=0)` → blocks slice

`locker_read_blocks` defaults to **block 0 (the envelope) first**, so a reader
naturally starts with the envelope before requesting the rest.

`locker_manifest` (when given a ticket) and `locker_read_blocks` verify the full
hash chain in Python and return an explicit integrity block — the model never
computes SHA-256 itself:

```json
{"integrity": {"chain_valid": true, "blocks_verified": 2}}
```

Register with Claude Code / Cursor / Open WebUI via `mcp_config.example.json`
(stdio `mcpServers` block).

## Operations

```bash
# Inspect a pad and verify its chain (stdlib only, no deps)
python scripts/inspect_pad.py <pad_id> --ticket <read_ticket> [--url http://127.0.0.1:8000]
```

Prints pad state, block count, total bytes, sealed status, head hash, and an
explicit SHA-256 chain verification.

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `LOCKER_MODE` | `local` | `local` (ticket bypass) or `x402` (payment) |
| `LOCKER_DB_PATH` | `locker.db` | SQLite file path |
| `LOCKER_HOST` | `127.0.0.1` | bind host (`python -m lockerd`) |
| `LOCKER_PORT` | `8000` | bind port (`python -m lockerd`) |
| `LOCKER_READ_LEASE_SECONDS` | `600` | read_once lease window |
| `LOCKER_URL` | `http://127.0.0.1:8000` | daemon URL for `lockermcp` |
| `PAYMENT_WALLET_ADDRESS` | (unset) | receiving EVM address (required in x402 mode) |
| `BASE_RPC_URL` | `https://mainnet.base.org` | Base JSON-RPC endpoint |
| `REQUIRED_USDC_UNITS` | `2000` | minimum payment (USDC units, 6 decimals) |
| `USDC_CONTRACT` | `0x8335…A02913` | Base native USDC token contract |

Hard limits (memory-safe): 64 KB per block, 256 KB per pad (byte quota), 32
blocks default (configurable at creation, capped at 4096), 64 KB payload per
`/blocks` slice, 256 blocks per slice. Request bodies are streamed with a hard
cap, so an oversized body is rejected before it is fully buffered.

## Docker

```bash
docker compose up -d   # builds + runs the daemon on :8000, SQLite at /data
```

- `Dockerfile`: `python:3.11-alpine`, plain `uvicorn` (no native extras to
  compile on musl), runs as a non-root `locker` user.
- SQLite lives at `/data/locker.db` on a named volume (`locker-data`) with WAL
  mode enabled; the `-wal`/`-shm` sidecars sit in the same volume.
- `deploy/Caddyfile`: reverse proxy in front of the daemon with a 128 KB
  `request_body` cap and sane connection timeouts.

## Testing

```bash
pytest -q                                    # 23 behavioral tests (API + quotas + lease + tamper)
.venv/bin/python scripts/test_handoff_e2e.py # two-agent handoff over MCP: planner/worker,
                                             # post-seal rejection, lease expiry, tamper
.venv/bin/python scripts/dogfood_llm.py      # live-LLM dogfood: a real model drives lockermcp as
                                             # planner + worker (Ollama; --model qwen2.5:14b recommended)
```

## Notes

- `LOCKER_MODE=x402` returns HTTP 402 with a clear error and one obvious extension
  point; no payment provider is wired yet.
- The DB schema carries a `tickets.lease_started_at` column; the DB file is
  gitignored/regenerable, so delete an old one rather than migrating.
