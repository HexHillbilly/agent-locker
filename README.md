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

LOCKER_DB=locker.db AUTH_MODE=local python -m lockerd        # the daemon (HTTP)
LOCKER_URL=http://127.0.0.1:8000 python -m lockermcp         # the MCP server (stdio)
```

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

## MCP server (`lockermcp`)

Five tools over stdio (Python MCP SDK v2, `MCPServer`):

- `locker_create(ttl_seconds, max_blocks=32)` → `{pad_id, write_key, read_ticket}`
- `locker_append(pad_id, write_key, payload, content_type="application/json")` → `{pad_id, seq, curr_hash}`
- `locker_seal(pad_id, write_key)` → `{pad_id, state, sealed_at, head_hash}`
- `locker_manifest(pad_id, ticket=None)` → manifest (free on the daemon)
- `locker_read_blocks(pad_id, ticket, from_block=0, to_block=0)` → blocks slice

`locker_read_blocks` defaults to **block 0 (the envelope) first**, so a reader
naturally starts with the envelope before requesting the rest.

Two-agent smoke test (starts its own daemon):

```bash
.venv/bin/python scripts/mcp_smoke.py
```

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `LOCKER_DB` | `locker.db` | SQLite file path |
| `AUTH_MODE` | `local` | `local` (ticket bypass) or `x402` (payment) |
| `LOCKER_HOST` | `127.0.0.1` | bind host (`python -m lockerd`) |
| `LOCKER_PORT` | `8000` | bind port (`python -m lockerd`) |
| `LOCKER_READ_LEASE_SECONDS` | `600` | read_once lease window |
| `LOCKER_URL` | `http://127.0.0.1:8000` | daemon URL for `lockermcp` |

Hard limits (memory-safe): 64 KB per block, 256 KB per pad (byte quota), 32
blocks default (configurable at creation, capped at 4096), 64 KB payload per
`/blocks` slice, 256 blocks per slice. Request bodies are streamed with a hard
cap, so an oversized body is rejected before it is fully buffered.

## Testing

```bash
pytest -q                          # 23 behavioral tests (API + quotas + lease + tamper)
.venv/bin/python scripts/mcp_smoke.py   # two-agent MCP handoff, end-to-end
```

## Notes

- `AUTH_MODE=x402` returns HTTP 402 with a clear error and one obvious extension
  point; no payment provider is wired yet.
- The DB schema gained a `tickets.lease_started_at` column; the DB file is
  gitignored/regenerable, so delete an old one rather than migrating.
