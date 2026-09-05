# agent-locker

A lightweight, tamper-evident **append-only locker** for agent-to-agent task
handoff. One writer appends hash-chained blocks, seals the pad, and hands off a
read ticket; one reader verifies the chain end-to-end.

Python / FastAPI + aiosqlite (single-file SQLite, WAL mode). No Redis, no S3,
no external services.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

LOCKER_DB=locker.db AUTH_MODE=local python -m lockerd
# or: uvicorn lockerd.main:create_app --factory
```

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST   | `/v1/pads` | — | create a pad → `{pad_id, write_key, read_ticket}` |
| POST   | `/v1/pads/{id}/append` | `Bearer <write_key>` | append one block (≤64 KB) |
| POST   | `/v1/pads/{id}/seal` | `Bearer <write_key>` | freeze the pad, revoke writes |
| GET    | `/v1/pads/{id}/manifest` | none (free) | state, block count, bytes, sealed_at, head hash |
| GET    | `/v1/pads/{id}/blocks` | `?ticket=<read_ticket>` | bounded slice of blocks |

Full walkthrough:

```bash
# 1. create a pad
curl -s -X POST localhost:8000/v1/pads \
  -H 'Content-Type: application/json' \
  -d '{"ttl_seconds": 3600, "max_blocks": 8}'
# -> {"pad_id":"…","write_key":"…","read_ticket":"…"}

# 2. block 0 MUST be a locker.handoff.v1 envelope
curl -s -X POST localhost:8000/v1/pads/$PAD/append \
  -H "Authorization: Bearer $WK" -H 'Content-Type: application/json' \
  -d '{"schema":"locker.handoff.v1","sender":"a","recipient":"b","task":"summarize"}'

# 3. append payloads (raw JSON or text, up to 64 KB each)
curl -s -X POST localhost:8000/v1/pads/$PAD/append \
  -H "Authorization: Bearer $WK" -H 'Content-Type: text/plain' \
  --data-binary 'hello world'

# 4. seal (revokes writes)
curl -s -X POST localhost:8000/v1/pads/$PAD/seal -H "Authorization: Bearer $WK"

# 5. read back — manifest is free, blocks need the ticket
curl -s localhost:8000/v1/pads/$PAD/manifest
curl -s "localhost:8000/v1/pads/$PAD/blocks?ticket=$RT&from=0&to=5"
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

## Auth

- **write_key** — returned once at creation; only its sha256 hash is stored.
  `append`/`seal` verify `sha256(presented_key) == write_key_hash`.
- **read_ticket** — v1 issues a `read_once` ticket (`max_reads = 1`): the first
  successful `/blocks` read consumes it; a second read returns 403. The schema
  also supports `read_unlimited`, but v1 has no endpoint to mint extra tickets
  (future work). Tickets are scoped to their pad.
- `manifest` is free (public metadata: counts, head hash, timestamps) and does
  not consume a read.

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `LOCKER_DB` | `locker.db` | SQLite file path |
| `AUTH_MODE` | `local` | `local` (ticket bypass) or `x402` (payment) |
| `LOCKER_HOST` | `127.0.0.1` | bind host (`python -m lockerd`) |
| `LOCKER_PORT` | `8000` | bind port (`python -m lockerd`) |

Hard limits (memory-safe): 64 KB per block, 256 KB per pad (byte quota), 32
blocks default (configurable at creation, capped at 4096), 64 KB payload per
`/blocks` slice, 256 blocks per slice. Request bodies are streamed with a hard
cap, so an oversized body is rejected before it is fully buffered.

## Testing

```bash
pytest -q          # 22 behavioral tests (spec'd API + quotas + expiry + tamper)
```

## Spec gaps resolved (v1 decisions)

The original spec left a few things undefined; these are the interpretations
chosen for v1:

- **`locker.handoff.v1` envelope** — not defined in the spec. Defined here as a
  JSON object carrying at least `schema`, plus optional `sender`, `recipient`,
  `task`, `nonce`, `created_at`. Block 0 is rejected unless it matches.
- **`Authorization: Bearer ***`** — the `***` is redaction; implemented as
  `Bearer <write_key>`.
- **`AUTH_MODE=x402`** — no payment provider/mechanism is specified. v1 returns
  HTTP 402 with a clear error and a single, obvious extension point; `local`
  mode is fully implemented.
- **read ticket type** — unspecified; v1 issues `read_once` (matches the
  schema's `max_reads = 1` default and single-handoff semantics).
- **"Free." on manifest** — interpreted as *no auth required*.
- **"max 64 KB per response"** — interpreted as ≤64 KB total payload per slice
  (base64 inflates serialized size), plus a 256-block cap.
- **ttl** gates writes (append/seal), not reads: sealed data stays readable
  after expiry, and expiry is enforced lazily on access (no background jobs).

Alternative: Go is also permitted by the spec; this implementation is Python
because it matches the surrounding toolchain. Say the word to port.
