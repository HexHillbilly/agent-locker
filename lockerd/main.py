"""FastAPI app for the Agent Locker Daemon (v1)."""
from __future__ import annotations

import base64
import hmac
import json
import logging
import secrets
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import __version__ as VERSION
from . import config as cfg
from . import db, hashchain, payments
from .models import (
    AppendResponse,
    BlocksResponse,
    HealthResponse,
    ManifestResponse,
    PadCreateRequest,
    PadCreatedResponse,
    SealResponse,
)

logger = logging.getLogger("lockerd.main")

DEMO_PAD_ID = "demo-pad-v1"


def api_error(status_code: int, code: str, detail: str) -> HTTPException:
    """HTTPException carrying a structured ``{"error", "detail"}`` body."""
    return HTTPException(status_code=status_code,
                         detail={"error": code, "detail": detail})


ERROR_RESPONSES = {
    400: {"description": "Bad request (invalid envelope, empty payload, or malformed tx hash)"},
    401: {"description": "Unauthorized (missing or invalid write key / read ticket)"},
    402: {"description": "Payment required (txid challenge or failed verification)"},
    403: {"description": "Forbidden (read ticket lease expired)"},
    404: {"description": "Not found (pad does not exist)"},
    409: {"description": "Conflict (pad sealed, quota exceeded, or payment already redeemed)"},
    413: {"description": "Payload too large (block or slice limit exceeded)"},
    422: {"description": "Unprocessable (invalid request body or range)"},
    502: {"description": "Bad gateway (Base RPC provider unreachable)"},
}


def _err(*codes: int) -> dict:
    """Responses dict documenting the given HTTP status codes."""
    return {c: ERROR_RESPONSES[c] for c in codes}


async def seed_demo_pad(store: db.Store) -> None:
    """Provision the permanent read-only demo pad if it does not exist."""
    if await store.get_pad(DEMO_PAD_ID) is not None:
        return
    write_key = "demo-write-key"  # published test key (SHA-256 hashed on insert)
    ttl = 100 * 365 * 24 * 3600  # effectively permanent
    await store.create_pad(DEMO_PAD_ID, hashchain.sha256_hex(write_key.encode()),
                           ttl, cfg.DEFAULT_MAX_BLOCKS)
    envelope = {
        "schema": "locker.handoff.v1",
        "task_id": "demo-pad-v1",
        "from_agent": "lockerd-demo",
        "to_agent": "you",
        "constraints": ["read-only demo", "illustrates hash-chain integrity"],
        "artifacts": [{"name": "demo-payload.txt", "size": 45}],
        "budget_usd": 0.0,
    }
    blocks = [
        (json.dumps(envelope).encode(), "application/json"),
        (b"Permanent read-only demo handoff pad.\n", "text/plain"),
        (b"Read it freely: GET /v1/pads/demo-pad-v1/blocks\n", "text/plain"),
    ]
    prev = cfg.ZERO_HASH
    for i, (payload, ct) in enumerate(blocks):
        curr = hashchain.compute_hash(prev, payload)
        await store.append_block(DEMO_PAD_ID, i, prev, curr, ct, payload)
        prev = curr
    await store.seal_pad(DEMO_PAD_ID)
    logger.info("seeded demo pad %s (%d blocks)", DEMO_PAD_ID, len(blocks))


def create_app(config: cfg.Config | None = None) -> FastAPI:
    config = config or cfg.Config.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        conn = await db.connect(config.db_path)
        app.state.store = db.Store(conn, config.read_lease_seconds)
        await seed_demo_pad(app.state.store)
        yield
        await conn.close()

    app = FastAPI(title="Agent Locker Daemon", version=VERSION, lifespan=lifespan)

    @app.exception_handler(HTTPException)
    async def _http_exception_handler(request: Request, exc: HTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            return JSONResponse(status_code=exc.status_code, content=detail,
                                headers=getattr(exc, "headers", None))
        return JSONResponse(status_code=exc.status_code, content={"detail": detail},
                            headers=getattr(exc, "headers", None))

    bearer_scheme = HTTPBearer(auto_error=False)

    # ---- helpers ----
    def store(request: Request) -> db.Store:
        return request.app.state.store

    def extract_bearer(request: Request) -> str | None:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            return auth[len("Bearer "):].strip()
        return None

    async def read_body(request: Request, limit: int) -> bytes | None:
        """Stream the body with a hard cap; returns None if it exceeds ``limit``."""
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > limit:
                return None
        return body

    def verify_write_key(pad: dict, write_key: str) -> bool:
        return hmac.compare_digest(
            hashchain.sha256_hex(write_key.encode()), pad["write_key_hash"])

    def _try_utf8(b: bytes) -> str | None:
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return None

    # ---- endpoints ----

    @app.get("/health", response_model=HealthResponse)
    async def health(request: Request):
        s = store(request)
        writable, wal_mode, total, unsealed, sealed = await s.health_check()
        pads = {"total": total, "unsealed": unsealed, "sealed": sealed}
        if not writable:
            return JSONResponse(status_code=503, content={
                "status": "unavailable", "version": VERSION,
                "database": {"writable": False, "wal_mode": wal_mode},
                "rpc": {"network": "base", "reachable": None},
                "pads": pads,
            })
        rpc_ok = True
        if config.auth_mode == cfg.AUTH_TXID:
            rpc_ok = await payments.rpc_reachable(config.base_rpc_url)
        return {
            "status": "ok", "version": VERSION,
            "database": {"writable": writable, "wal_mode": wal_mode},
            "rpc": {"network": "base", "reachable": rpc_ok},
            "pads": pads,
        }

    @app.head("/health", include_in_schema=False)
    async def health_head(request: Request):
        return await health(request)

    @app.post("/v1/pads", status_code=201, response_model=PadCreatedResponse,
              responses=_err(400, 402, 409, 502))
    async def create_pad(request: Request, body: PadCreateRequest):
        tx_hash = None
        payer_address = None
        amount_units = None

        if config.auth_mode == cfg.AUTH_TXID:
            wallet = config.payment_wallet_address
            if not wallet:
                logger.warning("LOCKER_MODE=txid but PAYMENT_WALLET_ADDRESS is unset")
                raise HTTPException(500, "payment configuration error")
            tx_hash = request.headers.get("X-Payment-Proof", "").strip()
            if not tx_hash:
                challenge = payments.build_challenge(
                    wallet, config.usdc_contract, config.required_usdc_units)
                return JSONResponse(
                    status_code=402,
                    content=challenge,
                    headers={"WWW-Authenticate": payments.www_authenticate_header(
                        wallet, config.required_usdc_units)},
                )
            if not payments.validate_tx_hash(tx_hash):
                raise HTTPException(
                    400, "payment verification failed: invalid transaction format")
            s = store(request)
            async with s.lock:
                if await s.has_receipt(tx_hash):
                    raise HTTPException(409, "payment already redeemed")
            try:
                receipt = await payments.get_transaction_receipt(
                    config.base_rpc_url, tx_hash)
                payer_address, amount_units = payments.validate_receipt(
                    receipt, wallet, config.usdc_contract, config.required_usdc_units)
            except payments.RPCError:
                raise HTTPException(502, "rpc provider unreachable")
            except payments.PaymentVerificationError as e:
                raise HTTPException(402, f"payment verification failed: {e}")

        ttl = body.ttl_seconds
        max_blocks = body.max_blocks
        pad_id = uuid.uuid4().hex
        write_key = secrets.token_urlsafe(32)
        read_ticket = secrets.token_urlsafe(32)
        s = store(request)
        async with s.lock:
            if config.auth_mode == cfg.AUTH_TXID:
                ok = await s.create_pad_with_receipt(
                    pad_id, hashchain.sha256_hex(write_key.encode()), ttl, max_blocks,
                    tx_hash, amount_units, payer_address)
                if not ok:
                    raise HTTPException(409, "payment already redeemed")
            else:
                await s.create_pad(pad_id, hashchain.sha256_hex(write_key.encode()),
                                   ttl, max_blocks)
            await s.create_ticket(read_ticket, pad_id, "read_once", 1)
        return {"pad_id": pad_id, "write_key": write_key, "read_ticket": read_ticket}

    @app.post("/v1/pads/{pad_id}/append", status_code=201,
              response_model=AppendResponse,
              responses=_err(400, 401, 404, 409, 413),
              openapi_extra={
                  "requestBody": {
                      "required": True,
                      "content": {
                          "application/octet-stream": {
                              "schema": {"type": "string", "format": "binary",
                                         "description": "Raw block payload bytes (≤64 KB). Block 0 must be a locker.handoff.v1 envelope."},
                          },
                          "application/json": {
                              "schema": {"description": "JSON-encoded block payload (≤64 KB). Block 0 must be a locker.handoff.v1 envelope."},
                          },
                      },
                  },
              })
    async def append(pad_id: str, request: Request,
                     auth: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)):
        write_key = auth.credentials if auth else None
        payload = await read_body(request, cfg.MAX_BLOCK_BYTES)
        if payload is None:
            raise api_error(413, "payload_too_large",
                            f"payload exceeds {cfg.MAX_BLOCK_BYTES} bytes")
        content_type = request.headers.get("content-type", "application/json")
        s = store(request)
        async with s.lock:
            pad = await s.get_pad(pad_id)
            if pad is None:
                raise api_error(404, "not_found", "pad not found")
            if not write_key or not verify_write_key(pad, write_key):
                raise api_error(401, "unauthorized", "invalid write key")
            pad = await s.expire_pad_if_needed(pad)
            if pad["state"] != "open":
                sealed = pad["state"] == "sealed"
                raise api_error(409 if sealed else 410,
                                "conflict" if sealed else "gone",
                                f"pad is {pad['state']}")
            if len(payload) == 0:
                raise api_error(400, "bad_request", "empty payload")
            if len(payload) > cfg.MAX_BLOCK_BYTES:
                raise api_error(413, "payload_too_large",
                                f"payload exceeds {cfg.MAX_BLOCK_BYTES} bytes")
            seq = await s.block_count(pad_id)
            if seq >= pad["max_blocks"]:
                raise api_error(409, "conflict", "block quota exceeded")
            if pad["current_bytes"] + len(payload) > pad["max_bytes"]:
                raise api_error(409, "conflict", "byte quota exceeded")
            if seq == 0:
                env_err = hashchain.envelope_error(payload)
                if env_err:
                    raise api_error(400, "bad_request",
                                    f"block 0 invalid envelope: {env_err}")
            prev_hash = pad["head_hash"]
            curr_hash = hashchain.compute_hash(prev_hash, payload)
            await s.append_block(pad_id, seq, prev_hash, curr_hash,
                                 content_type, payload)
        return {"pad_id": pad_id, "seq": seq, "curr_hash": curr_hash}

    @app.post("/v1/pads/{pad_id}/seal", response_model=SealResponse,
              responses=_err(401, 404, 409))
    async def seal(pad_id: str, request: Request,
                   auth: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)):
        write_key = auth.credentials if auth else None
        s = store(request)
        async with s.lock:
            pad = await s.get_pad(pad_id)
            if pad is None:
                raise api_error(404, "not_found", "pad not found")
            if not write_key or not verify_write_key(pad, write_key):
                raise api_error(401, "unauthorized", "invalid write key")
            pad = await s.expire_pad_if_needed(pad)
            if pad["state"] != "open":
                sealed = pad["state"] == "sealed"
                raise api_error(409 if sealed else 410,
                                "conflict" if sealed else "gone",
                                f"pad is {pad['state']}")
            await s.seal_pad(pad_id)
            pad = await s.get_pad(pad_id)
        return {"pad_id": pad_id, "state": pad["state"],
                "sealed_at": pad["sealed_at"], "head_hash": pad["head_hash"]}

    @app.get("/v1/pads/{pad_id}/manifest", response_model=ManifestResponse,
             responses=_err(404))
    async def manifest(pad_id: str, request: Request):
        s = store(request)
        async with s.lock:
            pad = await s.get_pad(pad_id)
            if pad is None:
                raise api_error(404, "not_found", "pad not found")
            pad = await s.expire_pad_if_needed(pad)
            block_count = await s.block_count(pad_id)
        return {
            "pad_id": pad_id,
            "state": pad["state"],
            "block_count": block_count,
            "total_bytes": pad["current_bytes"],
            "sealed_at": pad["sealed_at"],
            "head_hash": pad["head_hash"],
            "created_at": pad["created_at"],
            "expires_at": pad["expires_at"],
        }

    @app.get("/v1/pads/{pad_id}/blocks", response_model=BlocksResponse,
             responses=_err(401, 403, 404, 413, 422))
    async def blocks(
        pad_id: str,
        request: Request,
        ticket: str | None = Query(None),
        frm: int = Query(0, alias="from"),
        to: int | None = Query(None),
    ):
        is_demo = pad_id == DEMO_PAD_ID
        s = store(request)
        async with s.lock:
            pad = await s.get_pad(pad_id)
            if pad is None:
                raise api_error(404, "not_found", "pad not found")

            if not is_demo:
                ticket = ticket or extract_bearer(request)
                if not ticket:
                    raise api_error(401, "unauthorized", "missing read ticket")
                status = await s.check_ticket(pad_id, ticket)
                if status == "invalid":
                    raise api_error(401, "unauthorized", "invalid read ticket")
                if status == "exhausted":
                    raise api_error(403, "forbidden", "read ticket lease expired")

            await s.expire_pad_if_needed(pad)

            total_blocks = await s.block_count(pad_id)
            empty = {"pad_id": pad_id, "from": frm, "to": frm, "count": 0,
                     "total_blocks": total_blocks, "blocks": []}
            if total_blocks == 0:
                return empty
            if frm < 0 or (to is not None and to < frm):
                raise api_error(422, "unprocessable", "invalid from/to range")
            if frm >= total_blocks:
                return empty
            if to is None:
                to = total_blocks - 1
            to = min(to, total_blocks - 1)
            if to - frm + 1 > cfg.MAX_BLOCKS_PER_RESPONSE:
                raise api_error(
                    413, "payload_too_large",
                    f"slice exceeds {cfg.MAX_BLOCKS_PER_RESPONSE} blocks; narrow from/to")

            rows = await s.get_blocks(pad_id, frm, to)
            payload_total = sum(len(r["payload"]) for r in rows)
            if payload_total > cfg.MAX_RESPONSE_BYTES:
                raise api_error(
                    413, "payload_too_large",
                    f"slice payload exceeds {cfg.MAX_RESPONSE_BYTES} bytes; narrow from/to")

            if not is_demo:
                await s.record_read(ticket)
            blocks_out = [
                {
                    "seq": r["seq"],
                    "prev_hash": r["prev_hash"],
                    "curr_hash": r["curr_hash"],
                    "content_type": r["content_type"],
                    "payload_b64": base64.b64encode(r["payload"]).decode(),
                    "payload_utf8": _try_utf8(r["payload"]),
                    "created_at": r["created_at"],
                }
                for r in rows
            ]
        return {"pad_id": pad_id, "from": frm, "to": to, "count": len(blocks_out),
                "total_blocks": total_blocks, "blocks": blocks_out}

    return app
