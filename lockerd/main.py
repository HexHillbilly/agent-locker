"""FastAPI app for the Agent Locker Daemon (v1)."""
from __future__ import annotations

import base64
import hmac
import json
import secrets
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from . import config as cfg
from . import db, hashchain


def create_app(config: cfg.Config | None = None) -> FastAPI:
    config = config or cfg.Config.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        conn = await db.connect(config.db_path)
        app.state.store = db.Store(conn)
        yield
        await conn.close()

    app = FastAPI(title="Agent Locker Daemon", version="1.0.0", lifespan=lifespan)

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

    async def x402(request: Request) -> JSONResponse:
        # Drain the body so the request completes cleanly before rejecting.
        async for _ in request.stream():
            pass
        return JSONResponse(
            status_code=402,
            content={
                "error": "payment_required",
                "detail": "AUTH_MODE=x402 requires payment validation; no provider is wired in v1",
            },
        )

    def verify_write_key(pad: dict, write_key: str) -> bool:
        return hmac.compare_digest(hashchain.sha256_hex(write_key.encode()), pad["write_key_hash"])

    def _try_utf8(b: bytes) -> str | None:
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return None

    # ---- endpoints ----

    @app.post("/v1/pads", status_code=201)
    async def create_pad(request: Request):
        if config.auth_mode == cfg.AUTH_X402:
            return await x402(request)
        raw = await read_body(request, 4096)
        if raw is None:
            raise HTTPException(413, "request body too large")
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(422, "body must be JSON")
        if not isinstance(body, dict):
            raise HTTPException(422, "body must be a JSON object")

        ttl = body.get("ttl_seconds")
        max_blocks = body.get("max_blocks", cfg.DEFAULT_MAX_BLOCKS)
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0 or ttl > cfg.MAX_TTL_SECONDS:
            raise HTTPException(422, f"ttl_seconds must be an integer in (0, {cfg.MAX_TTL_SECONDS}]")
        if (isinstance(max_blocks, bool) or not isinstance(max_blocks, int)
                or max_blocks <= 0 or max_blocks > cfg.MAX_MAX_BLOCKS):
            raise HTTPException(422, f"max_blocks must be an integer in (0, {cfg.MAX_MAX_BLOCKS}]")

        pad_id = uuid.uuid4().hex
        write_key = secrets.token_urlsafe(32)
        read_ticket = secrets.token_urlsafe(32)
        s = store(request)
        async with s.lock:
            await s.create_pad(pad_id, hashchain.sha256_hex(write_key.encode()), ttl, max_blocks)
            await s.create_ticket(read_ticket, pad_id, "read_once", 1)
        return {"pad_id": pad_id, "write_key": write_key, "read_ticket": read_ticket}

    @app.post("/v1/pads/{pad_id}/append", status_code=201)
    async def append(pad_id: str, request: Request):
        if config.auth_mode == cfg.AUTH_X402:
            return await x402(request)
        write_key = extract_bearer(request)
        if not write_key:
            raise HTTPException(401, "missing Authorization: Bearer <write_key>")

        payload = await read_body(request, cfg.MAX_BLOCK_BYTES)
        if payload is None:
            raise HTTPException(413, f"payload exceeds {cfg.MAX_BLOCK_BYTES} bytes")
        if len(payload) == 0:
            raise HTTPException(400, "empty payload")
        content_type = request.headers.get("content-type", "application/json")

        s = store(request)
        async with s.lock:
            pad = await s.get_pad(pad_id)
            if pad is None:
                raise HTTPException(404, "pad not found")
            if not verify_write_key(pad, write_key):
                raise HTTPException(401, "invalid write key")
            pad = await s.expire_pad_if_needed(pad)
            if pad["state"] != "open":
                raise HTTPException(409 if pad["state"] == "sealed" else 410,
                                    f"pad is {pad['state']}")
            seq = await s.block_count(pad_id)
            if seq >= pad["max_blocks"]:
                raise HTTPException(409, "block quota exceeded")
            if pad["current_bytes"] + len(payload) > pad["max_bytes"]:
                raise HTTPException(409, "byte quota exceeded")
            if seq == 0 and not hashchain.is_envelope(payload):
                raise HTTPException(400, f"block 0 must be a {hashchain.ENVELOPE_SCHEMA} envelope")

            prev_hash = pad["head_hash"]
            curr_hash = hashchain.compute_hash(prev_hash, payload)
            await s.append_block(pad_id, seq, prev_hash, curr_hash, content_type, payload)
        return {"pad_id": pad_id, "seq": seq, "curr_hash": curr_hash}

    @app.post("/v1/pads/{pad_id}/seal")
    async def seal(pad_id: str, request: Request):
        if config.auth_mode == cfg.AUTH_X402:
            return await x402(request)
        write_key = extract_bearer(request)
        if not write_key:
            raise HTTPException(401, "missing Authorization: Bearer <write_key>")

        s = store(request)
        async with s.lock:
            pad = await s.get_pad(pad_id)
            if pad is None:
                raise HTTPException(404, "pad not found")
            if not verify_write_key(pad, write_key):
                raise HTTPException(401, "invalid write key")
            pad = await s.expire_pad_if_needed(pad)
            if pad["state"] != "open":
                raise HTTPException(409 if pad["state"] == "sealed" else 410,
                                    f"pad is {pad['state']}")
            await s.seal_pad(pad_id)
            pad = await s.get_pad(pad_id)
        return {"pad_id": pad_id, "state": pad["state"], "sealed_at": pad["sealed_at"],
                "head_hash": pad["head_hash"]}

    @app.get("/v1/pads/{pad_id}/manifest")
    async def manifest(pad_id: str, request: Request):
        s = store(request)
        async with s.lock:
            pad = await s.get_pad(pad_id)
            if pad is None:
                raise HTTPException(404, "pad not found")
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

    @app.get("/v1/pads/{pad_id}/blocks")
    async def blocks(
        pad_id: str,
        request: Request,
        ticket: str | None = Query(None),
        frm: int = Query(0, alias="from"),
        to: int | None = Query(None),
    ):
        ticket = ticket or extract_bearer(request)
        if not ticket:
            raise HTTPException(401, "missing read ticket")

        s = store(request)
        async with s.lock:
            status = await s.check_ticket(pad_id, ticket)
            if status == "invalid":
                raise HTTPException(401, "invalid read ticket")
            if status == "exhausted":
                raise HTTPException(403, "read ticket exhausted")

            pad = await s.get_pad(pad_id)
            if pad is None:
                raise HTTPException(404, "pad not found")
            await s.expire_pad_if_needed(pad)

            total_blocks = await s.block_count(pad_id)
            empty = {"pad_id": pad_id, "from": frm, "to": frm, "count": 0,
                     "total_blocks": total_blocks, "blocks": []}
            if total_blocks == 0:
                return empty
            if frm < 0 or (to is not None and to < frm):
                raise HTTPException(422, "invalid from/to range")
            if frm >= total_blocks:
                return empty
            if to is None:
                to = total_blocks - 1
            to = min(to, total_blocks - 1)
            if to - frm + 1 > cfg.MAX_BLOCKS_PER_RESPONSE:
                raise HTTPException(413,
                                    f"slice exceeds {cfg.MAX_BLOCKS_PER_RESPONSE} blocks; narrow from/to")

            rows = await s.get_blocks(pad_id, frm, to)
            payload_total = sum(len(r["payload"]) for r in rows)
            if payload_total > cfg.MAX_RESPONSE_BYTES:
                raise HTTPException(413,
                                    f"slice payload exceeds {cfg.MAX_RESPONSE_BYTES} bytes; narrow from/to")

            await s.redeem_ticket(ticket)
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
