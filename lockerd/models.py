"""Pydantic request/response models for OpenAPI documentation."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from . import config as cfg


class IntegrityModel(BaseModel):
    chain_valid: bool | None = None
    blocks_verified: int = 0


# ---- requests ----
class PadCreateRequest(BaseModel):
    ttl_seconds: int = Field(3600, gt=0, le=cfg.MAX_TTL_SECONDS)
    max_blocks: int = Field(32, gt=0, le=cfg.MAX_MAX_BLOCKS)


class PadAppendRequest(BaseModel):
    write_key: str
    payload: Any
    content_type: str = "application/json"


class PadSealRequest(BaseModel):
    write_key: str


# ---- responses ----
class PadCreatedResponse(BaseModel):
    pad_id: str
    write_key: str
    read_ticket: str


class AppendResponse(BaseModel):
    pad_id: str
    seq: int
    curr_hash: str


class SealResponse(BaseModel):
    pad_id: str
    state: str
    sealed_at: int | None
    head_hash: str


class TicketMintRequest(BaseModel):
    type: str = "read_unlimited"


class TicketMintResponse(BaseModel):
    pad_id: str
    ticket: str
    type: str


class BlockResponse(BaseModel):
    seq: int
    prev_hash: str
    curr_hash: str
    content_type: str
    payload_b64: str
    payload_utf8: str | None
    created_at: int


class BlocksResponse(BaseModel):
    pad_id: str
    from_: int = Field(alias="from")
    to: int
    count: int
    total_blocks: int
    blocks: list[BlockResponse]


class ManifestResponse(BaseModel):
    pad_id: str
    state: str
    block_count: int
    total_bytes: int
    sealed_at: int | None
    head_hash: str
    created_at: int
    expires_at: int


class HealthResponse(BaseModel):
    status: str
    version: str
    database: dict
    rpc: dict
    pads: dict
