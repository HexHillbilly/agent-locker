"""Configuration and hard limits for the locker daemon."""
from __future__ import annotations

import os
from dataclasses import dataclass

# Hard limits (memory-safe, per spec)
MAX_BLOCK_BYTES = 64 * 1024          # max payload per block: 64 KB
MAX_RESPONSE_BYTES = 64 * 1024       # max payload returned per blocks slice: 64 KB
MAX_BLOCKS_PER_RESPONSE = 256        # max block count per blocks slice
DEFAULT_MAX_BLOCKS = 32
DEFAULT_MAX_BYTES = 256 * 1024       # per-pad byte quota: 256 KB
MAX_MAX_BLOCKS = 4096                # sanity cap on user-provided max_blocks
MAX_TTL_SECONDS = 30 * 24 * 3600     # 30 days
READ_LEASE_SECONDS = 600             # read_once ticket lease window (10 min)
ZERO_HASH = "0" * 64

AUTH_LOCAL = "local"
AUTH_X402 = "x402"


@dataclass
class Config:
    db_path: str = "locker.db"
    auth_mode: str = AUTH_LOCAL
    read_lease_seconds: int = READ_LEASE_SECONDS

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            db_path=os.environ.get("LOCKER_DB", "locker.db"),
            auth_mode=os.environ.get("AUTH_MODE", AUTH_LOCAL),
            read_lease_seconds=int(os.environ.get("LOCKER_READ_LEASE_SECONDS", READ_LEASE_SECONDS)),
        )
