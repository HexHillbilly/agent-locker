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

# x402 payment defaults (Base USDC)
DEFAULT_BASE_RPC_URL = "https://mainnet.base.org"
DEFAULT_USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
DEFAULT_REQUIRED_USDC_UNITS = 2000   # 0.002 USDC (6 decimals)


@dataclass
class Config:
    db_path: str = "locker.db"
    auth_mode: str = AUTH_LOCAL
    read_lease_seconds: int = READ_LEASE_SECONDS
    payment_wallet_address: str | None = None
    base_rpc_url: str = DEFAULT_BASE_RPC_URL
    required_usdc_units: int = DEFAULT_REQUIRED_USDC_UNITS
    usdc_contract: str = DEFAULT_USDC_CONTRACT

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            db_path=os.environ.get("LOCKER_DB_PATH", "locker.db"),
            auth_mode=os.environ.get("LOCKER_MODE", AUTH_LOCAL),
            read_lease_seconds=int(os.environ.get("LOCKER_READ_LEASE_SECONDS", READ_LEASE_SECONDS)),
            payment_wallet_address=os.environ.get("PAYMENT_WALLET_ADDRESS") or None,
            base_rpc_url=os.environ.get("BASE_RPC_URL", DEFAULT_BASE_RPC_URL),
            required_usdc_units=int(os.environ.get("REQUIRED_USDC_UNITS", DEFAULT_REQUIRED_USDC_UNITS)),
            usdc_contract=os.environ.get("USDC_CONTRACT", DEFAULT_USDC_CONTRACT),
        )
