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

# Auth modes (canonical)
AUTH_OPEN = "open"      # open/local access, no payment required (default)
AUTH_TXID = "txid"      # tx-hash receipt verification (Base USDC)
# Legacy aliases (kept for backward compatibility)
AUTH_LOCAL = AUTH_OPEN
AUTH_X402 = AUTH_TXID

# Accepted LOCKER_MODE spellings -> canonical value. Anything not listed here is
# rejected at startup; see normalize_mode().
MODE_ALIASES = {
    "open": AUTH_OPEN,
    "local": AUTH_OPEN,
    "dev": AUTH_OPEN,
    "txid": AUTH_TXID,
    "x402": AUTH_TXID,
}

# x402 payment defaults (Base USDC)
DEFAULT_BASE_RPC_URL = "https://mainnet.base.org"
DEFAULT_USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
DEFAULT_REQUIRED_USDC_UNITS = 2000   # 0.002 USDC (6 decimals)


class ConfigError(ValueError):
    """An explicitly supplied configuration value is not usable.

    Raised while building the config, i.e. at startup, so a bad value stops the
    daemon rather than silently changing what it does.
    """


def normalize_mode(mode: str | None) -> str:
    """Map a ``LOCKER_MODE`` label to its canonical value.

    ``None``, or a value that is empty/whitespace-only, means *not supplied* and
    yields the documented default (``open``).

    Any other unrecognised value raises :class:`ConfigError`. This matters
    because the mode decides whether payment enforcement is on: an unrecognised
    value previously fell back to ``open`` silently, so a typo in a deployment
    that meant to require payment would serve requests for free instead. Legacy
    aliases (``local``, ``dev``, ``x402``) stay accepted, and matching is
    case-insensitive and whitespace-tolerant.
    """
    if mode is None or not str(mode).strip():
        return AUTH_OPEN
    key = str(mode).strip().lower()
    try:
        return MODE_ALIASES[key]
    except KeyError:
        raise ConfigError(
            f"LOCKER_MODE={mode!r} is not a recognized mode; expected one of: "
            f"{', '.join(sorted(MODE_ALIASES))}"
        ) from None


@dataclass
class Config:
    db_path: str = "locker.db"
    auth_mode: str = AUTH_OPEN
    read_lease_seconds: int = READ_LEASE_SECONDS
    payment_wallet_address: str | None = None
    base_rpc_url: str = DEFAULT_BASE_RPC_URL
    required_usdc_units: int = DEFAULT_REQUIRED_USDC_UNITS
    usdc_contract: str = DEFAULT_USDC_CONTRACT

    @classmethod
    def from_env(cls) -> "Config":
        """Build a config from the environment.

        Documented defaults: ``LOCKER_MODE`` unset (or empty) means ``open`` —
        no payment required. The other fields fall back to the constants above.
        An explicitly supplied but unrecognised ``LOCKER_MODE`` raises
        :class:`ConfigError` instead of defaulting; see :func:`normalize_mode`.
        """
        return cls(
            db_path=os.environ.get("LOCKER_DB_PATH", "locker.db"),
            auth_mode=normalize_mode(os.environ.get("LOCKER_MODE", AUTH_OPEN)),
            read_lease_seconds=int(os.environ.get("LOCKER_READ_LEASE_SECONDS", READ_LEASE_SECONDS)),
            payment_wallet_address=os.environ.get("PAYMENT_WALLET_ADDRESS") or None,
            base_rpc_url=os.environ.get("BASE_RPC_URL", DEFAULT_BASE_RPC_URL),
            required_usdc_units=int(os.environ.get("REQUIRED_USDC_UNITS", DEFAULT_REQUIRED_USDC_UNITS)),
            usdc_contract=os.environ.get("USDC_CONTRACT", DEFAULT_USDC_CONTRACT),
        )
