"""Run the daemon with ``python -m lockerd`` (honours LOCKER_* env vars)."""
import os

import uvicorn

from lockerd import config as cfg


def main() -> None:
    # Validate configuration before binding a port, so a bad value fails fast
    # with a readable message instead of surfacing as a uvicorn startup
    # traceback or, worse, a silent fallback.
    try:
        cfg.Config.from_env()
    except cfg.ConfigError as exc:
        raise SystemExit(f"lockerd: {exc}") from None

    uvicorn.run(
        "lockerd.main:create_app",
        factory=True,
        host=os.environ.get("LOCKER_HOST", "127.0.0.1"),
        port=int(os.environ.get("LOCKER_PORT", "8000")),
    )


if __name__ == "__main__":
    main()
