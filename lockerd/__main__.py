"""Run the daemon with ``python -m lockerd`` (honours LOCKER_DB / AUTH_MODE env)."""
import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "lockerd.main:create_app",
        factory=True,
        host=os.environ.get("LOCKER_HOST", "127.0.0.1"),
        port=int(os.environ.get("LOCKER_PORT", "8000")),
    )


if __name__ == "__main__":
    main()
