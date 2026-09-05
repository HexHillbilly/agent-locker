"""Entry point for ``python -m lockermcp`` and the ``lockermcp`` console script."""
from lockermcp.server import server


def main() -> None:
    # Runs the MCP stdio server loop (blocks until the client disconnects).
    server.run()


if __name__ == "__main__":
    main()
