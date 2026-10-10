#!/usr/bin/env python3
"""Inspect a locker pad and verify its hash chain (stdlib only).

Usage:
    python scripts/inspect_pad.py <pad_id> [--ticket TICKET] [--url URL]
"""
import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request

ZERO = "0" * 64


class DaemonError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        super().__init__(detail)


def get(url: str, token: str | None = None):
    """GET *url*, optionally presenting *token* as a Bearer credential.

    The ticket travels in the Authorization header, never in the URL, so it
    cannot be captured by a proxy log or echoed in an error message.
    """
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise DaemonError(e.code, (e.read().decode() or e.reason))
    except urllib.error.URLError as e:
        raise DaemonError(0, f"cannot reach daemon: {e.reason}")


def fetch_blocks(base: str, pad_id: str, ticket: str, block_count: int):
    blocks = []
    chunk = 256
    start = 0
    while start < block_count:
        end = min(start + chunk - 1, block_count - 1)
        url = f"{base}/v1/pads/{pad_id}/blocks?from={start}&to={end}"
        try:
            resp = get(url, token=ticket)
        except DaemonError as e:
            if e.status == 413 and chunk > 1:
                chunk = max(1, chunk // 2)
                continue
            raise
        blocks.extend(resp["blocks"])
        start = end + 1
    return blocks


def verify_chain(blocks, head_hash):
    prev = ZERO
    verified = 0
    for b in blocks:
        payload = base64.b64decode(b["payload_b64"])
        expect = hashlib.sha256(prev.encode() + payload).hexdigest()
        if b["prev_hash"] != prev or b["curr_hash"] != expect:
            return False, verified
        prev = b["curr_hash"]
        verified += 1
    return (verified == len(blocks)) and (prev == head_hash), verified


def _normalize_argv(argv: list[str]) -> list[str]:
    """Make ``--ticket=<value>`` out of ``--ticket <value>`` when the value starts with "-".

    Read tickets are ``secrets.token_urlsafe(32)``, i.e. URL-safe base64, so ``-`` is in the
    alphabet and a ticket really can begin with one. argparse reads a value that begins with
    a dash as an option and fails with "expected one argument", so roughly one ticket in 64
    could not be passed in the space-separated form. Measured on this build: a ticket
    ``-Ot9gmg44gUrGWlRFmVv0QDYYo8F0IGvK82LL2vAf4`` returns exit 2 while the same ticket in
    the ``--ticket=`` form exits 0. This normalises the former into the latter; every other
    argument is passed through untouched.
    """
    out: list[str] = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if (arg in ("--ticket", "-t") and index + 1 < len(argv)
                and argv[index + 1].startswith("-")):
            out.append(f"--ticket={argv[index + 1]}")
            index += 2
            continue
        out.append(arg)
        index += 1
    return out


def main():
    ap = argparse.ArgumentParser(description="Inspect a locker pad and verify its hash chain.")
    ap.add_argument("pad_id", help="pad id to inspect")
    ap.add_argument("--ticket", "-t", default=None,
                    help="read ticket (required to verify the chain; a value beginning with "
                         "a dash is accepted in either form)")
    ap.add_argument("--url", default="http://127.0.0.1:8000", help="daemon base URL")
    args = ap.parse_args(_normalize_argv(sys.argv[1:]))

    base = args.url.rstrip("/")
    try:
        m = get(f"{base}/v1/pads/{args.pad_id}/manifest")
    except DaemonError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    sealed = m["sealed_at"] is not None
    print(f"pad           {args.pad_id}")
    print(f"  state        {m['state']}")
    print(f"  blocks       {m['block_count']}")
    print(f"  total_bytes  {m['total_bytes']}")
    print(f"  sealed       {'yes' if sealed else 'no'}"
          + (f" (at {m['sealed_at']})" if sealed else ""))
    print(f"  head_hash    {m['head_hash']}")

    if m["block_count"] == 0:
        print("\nchain: empty pad (nothing to verify)")
        return

    if not args.ticket:
        print("\nchain: NOT verified — pass --ticket to read blocks and verify")
        return

    blocks = fetch_blocks(base, args.pad_id, args.ticket, m["block_count"])
    ok, verified = verify_chain(blocks, m["head_hash"])
    if ok:
        print(f"\nchain: VERIFIED — {verified} blocks, genesis -> head_hash consistent")
    else:
        print(f"\nchain: BROKEN — {verified} blocks verified before mismatch")
        sys.exit(2)


if __name__ == "__main__":
    main()
