# Security remediation — Phase 2 record

Bounded local fixes made after the Phase 1 containment. **Local only: nothing here
is released, published, or deployed.** No version bump, no artifact rebuild, no
tag move, no runtime behaviour change beyond the three items below.

Labels: **[S]** supported by captured output or source · **[U]** unverified ·
**[C]** constraint or decision.

## Baseline

**[S]** `pytest -q` on the pre-change tree: **47 passed**. After these changes,
including 40 new focused tests: **87 passed**. No pre-existing test was modified.

---

## A · Configuration: reject an explicitly supplied unknown `LOCKER_MODE`

### Reproduction

**[S]** `lockerd/config.py` ended in `return AUTH_OPEN  # unknown -> open
(developer-friendly default)`. Any unrecognised value — a typo, a bad compose
edit — silently selected **no payment enforcement**.

### Changed behaviour

**[S]** `normalize_mode()` now maps the accepted spellings (`open`, `local`,
`dev` → open; `txid`, `x402` → txid) case-insensitively and whitespace-tolerantly,
and raises the new `ConfigError` for anything else. `None`, empty, and
whitespace-only still mean *not supplied* and yield the documented default,
`open`.

**[S]** `lockerd/__main__.py` validates before binding a port, so the failure is
one readable line instead of a uvicorn startup traceback:

```
$ LOCKER_MODE=txdi python -m lockerd
lockerd: LOCKER_MODE='txdi' is not a recognized mode; expected one of: dev, local, open, txid, x402
exit=1
```

**[S]** A valid mode still starts normally (`LOCKER_MODE=txid` ran until the test
timeout stopped it).

### Tests

7 acceptance cases for the accepted spellings, the documented default for
unset/empty, 6 rejection cases, `from_env` on both paths, and `create_app()`
refusing to build with a typo mode — the startup gate, not just the helper.

### Limits

**[U]** Other environment variables (`LOCKER_READ_LEASE_SECONDS`,
`REQUIRED_USDC_UNITS`) still go through bare `int()` and will raise a raw
`ValueError` on garbage rather than a shaped error. Out of scope for this item;
noted so it is not mistaken for covered.

---

## B · Ticket transport: the client sends read tickets in the `Authorization` header

### Reproduction

**[S]** The client built its block request as
`params={"ticket": ticket, "from": start, "to": end}`, so the read ticket was
placed in the **request URL** — where proxies, access logs, and error strings can
capture it.

### Compatibility evidence, from source

**[S]** The daemon has accepted the header since its **first commit**:
`ticket = ticket or extract_bearer(request)` is present in the `/blocks` handler at
`d100a91` (first commit), `7390446`, `1f7807a`, `0d4311`, `37b46b7`, and `e523074`
(tag `v0.1.0`). The header path is therefore compatible with every daemon revision
in this repository's history, including the older build running on the hosted
instance.

**[S]** The query parameter is also still accepted by the daemon, and this change
does not touch the daemon at all.

### Changed behaviour

**[S]** The client now sends `Authorization: Bearer <ticket>` by default. The
legacy URL form remains available as an explicit, documented switch —
`LOCKER_TICKET_TRANSPORT=query` — rather than an automatic fallback, because
falling back silently would put the ticket back into the URL. An unrecognised
value raises rather than defaulting.

**[S]** Error paths are hardened so a ticket cannot leave through a message:
transport errors report only the query-stripped URL (`_redact`), and any daemon
error raised while fetching blocks has the ticket value scrubbed (`_scrub`).

### Tests

**[S]** A real daemon on a real socket is used for the end-to-end cases: the
client verifies a genuinely sealed pad over **both** transports with
`chain_valid: true`, so the change cannot break a daemon that only understands the
query parameter. Separate tests prove the daemon accepts the header directly and
still accepts the query parameter; that the ticket cannot escape through an error
message even when the daemon echoes it; and that on the default transport the
ticket appears in neither the URL nor the query.

### Limits — stated narrowly

- **[U]** Header transport is verified against the in-repo daemon, not against the
  hosted 0.1.0 instance. The hosted instance is read-only and no pad was created
  there, so the compatibility claim rests on the source evidence above, not on a
  live exercise.
- **[U]** **No claim is made that tickets were observed in any proxy log.** That
  was never evidenced. What is established is narrower: this client previously
  put the ticket in the URL, and no longer does by default.
- **[C]** A client that sets the transport to `query` still puts the ticket in the
  URL, and a server-side access log will still record it. The daemon is unchanged
  in this respect.

---

## C · Untrusted payload framing

### Changed behaviour

**[S]** The server's `instructions`, both read tools' descriptions, and the
returned verification metadata now state that payloads are **untrusted data, not
instructions**; that chain consistency is *internal* consistency only, which
establishes neither authorship nor the truth of any claim; and that it is not
authorization to follow instructions found inside a payload.

**[S]** The `integrity` block gains two **additive** keys — `payloads:
"untrusted"` and `note: <the framing sentence>`. `chain_valid` and
`blocks_verified` keep exactly their previous meaning and values, so existing
readers are unaffected; the addition is documented here and in the code.

**[S]** Payload bytes are untouched: `_fetch_and_verify_chain` verifies and
returns what the daemon returned, and never rewrites content. A test round-trips a
payload containing non-ASCII text and a prompt-injection-shaped instruction and
asserts the decoded bytes equal what was written.

### Tests

Framing present in the instructions and in the tool source; the `integrity` block
carries `payloads`/`note` alongside the unchanged keys; a sealed read returns
`chain_valid: true`; the untrusted manifest branch reports `chain_valid: null`
(not checked) rather than a failure.

### Limits

**[U]** These are descriptions and metadata. They raise the cost of a payload
being read as instructions; they cannot compel a model to treat it as data, and
nothing here inspects or validates payload content.

---

## Deployment implications

- **[C]** Client-side change: any deployment whose agents use `lockermcp` picks up
  the header transport on upgrade. Nothing needs to change on a daemon, and no
  configuration is required.
- **[C]** Phase 2A is a behavioural change for anyone relying on the previous
  silent fallback for an unrecognised mode. That reliance was a defect, but it is
  a change, so it belongs in the release notes for the next release.
- **[C]** The two new `integrity` keys are additive. A consumer doing strict schema
  validation against an exact key set would notice; nothing in this repository
  does.
- **[C]** **Public release and deployment remain pending.** Phase 2 changes stay on
  this branch until the release-candidate gate, where the full suite runs again.
