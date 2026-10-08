# Security remediation — Phase 3 record: trusted-head verification

Bounded local change made after the Phase 2 fixes. **Local only: nothing here is
released, published, or deployed.** No version bump, no artifact rebuild, no new
tag, and **no change to the hash format**.

Labels: **[S]** captured output/source · **[U]** unverified · **[C]** constraint
or decision.

---

## 1. The gap this closes

The daemon's chain is *self*-consistent. `curr_hash = sha256(prev_hash ++ payload)`
binds each block to its predecessor, and the client recomputes the whole chain. That
detects a payload edited in place, because the recorded hash no longer matches what
the payload produces.

It does **not** detect a host that rewrites a pad's history and recomputes every
hash afterwards. Such a chain is internally perfect. **[C]** Worth stating plainly:
a chain a host produces and a chain the same host serves cannot, on their own,
tell you the content is the one the writer wrote. Nothing *inside* the pad can
establish that.

**[S] Reproduced locally.** A pad was written and sealed through the real daemon,
the true head captured from the seal response, then block 1 altered from
`pay Alice 10 USDC` to `pay Mallory 9999 USDC` and the entire chain rehashed:

```
TRUE head:            f63b537ff16f836480a8ba6f…
REWRITTEN head:       d49eaf6f3c2fb81184bed574…
rewritten chain internally consistent: True (2 blocks verified)
```

The rewrite verifies perfectly against itself. It is visible **only** by comparing
against the head the writer held.

---

## 2. Contracts inspected before changing anything

| Tool | Contract before this phase |
|------|----------------------------|
| `locker_read_blocks(pad_id, ticket, from_block=0, to_block=0)` | Walks the **whole** chain, verifies it in Python, then slices for display. Returns `pad_id, from, to, count, total_blocks, integrity, blocks`. |
| `locker_manifest(pad_id, ticket=None)` | With a ticket, walks the chain and returns `{**manifest, "integrity": …}`. Without one, returns the server's manifest with `chain_valid=None`. |

Both already returned an `integrity` block, both already had an optional-ticket
shape, and `chain_valid` is documented as *internal consistency only*. **[C]** The
new parameter is additive on both; neither existing parameter changed meaning.

---

## 3. Changed behaviour

Both read tools take a new optional `expected_head_hash`. The integrity block gains
two additive keys:

```
integrity = {
  "chain_valid":     <bool|None>,   # unchanged meaning: internal consistency
  "blocks_verified": <int>,         # unchanged
  "payloads":        "untrusted",   # unchanged
  "note":            <str>,         # unchanged
  "expected_head": {                # NEW
    "supplied": <bool>, "checked": <bool>, "matches": <bool|None>,
    "expected": <str|None>, "observed": <str|None>, "detail": <str>,
  },
  "verdict": <str>,                 # NEW
}
```

`verdict` is an enum rather than a boolean, deliberately: a boolean would have to
answer "was this verified?", and the honest answer is often "partly" — it can never
be allowed to read as *verified* when nothing was compared against a reference.

| `verdict` | Meaning |
|-----------|---------|
| `trusted_head_match` | A caller-supplied head was supplied, well-formed, and **equalled** the head recomputed from the chain. |
| `internal_consistency_only` | No reference was supplied. The chain is consistent with itself — **[C] which a comprehensive rewrite would also satisfy.** |
| `not_checked` | No chain was walked at all (manifest without a ticket). |
| `failed` | The chain is inconsistent, or the supplied reference could not be checked / did not match. |

**[C] The two axes stay separate.** `chain_valid` reports *internal* consistency and
keeps its existing behaviour completely; `expected_head` reports comparison against a
reference obtained elsewhere. Neither is derived from the other.

**Behaviour matrix**

| Situation | Result |
|-----------|--------|
| No expected head | `checked=false, matches=null` → **not checked**, never a failure. `chain_valid` is still reported. |
| Expected head supplied, matched, chain consistent | `verdict=trusted_head_match`, payloads returned. |
| Expected head supplied, **mismatched** | `{"error": {"status": 0, "kind": "verification_failed", …}}` — **no payloads returned at all**. |
| Expected head supplied but **malformed** | Same failure shape. **[C]** Never downgraded to "not supplied": that would silently report a weaker check than the caller asked for. |
| Expected head supplied, chain inconsistent | Failure — no confirmable head exists, so the comparison could not be made, and it is not reported as a match. |
| `locker_manifest(expected_head_hash=…)` **without** a ticket | Failure. **[C]** The daemon's own manifest head is **never** substituted for the caller's reference — with no ticket there is no chain to walk, so the head cannot be recomputed independently of the server. |

**[C] Failure returns no payload.** A mismatch is reported through the existing
`error` shape (`kind: "verification_failed"` distinguishes it from a daemon error,
which has no `kind`), and the result carries no `blocks` key, so a caller — or a
model — that reads only `error` cannot mistake it for a successful verified read.
The `integrity` block rides along purely for diagnosis. The pre-existing tamper
behaviour is **unchanged**: a broken chain with no expected head still returns the
blocks with `chain_valid=false`, which is what existing callers and
`scripts/test_handoff_e2e.py` depend on.

**Edge cases defined and tested**

- *Partial reads.* The expected head always describes the **whole chain**, not the
  returned slice, because the client walks the chain to the end regardless of
  `from_block`/`to_block`. A rewrite in Block 2 is caught by a Block-0 read.
- *Empty pads.* A pad with no blocks has the genesis head `000…0`; that head is
  checkable like any other, and a wrong one still fails. Not an error.
- *Mutable vs sealed.* For an **unsealed** pad the head moves on every append, so an
  expected head captured earlier legitimately goes stale and now fails — correct, and
  documented. **Sealing** freezes the head, which is what makes the reference stable.

---

## 4. How the writer gets the head, and what this does and does not prove

**[C] Procedure.**

1. The writer seals the pad. The seal response returns `head_hash`; `locker_deposit`
   returns the same value as `head_hash`. That is the authoritative moment — the pad
   is final and cannot be appended to again.
2. The writer hands that hash to the reader over a **separately trusted channel**:
   in the task assignment, a signed message, a ticket system, a system of record —
   anywhere that is not the daemon the reader is about to check. **[C]** Re-reading
   it from the same daemon would defeat the purpose entirely.
3. The reader passes it as `expected_head_hash`. The client recomputes the head from
   the chain it fetched and compares.

**What a match proves:** the byte content served is the content that produced that
head — the chain was not rewritten, rehashed, truncated, or substituted, *relative
to the reference the reader already trusted*.

**What it does not prove:** not writer identity, not that the writer is who they
claim, not that the content is correct, safe, or non-malicious, and not that the
reference itself was authentic. **[C]** If the trusted channel is compromised, the
check is worthless. It converts "trust the host" into "trust the channel you already
use for the reference" — which is a real narrowing, not a solution to trust.

---

## 5. Tests

**[S]** Focused suite `tests/test_phase3_trusted_head.py` — **25 tests**, all passing.
Whole suite **88 → 113 passed**; `scripts/test_handoff_e2e.py` still passes end to
end over MCP.

The rewrite cases run against a **real daemon on a real socket** with a shim in
front that serves the rewritten chain — not a mock of the client's internals. The
shim's self-check (`chain_valid=True` on a rehashed rewrite, without a reference)
means the detection test cannot pass vacuously: if the rewrite stopped being served,
that test would fail first.

Required regressions, each mapped to a test:

| Required | Test |
|----------|------|
| Untouched sealed chain + correct head passes | `test_untouched_sealed_chain_with_the_correct_expected_head_passes` |
| Payload altered without rehashing fails internal consistency | `test_payload_alteration_without_rehashing_fails_internal_consistency` |
| Altered **and** fully rehashed passes internal consistency but fails against the original head | `test_rewritten_and_rehashed_chain_passes_internal_consistency` + `…_fails_against_the_true_head` |
| Wrong and malformed expected heads fail | `test_wrong_but_wellformed_expected_head_fails`, `test_malformed_expected_head_is_rejected_not_ignored` (11 malformed forms) |
| No supplied head reports not checked | `test_no_expected_head_reports_not_compared_rather_than_failed`, `test_manifest_without_ticket_reports_not_checked` |
| Partial reads and empty pads explicit and tested | `test_partial_read_still_compares_against_the_whole_chain`, `test_empty_pad_behaviour_is_explicit` |

Plus: mutable-vs-sealed, no manifest-head substitution, existing call signatures and
keys preserved, verification failure distinguishable from a daemon error, payload
bytes never rewritten by the check.

---

## 6. Limitations

- **[C] Unauthenticated metadata.** Everything the daemon returns about a pad is a
  claim by the host, and none of it is signed. `state`, `block_count`, `total_bytes`,
  `sealed_at`, `created_at`, `expires_at` and `head_hash` in the manifest, and
  `prev_hash`/`curr_hash`/`payload_utf8`/`created_at` on each block, are
  unauthenticated fields. **[C]** They *drive* the verification — `block_count` and
  `head_hash` decide what gets walked — so a hostile host can withhold blocks, serve
  a consistent prefix, or lie about state; the walk only proves the served blocks
  agree with each other and (when a reference is supplied) with the reference.
  `payload_utf8` is a convenience decode of `payload_b64` and is not itself verified.
- **[U]** Not addressed here: writer identity, transport confidentiality beyond the
  existing TLS, replay of a whole pad from a different pad id, and denial of service.
- **[U]** The hosted instance runs 0.1.0 and has no write path reachable, so this
  feature was exercised only against the local daemon.
- **[C]** A caller that never supplies an expected head gets no protection against a
  comprehensive rewrite from this change. The `verdict` field exists so that
  weak position is visible in the result rather than implied to be fine.

---

## 7. Hash format: unchanged, with a proposal recorded separately

**[C]** No hash-format change in this phase. `curr_hash = sha256(prev_hash ++ payload)`
with lowercase hex, inherited unchanged.

Candidate improvements — **[U] proposals only, not implemented, not scheduled**:

1. **Domain separation.** Prefix the digest input with a context string
   (e.g. `b"locker.block.v1\x00"`) so a locker hash can never be confused with a
   hash of the same bytes computed for another purpose.
2. **Length-prefix the fields.** `prev_hash ++ payload` is unambiguous only because
   `prev_hash` is fixed width; encoding `(tag, length, value)` per field would make
   the construction robust to future field additions.
3. **Versioned envelope.** A canonical `locker.head.v1` object — `{v, alg, pad_id,
   seq, prev, curr}` — that can be serialised and signed as a unit, so a head can
   carry its own algorithm and parameters.
4. **A signed head.** Signing the head with an operator key would finally bind
   content to a *key* rather than to a channel. This is the only item that addresses
   the limitation in section 4, and it is a design change, not a fix.

Any change here is a format break: it would invalidate every existing head and
require a versioned, dual-read transition. Recorded for a separate decision.

---

## 8. Deployment implications

- **[C]** Client-side change only; the daemon and the on-disk format are untouched.
  Existing daemons keep working, including the hosted 0.1.0 instance.
- **Response schema:** two additive keys (`expected_head`, `verdict`) inside the
  existing `integrity` block; existing readers that ignore unknown keys are
  unaffected. The one behavioural addition is that a *supplied* bad expected head
  returns an `error` — a path no existing caller can reach, since the parameter is
  new.
- **[C]** Public release and live backend deployment remain pending; this sits on
  the combined development lineage with the Phase 1 and Phase 2 work.
