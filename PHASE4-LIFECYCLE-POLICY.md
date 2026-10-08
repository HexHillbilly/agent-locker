# Phase 4 — Lifecycle policy: options for operator decision

**[C] Status: policy only. Nothing in this document is implemented, and nothing in
it is a promise about what happens to data.** The work order asks for the policy
table first, then implementation after decisions. That is the order used here.

Labels: **[S]** captured from source/output · **[U]** unknown or unverified ·
**[C]** constraint or decision. Every "current behaviour" cell below is **[S]**,
read from `lockerd/db.py` and `lockerd/main.py` on the integration lineage **and**
confirmed by local execution where execution can confirm it (§1.1). No cell
describes intended or expected behaviour, and no cell is a prediction.

---

## 0. Guiding principles (operator, 2026-10-08)

**[C]** Two principles constrain these decisions. They rule options out; they do not
pick between the ones that remain.

**P1 — Separate write expiry, read expiry, and deletion.** These are three different
questions and they get three different answers. **[C] In particular, a TTL must not
silently become permission to destroy data.** Today `expires_at` means "no more
writes", and every pad already in the database carries a TTL that was agreed on that
understanding. Reusing it as a deletion trigger would retroactively change the
meaning of a value already stored, without the pad creator having agreed to it.
Wherever an option below takes its trigger from `expires_at`, it is flagged **[P1]**.

**P2 — Payment replay protection is independent of payload retention, and ticket
expiry/revocation must be explicit.** A receipt lifetime has nothing to do with a
payload lifetime, and nothing about deleting payloads may shorten the replay window.
Ticket lifetimes must be stated and enforceable rather than implied by "it happens
not to expire". Flagged **[P2]**.

---

## 1. Current behaviour (from source)

**[S]** Schema (`lockerd/db.py`, `SCHEMA`):

| Table | Columns (abridged) |
|-------|--------------------|
| `pads` | `id`, `created_at`, `expires_at`, `max_blocks`, `max_bytes`, `current_bytes`, `state ∈ {open, sealed, expired}`, `write_key_hash`, `head_hash`, `sealed_at` |
| `blocks` | `id`, `pad_id → pads(id)`, `seq`, `prev_hash`, `curr_hash`, `content_type`, `payload` BLOB, `created_at`, `UNIQUE(pad_id, seq)` |
| `tickets` | `ticket_id` PK, `pad_id → pads(id)`, `type ∈ {read_once, read_unlimited}`, `redeemed_count`, `max_reads`, `lease_started_at`, `created_at` |
| `payment_receipts` | `tx_hash` PK, `pad_id → pads(id)`, `amount_units`, `payer_address`, `created_at` |

**[S]** Connection pragmas: `journal_mode = WAL`, **`foreign_keys = ON`**,
`synchronous = NORMAL`.

**[S] Expiry is lazy and write-only.**

- `expires_at = created_at + ttl_seconds`, set at creation. TTL is capped by
  `MAX_TTL_SECONDS` (30 days).
- `expire_pad_if_needed` runs `UPDATE pads SET state='expired' WHERE id=? AND
  state='open'` when `expires_at <= now()`. It is called from `append`, `seal`,
  `manifest` and `blocks` — i.e. **on access, never by a background job**.
- Because the update is guarded on `state='open'`, a **sealed** pad is never marked
  expired. **[S]** `state` is what it is: `sealed` stays `sealed` past its TTL.
- `append` and `seal` reject with **410 gone** when expired (409 when sealed).

**[S] Read availability is not affected by expiry.** The `/blocks` handler calls
`expire_pad_if_needed` and then serves the requested slice — there is **no state
check**. An expired open pad and a long-expired sealed pad are both readable while a
valid ticket exists.

**[S] Tickets.** `read_once` is a **read lease**: the first recorded read sets
`lease_started_at`, `check_ticket` returns `exhausted` once
`now() - lease_started_at > read_lease_seconds` (default 600s). `read_unlimited`
has **no expiry check at all** in `check_ticket`.

**[S] There is no revocation mechanism.** No `revoked` column, no DELETE of ticket
rows, no denylist anywhere in `lockerd/`.

**[S] There is no deletion mechanism.** No `DELETE FROM` statement exists in the
daemon, and no `VACUUM`. Blocks, pads, tickets and receipts are retained
indefinitely; `expired` is a state flag, not a retention outcome.

**[S] Payment receipts.** `payment_receipts.tx_hash` is the replay-prevention key
(`has_receipt(tx_hash)` guards `create_pad_with_receipt`). Receipts are never
deleted, so replay prevention currently survives by doing nothing.

**[S] Limits that exist:** per block 64 KB (`MAX_BLOCK_BYTES`), per pad 256 KB
(`DEFAULT_MAX_BYTES`) and `max_blocks` (default 32, sanity cap 4096), per response
256 blocks and 64 KB. **[S] Limits that do not exist: no cap on the number of pads,
no cap on total database size, no request-rate limiting, and no `429` anywhere in
the daemon.** **[U]** No forwarded-address handling: nothing reads
`X-Forwarded-For` or `Forwarded`, and no trusted-proxy list is configured.

### 1.1 Confirmed by local execution

**[S]** A local daemon was driven through the real HTTP API (`ttl_seconds=1`) to
check the source reading rather than trusting it. Observed:

| Action | Result |
|--------|--------|
| OPEN pad, TTL passed, then `GET /manifest` | `state` flips `open` → `expired` (the access does it) |
| `GET /blocks` on that expired open pad | **200**, `count=1` — reads are not blocked by expiry |
| `POST /append` on the expired pad | **410 gone** `pad is expired` |
| `POST /seal` on the expired pad | **410 gone** `pad is expired` |
| `POST /tickets` (`read_unlimited`) on the expired pad | **201** — minting is not blocked |
| `GET /blocks` with that freshly minted ticket | **200** — the new ticket works |
| SEALED pad, TTL passed, then `GET /manifest` | `state` stays **`sealed`** (never flipped to expired) |
| `GET /blocks` on that sealed pad past TTL | **200** — readable |
| `ttl_seconds` above `MAX_TTL_SECONDS`, `max_blocks` above the cap | **422** — those caps are enforced |

**[S] The two behaviours most likely to surprise an operator are confirmed, not
inferred:** expiry stops writes and does **not** stop reads, and a sealed pad is
never marked expired at all.

---

## 2. The policy table

Each row states the current behaviour, the options, what each option costs, and the
decision that is required. **[C]** Options are options — where the work order does
not define the intended outcome, this document does not pick one.

### 2.1 Write expiry

| | |
|---|---|
| **Current [S]** | `expires_at` fixed at creation from `ttl_seconds`; appended/sealed pads past it become `expired` on next access; `append`/`seal` return 410. Sealed pads are never marked expired. |
| **Options** | **(a)** Keep as is. **(b)** Add a background sweeper so `expired` is set even without access (status becomes consistent without traffic). **(c)** Apply expiry to sealed pads too (would need a decision on whether sealing is a promise of permanence — the current guard says it is). **(d)** Allow TTL extension by write-key holder before expiry. |
| **Compatibility** | (a) none. (b) none observable, but introduces a scheduler and a failure mode (sweeper not running ⇒ silent divergence from intent). (c) **breaking**: sealed pads would become unreadable and existing callers relying on "sealed means permanent" would break. (d) new endpoint, additive. |
| **Decision [C]** | Does sealing mean *permanent*? Today it does, by construction. If yes, (c) is out and (b) should skip sealed pads. If no, sealing needs a defined retention window and a deprecation path. |

### 2.2 Read availability

| | |
|---|---|
| **Current [S]** | Reads ignore pad state entirely. A ticket is the only gate (the demo pad needs none). Expired pads remain readable. |
| **Options** | **(a)** Keep as is — "expiry stops writes, not reads". **(b)** Refuse reads on `state='expired'` (403/410) while keeping sealed-after-TTL readable. **(c)** Refuse reads on any pad past `expires_at`, sealed or not. |
| **Compatibility** | (a) none. (b) **breaking for anyone reading after TTL**; the demo pad and any audit workflow must be exempted or re-homed — the hosted instance's only public pad is the demo, which is sealed. (c) more so, and it contradicts the `sealed` guard by making TTL stronger than the seal. |
| **Principle check [P1]** | This is the **read** expiry question. It is separate from 2.1's write expiry and from 2.5's deletion, and is answered on its own terms — not as a side effect of the TTL, and not as a step towards deletion. |
| **Decision [C]** | Should an expired pad still be readable? The current answer is yes, which is currently **undocumented on the site** — the site says nothing about post-TTL read behaviour. Whatever is chosen must be reflected in `llms.txt`, or the same claim-vs-reality drift this workstream has been correcting will recur. |

### 2.3 Ticket activation and expiry

| | |
|---|---|
| **Current [S]** | `read_once`: lease opens on the first successful read and lasts `LOCKER_READ_LEASE_SECONDS` (default 600s); reads inside are unlimited, after are 403 `exhausted`. `read_unlimited`: no expiry check. Tickets minted at pad creation and via `POST /v1/pads/{id}/tickets` (write key required). |
| **Options** | **(a)** Keep. **(b)** Make the lease configurable per pad at creation. **(c)** Give `read_unlimited` a configurable expiry (see 2.4). **(d)** Record the lease-window in the manifest so a reader can plan. |
| **Compatibility** | (a) none. (b)/(d) additive response/request fields. (c) breaking for existing unlimited tickets once enforced. |
| **Decision [C]** | Is 600 s the intended lease, and is it intended to be global? Also: **the name.** See 3.1. |

### 2.4 Ticket revocation

| | |
|---|---|
| **Current [S]** | **No mechanism.** A minted ticket is valid until its lease expires (`read_once`) or forever (`read_unlimited`). Losing a ticket means it cannot be cancelled — only the pad it points at could be made unreadable, which no option in 2.2 currently does. |
| **Options** | **(a)** Add `tickets.revoked_at`, checked in `check_ticket`, plus `DELETE`-style revoke endpoint authenticated by the write key. **(b)** Revoke-by-timestamp: a pad-level `tickets_valid_after` instant that invalidates every ticket minted earlier (coarse but one column, no per-ticket bookkeeping). **(c)** Add an absolute `expires_at` to `read_unlimited` so it is bounded rather than revocable. |
| **Compatibility** | (a)/(b) additive schema + endpoint; existing tickets keep working until explicitly revoked. (c) breaking once enforced. **[C]** Any revocation feature is a *weakening* of the current "a sealed pad's read ticket is durable" property, so it needs to be opt-in per pad or clearly announced. |
| **Decision [C]** | Is revocation needed at all before public release? If yes, per-ticket (a) or pad-level (b)? |

### 2.5 Payload deletion

| | |
|---|---|
| **Current [S]** | **None.** No `DELETE FROM`, no `VACUUM`. Payload bytes persist in `blocks.payload` for the lifetime of the database file. |
| **Options** | **(a)** No deletion; expiry is a state flag only, and that is documented as such. **(b)** Delete block payloads (`UPDATE blocks SET payload=X''` or `DELETE FROM blocks`) N days after expiry, keeping `pads` and the chain hashes for audit. **(c)** Delete whole pads (blocks, tickets, receipts) after N days. |
| **Compatibility / cost** | (a) leaves the storage question open forever and must never be described as a retention guarantee. (b) removes the bytes a reader may still want; the chain head stays but blocks no longer verify — a pad would then fail `chain_valid` rather than 404, which is a worse failure mode than refusing the read. (c) **conflicts with `foreign_keys = ON`**: `blocks`, `tickets` and `payment_receipts` all reference `pads(id)` with no `ON DELETE CASCADE`, so a pad row cannot be deleted while any of them exist — deletion requires an ordered multi-table transaction and a decision about receipts (see 2.6). |
| **Principle check [P1]** | **(b) and (c) take their trigger from expiry or age, which is exactly the silent conversion P1 forbids** — they would turn a stored write deadline into a destruction permission for pads created before the decision existed. If deletion is chosen, it needs a distinct, explicit basis: a separate retention field with its own default, or an explicit delete request from the write-key holder. **[C] Options (b)/(c) as written are ruled out by P1.** |
| **Decision [C]** | Whether deletion is wanted at all, and if so its trigger (**on a basis other than the existing `expires_at`**) and what a reader sees afterwards. **[C] Do not implement before this is answered.** |

### 2.6 Payment-redemption record retention

| | |
|---|---|
| **Current [S]** | `payment_receipts` rows are never deleted. `tx_hash` is the PK and the replay-prevention key. |
| **Options** | **(a)** Keep receipts indefinitely (unbounded, small rows). **(b)** Retain receipts for a defined window and prune older ones. **(c)** Keep the key but relocate it to a compact `redeemed_tx_hashes` table, pruning the richer detail. |
| **Compatibility / cost** | (a) unbounded growth of a table whose purpose is exactly replay prevention. (b)/(c) shrink the replay window: a tx hash older than the window becomes redeemable again. **[C]** The replay window must be at least as long as any challenge/authorization expiry plus the chain-reorg horizon of the settlement network, or an old proof becomes reusable. **[U]** That horizon is not established here and needs its own evidence. |
| **Principle check [P2]** | Receipt retention is governed by the settlement network's replay horizon and any authorization/challenge expiry — **never** by payload lifetime. **[C] Deleting payloads must not delete or shorten receipts.** |
| **Decision [C]** | The required replay window, on evidence rather than convenience. **[C] Receipts must not be purged merely because payloads expired — the two have unrelated lifetimes and the receipt is what stops a second redemption.** |

### 2.7 Backup retention implications

| | |
|---|---|
| **Current [S]** | The operator holds host-side backups (`/root/padlockspace-backup-*.tar.gz`, `/root/padlockspace-prev-*`) and the Docker volume `agent-locker_locker-data` mounted at `/data`. All of these contain the SQLite database, hence payload bytes. |
| **Options** | **(a)** Backups keep full history; deletion inside the DB does not propagate. **(b)** A defined backup retention window, with deletion applied to backups too. **(c)** Encrypt backups so retained copies are not casually readable. |
| **Compatibility / cost** | (b) requires operator-run work on the host — outside the local authorization of this work order. (c) changes the recovery procedure. **[C] Any "payloads are deleted after N days" claim is false while backups containing those payloads are retained**; the honest phrasing must name the backup boundary. |
| **Decision [C]** | Whether backups count as in-scope for retention, and who performs the host-side work. **[U]** Current backup retention policy is unknown to me. |

---

## 3. The named questions

### 3.1 `read_once` is not "once" — rename and migration

**[S]** The implemented semantics are a **time-bounded read lease**: the first read
opens a window, and further reads inside it are permitted. **[C]** The name
`read_once` therefore misdescribes the behaviour, and a caller who reads the name
rather than the docs will implement the wrong retry strategy — the exact class of
claim-vs-reality drift this work order exists to remove.

Options:

- **(a) Rename with an alias.** Introduce `read_lease` as the value; accept
  `read_once` on input (mapped to `read_lease`), return the canonical name, keep
  reading legacy rows. Compatibility: old clients keep working; responses change
  from `read_once` to `read_lease`, which is a **breaking change for anything
  string-matching the type field**.
- **(b) Keep the name, fix the docs.** No compatibility risk; the misnomer stays in
  the API surface permanently.
- **(c) Rename hard.** Cleanest surface, breaks every existing caller and the
  site's wording at once.

**[C]** Rows already store `'read_once'` and the column has a `CHECK` constraint, so
(a) or (c) require a schema/migration decision — a `CHECK` constraint cannot be
altered in place in SQLite without a table rebuild. **[U]** The migration path is
not designed here.

**[C] Decision required:** which option, and whether the site's wording changes in
the same release or after it.

### 3.2 Minting tickets for expired pads

**[S]** `POST /v1/pads/{id}/tickets` calls neither `expire_pad_if_needed` nor any
state check. A write-key holder can mint a ticket for an expired **or** sealed pad,
and since reads ignore state (2.2), such a ticket works.

Options: **(a)** leave it (a ticket is a capability, not a statement about the pad);
**(b)** reject minting once `expires_at` has passed; **(c)** allow minting but mark
the ticket as expired-pad so reads refuse it.

**[C] Decision required.** Note the interaction: if 2.2 option (b) or (c) is chosen,
(c) here becomes necessary for consistency; otherwise the two disagree.

### 3.3 Expiry and revocation for unlimited tickets

**[S]** `read_unlimited` currently never expires and cannot be revoked — it is a
permanent capability against the pad, bounded only by the pad's readability.
Options: **(a)** keep permanent (document it as permanent); **(b)** absolute expiry,
configurable at mint time; **(c)** revocable (2.4(a)) without expiry; **(d)** both.

**[C] Decision required.** This is the single highest-consequence lifecycle
question: an unlimited ticket on a pad that (for any reason) becomes readable again
is a permanent read capability, and there is currently no way to withdraw it.
**[P2]** Whichever is chosen must be *explicit and enforceable* — a ticket lifetime
that is permanent only because nothing checks it is not a stated lifetime.

### 3.4 Limits for deployments permitting writes

**[S]** Absent entirely: no pad-count cap, no total-storage cap, no request rate
limit, no `429`. The hosted instance is read-only today, so this is latent — it
becomes live the moment a write-enabled deployment is exposed.

Options: **(a)** per-IP rate limits at the proxy layer (Caddy) — cheapest, but
requires the trusted-proxy decision in §4; **(b)** per-write-key pad-count and
storage quotas enforced in the daemon; **(c)** a global storage ceiling with
`503`/`507` when reached; **(d)** a combination.

**[C] Decision required:** which limits, at which layer, and what the failure
response should be. **[C]** A limit that cannot be hit is not a control — whatever
is chosen must be tested by actually hitting it.

---

## 4. Rate limits and trusted proxies

**[S]** Nothing in the daemon reads `X-Forwarded-For` or `Forwarded`, and no proxy
is declared trusted. The public path is Caddy → loopback daemon.

**[C]** Before any forwarded address is used for rate limiting, all of the following
must hold, or the limit is trivially bypassable by a client setting its own header:

1. The daemon binds only to loopback (already true on the hosted instance).
2. Every request reaching the daemon comes from the proxy — a direct-to-daemon
   request must be impossible, or it must be treated as untrusted.
3. The proxy is configured to **overwrite** (not append to) the client-supplied
   `X-Forwarded-For`, so a forged value cannot survive.
4. The trust decision is a fixed list, not "trust the header".

**[C]** Failing 1–3, the safe default is to rate-limit **per socket peer** and
accept that all traffic behind the proxy shares one bucket — a coarse but
non-spoofable limit.

---

## 5. What must not be assumed

- **[C] No deletion promise exists**, in either direction. Nothing is deleted today,
  and nothing written here commits to deleting anything later.
- **[C]** Deletion inside the SQLite database does **not** remove bytes from: the
  WAL file, free pages in the database file, host backups, or the Docker volume.
  Under WAL, a truthful "payload is gone" claim would additionally require
  `VACUUM` (and, for physical media, more than that). **[U]** This is stated as a
  constraint on phrasing, not as a solved problem.
- **[C]** `foreign_keys = ON` means pad deletion is an **ordered** operation across
  `blocks`, `tickets` and `payment_receipts`, not a single `DELETE`.
- **[C]** Receipts must outlive payloads. Any future cleanup of receipts needs its
  own replay-window demonstration **before** it is implemented; until then, the
  safe action is none.
- **[U]** Nothing here has been validated against a write-enabled deployment,
  because none exists yet.

---

## 6. Decisions requested

1. **Sealing.** Does `sealed` mean permanent? (2.1)
2. **Reads after expiry.** Should an expired pad remain readable? (2.2)
3. **Read lease.** Is 600 s the intended global window? (2.3)
4. **Ticket naming.** Rename `read_once` with an alias, keep it, or break it? (3.1)
5. **Ticket revocation.** Needed before release? Per-ticket or pad-level? (2.4)
6. **Unlimited tickets.** Permanent, expiring, revocable, or both? (3.3)
7. **Deletion.** Wanted at all? Trigger, and what a reader sees afterwards. (2.5)
8. **Receipt retention.** Required replay window, and the evidence for it. (2.6)
9. **Backups.** In scope for retention, and who runs the host-side work. (2.7)
10. **Limits.** Which, at which layer, with what failure response. (3.4, §4)

**[C]** Implementation of anything ambiguous or destructive stops here until these
are answered. Nothing in Phase 4 has been implemented.
