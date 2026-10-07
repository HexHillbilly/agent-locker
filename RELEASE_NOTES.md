# Release notes

Point-in-time observations about deployed instances. These are dated snapshots,
not standing facts — re-observe before relying on them. Deployment state is
deliberately kept out of the installation instructions in `README.md` because it
goes stale faster than the code does.

## 2026-10-07 — hosted instance trails the source revision

Observed while reconciling release state (Phase S1). Recorded as an observation,[S]
not a supported configuration.

| Surface | Observed | Note |
|---------|----------|------|
| `https://api.padlockspace.org/health` | `200`, `version 0.1.0`, payload uses `active_pads` | responding |
| `https://api.padlockspace.org/openapi.json` | 6 routes, **no** `/v1/pads/{pad_id}/tickets` | predates the ticket endpoint in this tree |
| `https://api.padlockspace.org/v1/pads/demo-pad-v1/blocks` | `200` (no ticket required) | demo pad is served |
| `POST .../demo-pad-v1/append` with `demo-write-key` | **`401`** | source revision returns **`409 Conflict`** (verified locally) |
| `https://padlockspace.org/` | `404`, zero-length body, `server: Caddy` | static site is **not** deployed |
| `www.padlockspace.org` | does not resolve | no DNS record observed |
| `POST /v1/pads` documented responses | `201`, `422` only — no `402` | hosted build consistent with `LOCKER_MODE=open`; payment rail not evidenced as enabled |

Consequences, stated plainly:

- The hosted revision **does not match this source tree** and does not expose the
  ticket endpoint. Do not describe the hosted service as matching HEAD.
- The `demo-write-key` → `409` behaviour documented in `README.md` is correct for
  **this revision**; the live host returns `401` because it is older. That is a
  deployment gap, not a documentation error.
- The `llms.txt` served by the host advertises the ticket endpoint and the `409`
  behaviour; both are ahead of what that host actually runs.

No redeployment was performed or authorised in this phase.
