# 06 — Monitor interface mock: one screen of daemon truth

- Type: prototype
- Status: open
- Blocked by: 01, 03

## Question

Given the admin channel (ticket 01) and the data model (ticket 03), mock
the operator-facing output to react to — cheap text mocks via /prototype,
no daemon code:

1. The **one-glance screen**: store summary (footprint vs quota gauge,
   chunks, zero-ref, last prune/gc) + per-client table (name, last seen,
   last snapshot + outcome, unique/referenced bytes, revoked flag). Where
   does it live — `busyncr-daemon status` grown live, or a new
   `monitor`/`top` subcommand?
2. **One-shot vs watch** — is a refreshing watch mode (interval re-render,
   FR-M1 M2.1 TTY conventions) in v1, or is `watch -n5 'busyncr-daemon
   status'` good enough because the output is stable?
3. **`--json` parity** (FR-M1 M3.3 precedent) — same payload shape for
   scripting; NDJSON only if watch mode exists.
4. React with the owner: what's missing / what's noise for controlling the
   first production run — the final trim of "reasonable depth".

Link the chosen mock as an asset; the agreed screen becomes normative in
ticket 07's FR doc.
