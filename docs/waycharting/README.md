# Waycharting — wayfinder maps for this repo

This repo's wayfinding artifacts live **here**, not in `.scratch/` (owner
decision 2026-07-11, overriding the local-markdown tracker default): maps
are committed, shared planning state, and "scratch" misread as disposable.

## Wayfinding operations (repo-specific)

Used by `/wayfinder`. Same conventions as the local-markdown tracker,
relocated:

- **Map**: `docs/waycharting/<effort>/map.md` — Destination / Notes /
  Decisions-so-far / Not-yet-specified / Out-of-scope body.
- **Child ticket**: `docs/waycharting/<effort>/issues/NN-<slug>.md`,
  numbered from `01`, question in the body. `Type:` line records the
  ticket type (`research`/`prototype`/`grilling`/`task`); `Status:` line
  records `open`/`claimed`/`resolved`.
- **Blocking**: a `Blocked by: NN, NN` line near the top. A ticket is
  unblocked when every ticket it lists is `resolved`.
- **Frontier**: scan the effort's `issues/` for files that are open,
  unblocked, and unclaimed; first by number wins.
- **Claim**: set `Status: claimed` and save before any work.
- **Resolve**: append the answer under an `## Answer` heading, set
  `Status: resolved`, then append a context pointer (gist + link) to the
  map's Decisions-so-far.

Implementation issues that come out of a resolved map are filed in the
top-level `issues/` backlog (see `issues/README.md`) — decision tickets
stay here; build slices go there.

## Efforts

- `daemon-service-and-live-monitor/` — daemon as a background service
  (Windows/macOS/Linux) + live monitor/admin channel. Charted 2026-07-11.
- `packed-store-layout/` — pre-charter seed notes + real-workload bench
  data for the R8 packed store / sub-256K effort. Not yet a map.
