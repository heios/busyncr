# Handoff — next dev session

Written 2026-07-11 at the owner's request. Orientation for a fresh agent;
everything of substance lives in repo artifacts — this file only points and
prioritizes. Delete/refresh it when the state moves on.

## Where things stand

- `main` is pushed and green as of the reorg commits (docs move, backlog,
  waycharting). Read first: `AGENTS.md` (rules + hard gates), then
  `issues/README.md` (backlog conventions), then
  `docs/waycharting/README.md` (wayfinder map conventions for this repo).
- All documentation lives under `docs/` (PRD, SLICES frozen v1 record,
  FR-*, ROADMAP, CHANGELOG, adr/).
- Two active planning tracks:
  1. **Daemon service + live monitor** — wayfinder map at
     `docs/waycharting/daemon-service-and-live-monitor/map.md`, 7 decision
     tickets, none resolved yet. Owner scope decisions are baked into the
     map's Notes (daemon-only service, FR-Q1 global quota pulled forward,
     live monitoring required).
  2. **Packed store layout / sub-256K** — pre-charter: agreed directions
     in `docs/ROADMAP.md` R8, reasoning + do-not-relitigate list in
     `docs/waycharting/packed-store-layout/notes.md`, real-workload bench
     data in `2026-07-11-documents-bench.md` alongside it. Do not charter
     the map until the extended bench rerun exists.
- Implementation backlog: issues 00001–00006 (all bench-chunking
  evolution). 00004 is HITL and nearly resolved (format locked; see its
  "Still open" list). The rest are AFK.

## Recommended plan for the next session

Priority order (rationale: the bench rerun gates the chunk-size decision,
which gates the owner's first production backup):

1. **Implement issue 00001** (bench JSON history + `--json` path
   semantics) — unblocked, sonnet-tier, self-contained. Test-first per the
   issue's spec; hard gates before commit.
2. **Then 00003** (sub-256K candidates) and **00006** (progress + timing)
   — both unblocked and independent; 00006 matters because the owner's
   next real run is ~494 GiB and must show progress.
3. **Then 00002 and 00005** (blocked by 00001's payload shape).
4. If the owner is present and prefers design over implementation: grill
   **ticket 01 (admin channel)** on the daemon-service map — it is the
   keystone blocking tickets 04 and 06 there — and/or run **ticket 02
   (service mechanics)** as background research. One map ticket per
   session, per wayfinder rules.

After 00001–00006 land, the owner reruns bench on the Windows box
(`--sizes 64K,...,4M --baseline ... --baseline-age <gap>`); that data
closes the chunk-size decision and seeds the packed-store map charter.

## Cautions

- Chunk size freezes at first production backup; 16B ID truncation is
  parked, decide-before-first-backup only (ROADMAP R8). Don't relitigate
  owner decisions listed in `packed-store-layout/notes.md`.
- `docs/SLICES.md` and `docs/PRD.md` are frozen (AGENTS.md); PRD
  amendments belong to map ticket 07's spec-assembly step.
- Push only at the owner's request (AGENTS.md); pushing triggers CI.

## Suggested skills

- `/tdd` — for issues 00001/00002/00003/00005/00006 (each carries a
  test-first spec; red before green).
- `/wayfinder` — to work a map ticket; conventions in
  `docs/waycharting/README.md` (repo-specific, overrides `.scratch/`).
- `/grilling` + `/domain-modeling` — for HITL map tickets 01/03/04/05 and
  the 00004 final sign-off.
- `/research` — for map ticket 02 (service mechanics, AFK).
- `/prototype` — for map ticket 06 (monitor screen mock).
- `/code-review` — before any push of implementation work.
