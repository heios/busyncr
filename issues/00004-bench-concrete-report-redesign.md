# 00004 — bench-chunking: concrete-terms report (grill format, then spec)

- Type: HITL
- Priority: 3
- Tier: opus

## Why

The current table reports raw metrics (chunks, dedup ratio, index/manifest
sizes) and leaves the operator to derive what they actually decide on.
Owner request (2026-07-11): the report should tell the story in concrete
terms — how big an update is, how much space steady state allocates per
candidate size, and how long syncs take at given network speeds. Format
needs a grilling pass before implementation is specced.

## Question to resolve (HITL — grill + prototype mock tables)

1. **Inputs the estimates need:**
   - `--baseline-age <duration>` (e.g. `14d`, `3w`): the wall-clock gap
     between the baseline copy and the current tree. Without it, overlap%
     cannot be normalized to a churn *rate*; with it, per-backup-interval
     update size is `(1 − overlap) × unique_bytes` scaled from the gap to
     the backup interval (linear-churn assumption, stated in the output).
     Decide: required with `--baseline`, or optional with a loud
     "unnormalized" caveat? Prompt interactively when missing, or
     flag-only (script safety)?
   - `--net-mbps` already exists for the single-size `--compression` mode
     (CPU floor + bandwidth points, default 50,200,1000) — generalize to
     the main multi-candidate table? Same defaults?
   - Backup interval (default 3h, PRD §3.5) and retained-snapshot count
     (default N = 36 grid occupancy) — reuse existing knobs.
2. **The derived rows/columns**, per candidate size:
   - initial full backup: bytes to ship + time at CPU floor and per net
     speed;
   - per-backup update: bytes (churn-normalized) + time per net speed;
   - steady-state store footprint at the retention grid's occupancy
     (model: unique_bytes + churn rate integrated over the grid's
     retained-age spans — model choice is part of the grilling);
   - bookkeeping (existing projection) folded in or kept separate?
3. **Presentation**: one story-table with raw metrics demoted to a
   secondary section / `--verbose`? Per-candidate block vs one row per
   candidate? How does the recommendation line change when the story
   columns exist (e.g. "256K: +1.2 GiB bookkeeping buys −47 GiB store and
   −35 GiB per-update vs 4M")?
4. Compression interplay: measured figures are pre-compression unless
   `--compression` ran; decide how the story table labels that
   (understated sizes note vs requiring a compression pass).

## Resolution

Grill with the owner over 2–3 mock tables rendered from the real
C:\DOCUMENTS numbers (the 2026-07-11 run). Lock the format, then file the
AFK implementation slice with exact rendering + model formulas; that slice
Blocked-by: 00001, 00002, 00003 (payload shape, churn fields, and small
sizes all feed it).

## Decisions (grill round 1, 2026-07-11)

1. **`--baseline-age` is required whenever `--baseline` is given** —
   refuse to run without it; estimates are always rate-normalized, never
   silently wrong. Duration syntax like `14d` / `3w`.
2. **Steady state → growth milestones.** Per candidate size: time to
   reach 125 / 150 / 175 / 200 / 250 / 300 / 400 / 500 % of the dataset
   size. Milestone sizes are printed in absolute units rounded to **two
   significant digits** (e.g. 617.4 GiB → "620 GiB") to keep reading
   simple. Model: linear accumulation from the churn rate (an upper
   bound — grid thinning reclaims some; state the assumption in output).
3. **Raw metrics table demoted to `--verbose`** — the story table is the
   default output. Additionally: the report must be **re-renderable from
   a saved JSON** (`--render <report.json>` re-prints story and/or verbose
   tables with no dataset walk) — pairs with 00001's always-on history.
4. **Network speed columns: 50, 100, 200, 1000, 10000 Mbps** (new
   `--net-mbps` default, shared with the compression mode).

Mock as agreed (real numbers, 14 d baseline age assumed):

```text
 target   ── first backup ─────────────────────────   ── each update (3 h) ─────────────
          ships     50M     100M    200M   1G    10G   ships     50M    200M   1G    10G
   256K   399 GiB   19.0h   9.5h   4.8h   57m   5.7m   679 MiB   1.9m   28s   5.7s  0.6s
     4M   446 GiB   21.3h  10.7h   5.3h   64m   6.4m   982 MiB   2.7m   41s   8.2s  0.8s

 store growth (time to reach % of dataset, linear churn from 14 d baseline)
 target   125%      150%     175%     200%     250%     300%     400%     500%
          620 GiB   740 GiB  860 GiB  990 GiB  1.2 TiB  1.5 TiB  2.0 TiB  2.5 TiB
   256K   41 d      63 d     85 d     3.6 mo   5.1 mo   6.6 mo   9.7 mo   12.7 mo
     4M   22 d      37 d     53 d     2.3 mo   3.3 mo   4.4 mo   6.5 mo   8.6 mo
```

## Still open (next grill round)

- ~~Compression labeling~~ — resolved 2026-07-11 by 00005: story figures
  carry sampled compression estimates labeled `est.` by default (always-on
  Monte-Carlo sampling), upgraded to `measured` for sizes covered by a
  precise multi-size `--compression` pass.
- Final sign-off on column layout once 64K/128K rows exist from a real
  rerun (00003) — 8 milestone columns × 7 candidates must stay readable.
- Exact model formulas written down for the implementation slice.

## Scope (exact)

- Touch (at implementation, filed separately after this grilling):
  `crates/busyncr-client/src/bench_cmd.rs`, `crates/busyncr-core/src/bench.rs`,
  `crates/busyncr-client/tests/fr10_bench_chunking_cli.rs`
- Out of scope: changing what is measured (only what is derived and shown);
  scheduling/retention defaults.

## Done when

- [ ] Format locked with the owner (mock table linked or embedded here)
- [ ] Estimation model written down (formulas + stated assumptions)
- [ ] AFK implementation issue filed with test-first spec

## Blocked by

- none (grilling can start now; the implementation slice it spawns will be
  blocked by 00001, 00002, 00003)
