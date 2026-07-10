# BusyNCR — Functionality Request FR-Q1: Store disk quota + tail pruning

Status: **Requested** (2026-07-10)
Scheduling: **post-v0.1.0** (explicitly excluded from the v0.1.0 release; roadmap R7)
Depends on: retention grid + prune/GC (S9), daemon status (FR-M1)

## 1. Problem

The daemon store grows without bound: the retention grid thins snapshot
*density* but its oldest tier (≥ 16 d, one per 16 d) retains forever. An
operator must be able to cap the store's disk footprint and have the daemon
enforce it by shedding the oldest history.

## 2. Behavior

- **Q1.1** Daemon config: `store_quota_bytes` (optional; absent = unlimited,
  current behavior). Human-friendly units accepted (`500G`, `2T`).
- **Q1.2** Accounting: quota is compared against the store's real footprint —
  live chunk bytes on disk + index + manifests (measured, not estimated).
- **Q1.3** Enforcement — **tail pruning**: when footprint > quota, drop
  snapshots strictly oldest-first (the tail of history, beyond what the
  retention grid already dropped), then GC, repeating until under quota or
  the safety floor is hit.
- **Q1.4** Safety floor: never drop the most recent `min_snapshots` (config,
  default 8 — one day of 3-hourly history). If the quota cannot be met
  without violating the floor, the daemon keeps the floor, logs loudly, and
  reports over-quota status; it never deletes its way to zero and never
  refuses incoming backups silently.
- **Q1.5** Trigger points: after each completed backup, after each prune
  (auto or manual, cf. FR-M1 M1.2), and daily. Manual command:
  `busyncr-daemon enforce-quota --store <dir>`.
- **Q1.6** Observability: `busyncr-daemon status` (FR-M1 M3.2) gains
  footprint vs quota, headroom, last enforcement (time, snapshots dropped,
  bytes reclaimed), and over-quota flag. Every enforcement logs which
  snapshots were dropped and why.
- **Q1.7** Zero-knowledge unchanged: quota logic sees only sizes and
  timestamps — no client keys, no plaintext.

## 3. Acceptance criteria

- **FR-Q1a** Simulated long history exceeding quota: enforcement drops
  exactly the oldest snapshots needed (deterministic given sizes), footprint
  ends ≤ quota, all survivors restore byte-exact.
- **FR-Q1b** Safety floor: quota smaller than `min_snapshots` worth of data
  ⇒ floor retained, over-quota status reported, no further deletion, backups
  still accepted.
- **FR-Q1c** Interplay: grid prune + quota enforcement compose (grid first,
  tail-shed second); GC reclaims the shed chunks; refcounts stay consistent
  under a concurrent backup (grace-period machinery from S9 reused).
- **FR-Q1d** No quota configured ⇒ behavior identical to v0.1.0 (regression
  guard).

## 4. Out of scope

- Per-client quotas on a shared daemon (single backup-set model for now).
- Quota for the WebDAV replica — that is R1's own quota mode (ROADMAP), which
  shares the newest-first packing idea but runs against the replica, not the
  primary store.
