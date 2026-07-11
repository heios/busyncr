# Map — Daemon as a service + live monitor

Label: wayfinder:map · Charted: 2026-07-11 · Owner: Alexander

## Destination

A locked spec, ready to slice: (1) **busyncr-daemon runs as a supervised
background service** on Windows and macOS (documented supervision on Linux),
with an operator quickstart; (2) a **live monitor/admin interface** that
works against a *running* daemon and covers: enrolled clients, per-client
disk attribution, store footprint vs the global quota (FR-Q1 pulled
forward), last client activity and its outcome, prune/GC stats, quota
setting, and store relocation. The map is done when the FR docs + PRD
amendment are written and the implementation issues are filed in `issues/`
— nothing left to decide before an agent can build it.

## Notes

- Skills: HITL tickets run via /grilling + /domain-modeling; research
  tickets via /research; the monitor mock via /prototype;
  /design-an-interface is a fit for the admin-channel ticket.
- Standing scope decisions (owner, charting session 2026-07-11):
  - The **daemon** is the service; clients keep starting backups manually —
    client-as-a-service is explicitly later.
  - "Quotas" = **FR-Q1 global store quota, pulled forward** from
    post-v0.1.0. Per-client remains visibility-only.
  - **Live monitoring is a hard requirement** — inspecting a stopped store
    is not enough for the first production run.
- Load before any ticket: docs/PRD.md (§3.6, §6), docs/FR-M1.md (the
  existing offline status commands), docs/FR-Q1.md (quota spec),
  AGENTS.md (dependency palette — new deps need justification).
- Two constraints every monitor decision must respect: the **redb store is
  exclusive-lock** (a second process cannot read while `serve` runs — this
  is why the admin channel exists), and the **daemon is zero-knowledge**
  (encrypted manifests; it sees chunk IDs, sizes, refcounts, and
  snapshot→client attribution only).

## Decisions so far

<!-- one line per closed ticket: gist + link -->

(none yet)

## Not yet specified

- Quickstart placement and depth (README section vs docs/ operator guide) —
  follows the service-surface decision in
  [Service mechanics for busyncr-daemon on Windows, macOS, Linux](issues/02-service-mechanics-win-macos-linux.md).
- CI gates for daemon-service install/start/stop smoke tests on
  windows-latest / macos-latest — shape depends on the same ticket.
- In-place upgrade story for a running daemon service (binary swap, store
  format compatibility across versions) — too dim to ticket until the
  service mechanics are decided.
- Alerting when the store goes over-quota or a client goes silent — may
  graduate after the monitor data model settles, or be ruled out to R5.

## Out of scope

- busyncr-client as a service (Windows scheduling exists; macOS launchd
  agent, auto-scheduled clients) — owner call at charting: "service for
  that is for later".
- Web/remote monitoring UI, Prometheus/metrics endpoints, notifications —
  ROADMAP R5 / FR-M1 §5 boundary holds; this effort is CLI-local.
- Per-client quotas — FR-Q1 §4 boundary holds (single backup-set model).
- Replication of any kind (WebDAV R1, multi-daemon R3) — "storage moving"
  in this effort means local store relocation, not a second copy.
