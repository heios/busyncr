# BusyNCR — Functionality Request FR-M1: CLI monitoring + explicit manual/auto control

Status: **Requested** (2026-07-10)
Scheduling: **phase 2b** — after FR-K1/FR-C1 slices, before REQUIREMENTS.md and the v0.1.0 tag
Target: client/daemon CLI UX; resolves the PRD §3.5 auto-prune deviation explicitly

## 1. Manual vs automatic control (make current behavior deliberate)

- **M1.1** Manual one-shot backup (`busyncr-client backup`) and opt-in
  scheduling (`run` / Windows service) are the *documented contract*, not an
  accident: README gets a "manual vs scheduled operation" subsection.
- **M1.2** Retention autoprune becomes an explicit daemon config
  (`auto_prune = true|false`, default **true** to match PRD §3.5: apply the
  grid after each completed backup and on a daily timer). `false` = grid is
  applied only when the operator runs `busyncr-daemon prune` manually.
  Manual `prune`/`gc` remain available in both modes. Status log must record
  which mode produced each prune.

## 2. Progress reporting (client)

- **M2.1** `backup` and `restore` report live progress to **stderr**:
  files walked, chunks hashed, chunks to ship / shipped, bytes up/down,
  running MB/s, and a coarse ETA from the running rate. Plain
  one-line-per-interval output when stderr is not a TTY (log-safe);
  carriage-return updating line when it is. No new heavy deps — hand-rolled;
  `--quiet` suppresses, `--json-progress` emits NDJSON events for scripting.
- **M2.2** Progress must not distort FR3 accounting: counters come from the
  same byte-accounting used by tests.

## 3. Status subcommands (monitoring)

- **M3.1** `busyncr-client status --state <dir> [--config <toml>]`: enrollment
  identity (name, cert fingerprint, daemon URL), committed chunk size,
  last-backup record (snapshot id, time, files, bytes shipped, duration —
  persisted to the state dir by every backup/run/service iteration), and,
  when the daemon is reachable, the last N snapshots for the set.
- **M3.2** `busyncr-daemon status --store <dir>`: snapshots count (+ per
  enrolled client), unique chunks, store bytes on disk, zero-ref chunks
  awaiting gc, last prune/gc time and mode (auto|manual), CA fingerprint.
  Read-only; safe while `serve` runs.
- **M3.3** Both support `--json`.

## 4. Acceptance criteria

- **FR-M1a** `auto_prune = true`: completed backup triggers a prune whose
  surviving set equals `retention::plan` output (reuses FR5 machinery);
  `auto_prune = false`: no prune occurs without the manual command (asserted
  over a simulated multi-backup run).
- **FR-M1b** Progress events during a real backup sum exactly to the final
  FR3 byte-accounting figures; `--quiet` emits nothing on stderr besides
  errors; NDJSON events parse and are monotone.
- **FR-M1c** `client status` after a backup shows that backup's record;
  `daemon status` figures match store ground truth (asserted against direct
  store inspection in a test).
- **FR-M1d** v1 + phase-2 regression stays green.

## 5. Out of scope

- Web/remote monitoring UI (ROADMAP R5), metrics endpoints/Prometheus,
  notifications. This FR is CLI-local visibility only.
