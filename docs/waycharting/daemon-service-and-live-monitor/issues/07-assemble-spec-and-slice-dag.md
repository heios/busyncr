# 07 — Assemble the spec: FR docs, PRD amendment, slice DAG

- Type: task
- Status: open
- Blocked by: 01, 02, 03, 04, 05, 06

## Question

Fold every decision on this map into the repo's normative docs and file the
implementation backlog — the destination artifact:

1. Write **FR-S1** (daemon as a background service: Windows SCM, macOS
   LaunchDaemon, Linux systemd documentation, `service` subcommand surface,
   quickstart) and **FR-M2** (live monitor/admin channel: transport, auth,
   data model, control operations incl. set-quota and store relocation) in
   `docs/`, following the FR-M1/FR-Q1 house style with acceptance criteria.
2. Amend **docs/PRD.md** §6 (macOS launchd out-of-scope line no longer
   holds for the daemon) and §3.6, bumping the status line the way v1.1–v1.3
   did; update **docs/FR-Q1.md** scheduling + **docs/ROADMAP.md** R7.
3. Slice both features into **vertical tracer-bullet issues** filed as
   `issues/NNNNN-*.md` per issues/README.md conventions (Type/Priority/Tier
   headers, test-first specs, evidence-bearing done-whens, Blocked-by
   edges), starting from 00001.
4. Close this map: every ticket resolved or ruled out of scope, Decisions
   so far complete, fog either graduated or explicitly left for a future
   effort.
