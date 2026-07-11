# Issues — BusyNCR backlog

Issue conventions adopted from the agentic-harness framework (we are not
running its AFK loop here yet, but the backlog is shaped so we can). One
file per issue, `NNNNN-kebab-title.md`, 5-digit zero-padded, monotonically
increasing. Done = moved to `issues/done/` (`git mv issues/NNNNN-*.md
issues/done/`).

Historical note: the v1 build (S0–S13, K1, C1–C4, M1) was tracked in
docs/SLICES.md, which stays frozen as the build record. New work — starting
with the daemon-service + live-monitor effort — is filed here instead.
Upstream of this backlog, foggy efforts are charted first as wayfinder maps
under `docs/waycharting/<effort>/` (map + decision tickets); implementation issues
land here once a map has made them specifiable.

## Headers

Each issue starts with:

- `Type:` `AFK` (an agent works it unattended) or `HITL` (human in the
  loop — an autonomous loop must skip it).
- `Priority:` 1 critical bugfix · 2 dev infra/review finding · 3 feature
  slice · 4 polish · 5 refactor.
- `Tier:` haiku | sonnet | opus — assigned at planning time; route by
  complexity (ambiguous/integration-heavy → opus), and slice smaller before
  going bigger.
- Optional `Runtime: host` when the issue needs something a sandbox lacks
  (Docker, real Windows/macOS service manager, network).

## Slicing

Every issue is a **vertical slice**: a thin but complete path through every
layer, demoable/verifiable on its own. The first slice connects the ends
(possibly against a fake); later slices thicken it. No horizontal-layer
issues ("build all the models", "then all the handlers"). Each issue must be
a near-executable spec — the thinking happens at filing time; the
implementer should mostly be making a named test pass.

## Evidence conventions

Two rules, mechanical enough for a fresh reviewer to apply without judgment
calls:

- **`Touch:` paths are claims, not law.** The filer verifies each path
  exists (one `ls`) before filing; a worker who finds a divergence records
  the correction in the issue file as part of close.
- **Done-when ticks are evidence-bearing.** A tick that claims an
  environment or scope of evidence ("both runtimes", "on windows-latest",
  "on N fixtures") must carry the evidence inline, e.g.
  `[x] ... (linux: 189/0; windows CI: run #142 green)`. A bare tick on a
  multi-environment claim is treated as unticked by review.

## Gate

An issue is not done until the repo hard gates pass from the root
(AGENTS.md): `cargo fmt --all --check`, `cargo clippy --workspace
--all-targets -- -D warnings`, `cargo test --workspace`.
