# NNNNN — Short imperative title

> Filename: `issues/NNNNN-kebab-title.md` — 5-digit zero-padded issue number.

- Type: AFK
- Priority: 3
- Tier: sonnet

> Type: `AFK` (agent works it) or `HITL` (human only — a loop skips it).
> Priority: 1 critical bugfix · 2 dev infra/review finding · 3 feature slice · 4 polish · 5 refactor.
> Tier: haiku | sonnet | opus — assigned at planning time; route by complexity
> (ambiguous/integration-heavy → opus), and slice smaller before going bigger.
> Optional: `- Runtime: host` when the issue needs Docker/service-manager/network a sandbox lacks.
> Delete these blockquote notes when filling the template.

## Why

One short paragraph: the user-visible problem or goal. Link docs/PRD.md
sections, FR docs, ADRs, or the wayfinder map decision that spawned this.

## Scope (exact)

> `Touch:` paths are claims, not law: verify each path exists (one `ls`)
> before filing. A worker who finds a divergence records the correction in
> the issue file as part of close.

- Touch: `crates/<x>/src/<y>.rs`
- Out of scope: anything not listed above; name known temptations explicitly.

## Test-first spec

Name the failing test(s) to write first — file, test name, what each asserts.
Acceptance-relevant tests follow the `fr<N>_<description>` naming rule
(AGENTS.md). Sketch the skeleton when the arrange step isn't obvious:

```rust
// crates/<x>/tests/<feature>.rs
#[test]
fn frs1_daemon_service_survives_restart() {
    // arrange: ...
    // act: ...
    // assert: ...
}
```

## Steps

1. Write the failing test(s) above; run the scoped test to see red.
2. Implement the smallest change in the Scope files to go green.
3. `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.

## Done when

> A tick that claims an environment or scope of evidence ("both runtimes",
> "on windows-latest", "on N fixtures") must carry the evidence inline, e.g.
> `[x] ... (linux: 189/0; windows CI: run #142 green)`. A bare tick on a
> multi-environment claim is treated as unticked by review.

- [ ] Observable behavior X (mirrors the test assertions)
- [ ] Hard gates green from repo root, no new suppressions

## Blocked by

- none
