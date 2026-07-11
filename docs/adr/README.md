# Architecture Decision Records

One record per pivotal, hard-to-reverse decision — the kind that shapes the
on-disk format, the protocol, or the threat model and would be expensive to
walk back. Numbered `NNNN-slug.md`, titled `# NNNN — Title`, with a
`Status:`/`Date:` header.

PRD.md and the `FR-*.md` functionality requests remain the founding spec;
ADRs record the cross-cutting decisions behind them and any made after they
were frozen. Extended rationale from external research (papers, other
projects' approaches) belongs in the ADR's `## Research` section with
sources — research spend is reusable.

- [0001](0001-blake3-chunk-identity.md) — BLAKE3 for chunk identity and
  integrity
