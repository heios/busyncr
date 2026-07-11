# Coding standards

## Commit messages

- **Each commit is the next agent's/developer's only memory of this work.**
  Write the message to carry three things: (1) key decisions made and why,
  briefly; (2) what changed — files touched or moved; (3) blockers or notes
  for whoever picks this up next. Reference the tracking slice/FR (e.g.
  `S13: ...`, `FR-M1: ...` — see SLICES.md and the FR-*.md specs). One
  logical task per commit — don't bundle unrelated changes just because they
  landed in the same session.
  (Decided 2026-07-10 16:54Z.)

## Commit attribution

- **AI commits use `Generated-by:` trailers, never `Co-Authored-By`.** Every
  commit written with AI assistance carries one
  `Generated-by: <provider>:<model-id>` trailer per model that contributed to
  it — `<model-id>` is the resolved model id, lowercased and hyphenated (e.g.
  `anthropic:claude-opus-4-8`), never a display name like `Claude Opus 4.8`.
  Work that spanned tiers lists one line each. The human maintainer remains the
  sole author identity — the model is credited in the trailer, not as a
  co-author — so the public author line stays human.
