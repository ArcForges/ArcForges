# CLAUDE.md

Instructions for Claude Code in this repository live in **[AGENTS.md](AGENTS.md)** — read it first and follow
it. It covers the product family, the frozen architecture invariants, repository layout, conventions, and the
build/verify commands.

A few reminders that matter most here:

- Work in a Git worktree under `.worktree/` (gitignored), one focused branch/PR per change, and touch only the
  scope your change owns.
- Prefer the built-in tools; do **not** add tracked `.ps1`/`.sh` helper scripts (enforced by
  `RepositoryPolicyTests`). Keep build inputs declarative in `.props`/`.targets`.
- Run the verification loop in [AGENTS.md](AGENTS.md#build-and-verify) before committing, and state results
  honestly — do not claim a build, test, or publish passed without the real command output.
