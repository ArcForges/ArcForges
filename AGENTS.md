# Agent instructions: ArcForges

This repository implements the ArcForges node, CLI, MCP adapter, hook handler and Desktop.
[ArcForges-Design](https://github.com/ArcForges/ArcForges-Design) is the product authority;
[Plan](https://github.com/ArcForges/Plan) governs delivery. Read the Plan's
[AGENTS.md](https://github.com/ArcForges/Plan/blob/main/AGENTS.md),
[execution-policy.md](https://github.com/ArcForges/Plan/blob/main/execution-policy.md) and
[delivery-procedure.md](https://github.com/ArcForges/Plan/blob/main/delivery-procedure.md) before
any change. They are binding; this file summarizes them and adds the repository rules.

## 1. Serial delivery

- One Plan task at a time, and only inside a range the user authorized with the Plan's
  execution prompt. Work only on the active task, within its write scope.
- One delegated worker or reviewer at a time, Opus 5.5 only, never Haiku.
- Work in a worktree, `.worktree/<task-id>` on branch `task/<task-id>`, never in the main checkout.
- Delegates work locally only. The coordinator alone pushes, opens PRs, posts review records,
  merges at the reviewed head and updates the Plan's records.
- Build vertically: each task's user-visible outcome works end to end. Behaviour that no task
  specifies is a new task proposal, not part of the change.

## 2. Verification responsibilities (distinct evidence only)

| Role | Runs |
|---|---|
| Author | Targeted and affected tests, affected real Windows and WSL2 Debian tests, build, format, analyzers and Native AOT publish of affected components. Records exact commands and results in the PR. |
| Reviewer (one, after the author) | Full diff review at the exact head against the design references and acceptance criteria; re-runs only doubted tests, changed scripts or workflows, or real-environment tests the author could not run. |
| Hosted CI | The merge gate: build, analyzers, format, tests, AOT publish per RID, size gates, packaging, security scans. |

- Tests follow [16-testing-strategy](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/16-testing-strategy.md).
  Fakes are allowed only where the task's `fakes_allowed` lists them, never for the behaviour under test.
- Real-world validation that cannot run now goes to the Plan's acceptance register and is never
  reported as proven.

## 3. Standing constraints

- Never read or print secrets; no credentials in files, logs or prompts.
- No proxy or network changes; no installs by agents (installs are the user's); reuse installed
  toolchains and caches.
- No macOS, device, GUI, browser, live-service or inference CI. Desktop UI tests are Avalonia headless.
- WSL2 distribution `Debian` for Linux tests (worktree under `/mnt/c`). Never use `ArcForgesTest`
  for development tests; it is reserved for installation and restart tests. No SSH.
- Never touch Dependabot PRs, never enable auto-merge, never change repository security settings.
- Diagnose before rerunning; bounded backoff; read CI through the PR tools, never by polling loops.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; PR bodies
  end with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

## 4. Repository rules

- **Layout** (architecture 01 §5): `src/` shipped projects, `tools/` (`ArcForges.TestLoad`,
  `ArcForges.Bench`), `tests/` (16 §4), `eng/` scripts and policy. Add a project only when its task
  fills it; no placeholder behaviour.
- **Executables** (AD-0003): `arcforges` (`src/ArcForges.Host`, multi-role node/CLI),
  `arcforges-desktop` (`src/ArcForges.Desktop`), plus the tools `arcforges-testload` and
  `arcforges-bench`. Names must stay distinct on case-insensitive file systems.
- **Build policy:** `Directory.Build.props` references DesktopPlatform's build-only
  `ArcForges.Build.Policy` (`PrivateAssets="all"`): C# 14, nullable, deterministic,
  warnings-as-errors, analyzers (`latest-recommended`), central exact versions and locked
  restores. `Directory.Build.targets` makes every `src/` and `tools/` executable Native AOT with
  trim and AOT warnings as errors.
- **Packages:** versions only in `Directory.Packages.props`; commit every `packages.lock.json`;
  every package needs an entry in `eng/policy/dependency-admissions.json` (the repository tests
  check versions, lock hashes and the never-admit list). First-party packages only at versions
  whose publishing commit is an ancestor of the producer's main; never Build.Policy
  `1.0.0-ci.124.1` or Contracts `1.0.0-ci.350.1`.
- **Native AOT:** zero warnings on every RID: win-x64, win-arm64, linux-x64 and linux-arm64
  (`eng/publish.ps1` fails on any warning). On Windows the MSVC linker comes from the Visual Studio
  developer environment (`Launch-VsDevShell.ps1`); Linux targets are published in WSL Debian
  (clang and zlib). linux-arm64 links only on an arm64 host or with an arm64 sysroot (hosted CI).
- **Tests:** select suites by trait with `eng/test.ps1` or `eng/test.sh` (`-List` / `--list`
  shows suites and task kinds; definitions in `eng/test-suites.conf`). Real-OS tests carry
  `env=windows-real|linux-real|wsl-bridge` and skip with a reason elsewhere; tool-dependent tests
  carry `tool=...` and skip with a reason when the tool is missing.
- **Workloads and benchmarks:** `arcforges-testload` (cpu, mem-ramp, output, fork) is a
  deterministic synthetic workload, not a fake; evidence names the scenario and parameters.
  `arcforges-bench` (size, startup, compare-startup, store-growth) produces the JSON results of
  15-performance-targets. CI gates sizes and node store growth, and gates startup against the previous successful main
  run (`eng/compare-startup.ps1`): the statistic is the p50 of 50 runs, and a regression must
  exceed both 25% and an absolute noise floor of 5 ms. Without a baseline, the result passes
  with its reason. On the workstation, check the absolute targets with `eng/bench.ps1 -StartupP50Ms`.
- Avalonia build telemetry is off repository-wide: `Directory.Build.targets` replaces the
  `AvaloniaStats` target of the transitive Avalonia.BuildServices package (a repository test keeps
  it). CI and the `eng/` scripts also set `AVALONIA_TELEMETRY_OPTOUT=1`; keep it set in your shell.
- Keep the CI check names stable: `Native (<rid>)` for win-x64, win-arm64, linux-x64 and
  linux-arm64, `Verify`, `Workflow lint`, `Secret scan`,
  `Dependency review`, `CodeQL (csharp)`, `CodeQL (actions)`.
