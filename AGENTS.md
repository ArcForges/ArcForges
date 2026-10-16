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
  `arcforges-supervisor.exe` (`src/ArcForges.Supervisor`, Windows only, GUI subsystem),
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
  shows suites and task kinds; definitions in `eng/test-suites.conf`). The scripts run up to `-Parallel` / `--parallel` test
  projects at once (default: half the logical processors, at least 2; each project's log in `artifacts/test-logs/`); `-Repeat` /
  `--repeat N` reruns the selected suites until the first failing iteration. Tests run in parallel inside their projects too, each
  with its own node, platform, data root, endpoint and slice; never add a serial collection. A timing-, CPU-share- or memory-sensitive
  test, or one that changes machine-wide state, carries `isolation=exclusive` and `DisableParallelization = true`; the parallel suites
  leave it out and the `exclusive` suite runs it alone afterwards (`-Suite ci,exclusive`). Real-OS tests carry
  `env=windows-real|linux-real|wsl-bridge` and skip with a reason elsewhere; tool-dependent tests
  carry `tool=...` and skip with a reason when the tool is missing. Closed-loop tests (`loop=local`)
  run real `arcforges` processes (JIT next to the tests, or `ARCFORGES_HOST_PATH`), each node isolated with
  `--test-mode` and the `ARCFORGES_ENDPOINT` / `ARCFORGES_CONFIG_DIR` hooks; their fixture fails a test that leaves a
  node or supervisor of its own environment (its endpoint, or on Linux its slice) running and deletes the node data key it created in
  the OS secret store. On Linux each test node gets its
  own slice `arcforges-test-<id>.slice` (`ARCFORGES_SLICE`) and the fixtures stop its units, slice and test units and fail on anything
  left running (the shared parent slices stay); a test that freezes a unit must thaw it before it is killed (the user manager blocks spawning into a frozen cgroup). On Windows a
  shell inside a job without breakaway (an AI-client sandbox) refuses auto-start by design, so the auto-start
  test skips there with its reason.
- **Workloads and benchmarks:** `arcforges-testload` (cpu, mem-ramp, output, fork) is a
  deterministic synthetic workload, not a fake; evidence names the scenario and parameters.
  `arcforges-bench` (size, startup, compare-startup, store-growth) produces the JSON results of
  15-performance-targets. CI gates sizes and node store growth, and gates the CLI cold start (`arcforges --version`)
  against the previous successful main run (`eng/compare-startup.ps1`) on the same runner: main-push runs upload their
  CLI (`startup-host-<rid>-<sha>`), and a run downloads the previous main run's CLI and measures it and its own CLI
  interleaved (alternating runs, same warm-up and count; never a p50 recorded on another VM). The statistic is the p50
  of 50 runs, and a regression must exceed both 25% and an absolute noise floor of 5 ms. The baseline is the newest of
  the last 20 successful main-push runs with the CLI artifact, and the download must match the artifact's SHA-256 digest;
  only when none of them has one (the first main run after the change) does the result pass, with the runs checked in its
  reason. Other API failures fail the step; the token never reaches the benchmark or the measured CLIs.
  Locally, `eng/compare-startup.ps1 -RuntimeIdentifier <rid> -BaselineExecutable <main build>` runs the same comparison.
  On the workstation, check the absolute targets with `eng/bench.ps1 -StartupP50Ms 40 -StartupP95Ms 80`;
  the status round trip is the `category=perf` test `StatusRoundTrip` with `ARCFORGES_HOST_PATH` set.
- Avalonia build telemetry is off repository-wide: `Directory.Build.targets` replaces the
  `AvaloniaStats` target of the transitive Avalonia.BuildServices package (a repository test keeps
  it). CI and the `eng/` scripts also set `AVALONIA_TELEMETRY_OPTOUT=1`; keep it set in your shell.
- Keep the CI check names stable: `Native (<rid>)` for win-x64, win-arm64, linux-x64 and
  linux-arm64, `Verify`, `Workflow lint`, `Secret scan`,
  `Dependency review`, `CodeQL (csharp)`, `CodeQL (actions)`.
