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
| Local verification (pre-push hook, the owner merge gate) | The CI-equivalent profile of every pushed commit on Windows and WSL2 Debian ([§5](#5-local-verification-ad-0016)). For the owner's (`deku2026`) PRs, its `arcforges-verify: PASS` line at the pushed head plus the review is the merge gate; hosted validation is skipped for them. |
| Hosted CI (external PRs, ARM64, weekly security) | The merge gate of PRs by anyone else (Dependabot included), the merge queue and manual dispatch: build, analyzers, format, tests, AOT publish on win-x64, win-arm64, linux-x64 and linux-arm64, size and startup gates, packaging, workflow lint, secret scan, dependency review, CodeQL. The Security workflow also runs weekly. Push to main runs nothing. |

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
- Diagnose before rerunning; bounded backoff; read hosted CI (external PRs) through the PR tools, never by polling loops.
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
  projects at once (default 2, measured: the longest project bounds the run; each project's log in `artifacts/test-logs/`); `-Repeat` /
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
  15-performance-targets. The verification (the hook, or hosted CI for external PRs) gates sizes and node store growth,
  and gates the CLI cold start (`arcforges --version`) against the base commit's CLI built on the same machine
  (`eng/compare-startup.ps1 -RuntimeIdentifier <rid> -BaselineExecutable <base host>`): the hook builds the merge base
  with main, external-PR CI the PR's base commit on its runner; both CLIs are measured there interleaved (alternating
  runs, same warm-up and count; never a p50 recorded on another machine). The statistic is the p50 of 50 runs, and a
  regression must exceed both 25% and an absolute noise floor of 5 ms. A missing baseline fails the gate; no CLI
  artifact is uploaded or downloaded.
  On the workstation, check the absolute targets with `eng/bench.ps1 -StartupP50Ms 40 -StartupP95Ms 80`;
  the status round trip is the `category=perf` test `StatusRoundTrip` with `ARCFORGES_HOST_PATH` set.
- Avalonia build telemetry is off repository-wide: `Directory.Build.targets` replaces the
  `AvaloniaStats` target of the transitive Avalonia.BuildServices package (a repository test keeps
  it). CI and the `eng/` scripts also set `AVALONIA_TELEMETRY_OPTOUT=1`; keep it set in your shell.
- Keep the CI check names stable: `Native (<rid>)` for win-x64, win-arm64, linux-x64 and
  linux-arm64, `Verify`, `Workflow lint`, `Secret scan`,
  `Dependency review`, `CodeQL (csharp)`, `CodeQL (actions)`. They run for external PRs, the merge queue and manual
  dispatch (Security also weekly) and show as skipped on the owner's PRs. No status check is required on this
  repository. `Verify` requires every `Native (<rid>)` job, not the Security jobs or code scanning's separate `CodeQL`
  alert check: an external PR merges only when none of them is failing.

## 5. Local verification (AD-0016)

The owner's PRs are verified by the repository's pre-push hook, not by hosted CI
([AD-0016](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0016-local-first-verification.md)).
The cross-repository rules are the Plan [AGENTS.md](https://github.com/ArcForges/Plan/blob/main/AGENTS.md) rules 6 and 7.

- **Install** once per clone, from the main checkout on `main`: `python eng/verify.py install`. It copies `.githooks/*`
  into the clone's common hooks directory, so every worktree runs them, and removes any `core.hooksPath`. Re-run it
  when `.githooks/` changes.
- `python eng/verify.py list` shows the profile and steps of `HEAD`. `python eng/verify.py run` verifies `HEAD` now; the
  push reuses that pass for the identical tree, step set, scripts and tools (the secret scan also binds it to the exact
  merge base and head).
- **What runs.** Each pushed commit, never the working tree: on Windows in `.worktree/_verify` of the main checkout, in
  WSL Debian in `~/.cache/arcforges-verify/ArcForges`, both checked out at the commit; ignored build output stays, so
  builds are incremental. The steps are in `eng/verify_steps.py`.
  - `full` profile, lanes concurrently: `win` (locked restore, Release build with analyzers as errors, the `ci` suite,
    the store schema check, Native AOT publish of host, supervisor, desktop, testload and bench for win-x64 with zero
    warnings in the Visual Studio developer environment, the `tools` suite against the native TestLoad and Bench, the
    `closed-loop` suite against the native host, `eng/bench.ps1`, `eng/package.ps1`); `wsl` (the same for linux-x64,
    plus `dotnet format --verify-no-changes`, once, where hosted CI runs it); `win-base` and `wsl-base` (the merge base's
    Native AOT host in `.worktree/_verify-base` and `~/.cache/arcforges-verify/ArcForges-base`, rebuilt only when the
    merge base changed); `scan` (the pinned gitleaks image over the pushed range with `.gitleaksignore`, in WSL Docker
    without network); `actionlint` when `.github/workflows/**` changed. Then, alone: the `exclusive` suite on the JIT
    build and against the native host, on Windows and on Linux, and the startup gate per platform against the merge
    base's host.
  - `docs` profile, when every changed path is Markdown outside `src/`, `tests/`, `tools/`, `eng/` and `.github/`
    (and not `THIRD_PARTY_NOTICES.md`, which the desktop ships): the secret scan.
  - WSL Debian has no PowerShell, so `eng/verify_linux.py` does there what `eng/publish.ps1`, `bench.ps1`,
    `compare-startup.ps1` and `package.ps1` do; keep them in step. The `tool=pwsh` tests run on Windows only.
  - Not reproduced: CodeQL and dependency review (GitHub services; external PRs and the weekly schedule), win-arm64
    and linux-arm64 (removed from the owner path by the user's instruction; a manual `workflow_dispatch` runs them).
- **Prerequisites** (installs are the user's): Windows with the .NET SDK selected by `global.json`, PowerShell 7,
  Python and Visual Studio with the MSVC x64 tools; WSL Debian with the same .NET SDK, clang and zlib, Python, the
  systemd user manager, and Docker with the pinned gitleaks image; network access to NuGet (and once to the actionlint
  release).
- **Failures.** A failed, timed-out or unrunnable step rejects the push and prints the step, the last log lines and the
  log path: `<git common dir>/arcforges-verify/logs/<time>-<sha>/<step>.log`, with `summary.json` (every step's result
  and duration) beside it. The test projects' own logs are in the verification checkout's `artifacts/test-logs/`. Read
  the log, fix the cause, push again.
- AI agents must never use `git push --no-verify` to bypass required validation.
- They must also never disable, remove, modify, or otherwise circumvent the hooks merely to allow a push.
- If validation fails, investigate and fix the underlying issue.
- If a required local test cannot run, do not silently skip it or claim successful verification.
- Changing `eng/verify*.py` or `.githooks/` as reviewed engineering work is allowed; changing them to get a push through
  is not.

## 6. Efficient execution

The Plan's rule 7 applies. In this repository:

- Restore once (`dotnet restore ArcForges.slnx --locked-mode`) and build once
  (`dotnet build ArcForges.slnx -c Release --no-restore`); then run tests with `-NoBuild` / `--no-build`.
- While iterating, run the affected suites: `./eng/test.ps1 -Kind <kind> -NoBuild` or `-Suite <name>`
  (`eng/test.sh --kind <kind> --no-build` in WSL Debian; `-List` shows kinds and suites). `-Parallel` (default 2,
  measured) runs test projects concurrently; never lower it without a measurement. Run the `exclusive` suite when you
  change an exclusive test or the code it covers; `-Repeat <n>` is the deep tier's stress and flake hunt.
- Format only the changed files: `dotnet format ArcForges.slnx --include <files> --no-restore`.
- Publish only the changed component with Native AOT: `./eng/publish.ps1 -RuntimeIdentifier win-x64 -Component <name>
  -NoRestore` in the Visual Studio developer environment, `python eng/verify_linux.py publish <name>` in WSL Debian.
- Run the full profile once, with `python eng/verify.py run` before handover; the push reuses its pass.
- Reviewers add a worktree to the existing clone (`git worktree add .worktree/<key> <sha>`) and re-run only distinct
  evidence; a head that already has a PASS record is not verified again in full.
