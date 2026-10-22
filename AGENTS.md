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
| Author | Targeted and affected tests, affected real Windows and real Linux tests, build, format, analyzers and Native AOT publish of affected components. Records exact commands and results in the PR. |
| Reviewer (one, after the author) | Full diff review at the exact head against the design references and acceptance criteria; re-runs only doubted tests, changed scripts or workflows, or real-environment tests the author could not run. |
| Host verification after the push (the merge gate of every PR) | The CI-equivalent profile of every pushed head: a Windows leg on native Windows and a Linux leg on a real Linux host, each reported as a required commit status, `arcforges/windows` and `arcforges/linux` ([§5](#5-verification-after-the-push-ad-0020)). The statuses at the head plus the review are the merge gate; hosted validation is skipped for the owner's (`deku2026`) PRs. |
| Hosted CI (external PRs, ARM64, weekly security) | The merge gate of PRs by anyone else (Dependabot included), the merge queue and manual dispatch: build, analyzers, format, tests, AOT publish on win-x64, win-arm64, linux-x64 and linux-arm64, size and startup gates, packaging, workflow lint, secret scan, dependency review, CodeQL. CodeQL and the secret scan also run weekly. Push to main runs nothing. |

- Tests follow [16-testing-strategy](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/16-testing-strategy.md).
  Fakes are allowed only where the task's `fakes_allowed` lists them, never for the behaviour under test.
- Real-world validation that cannot run now goes to the Plan's acceptance register and is never
  reported as proven.

## 3. Standing constraints

- Never read or print secrets; no credentials in files, logs or prompts.
- No proxy or network changes; no installs by agents (installs are the user's); reuse installed
  toolchains and caches.
- No macOS, device, GUI, browser, live-service or inference CI. Desktop UI tests are Avalonia headless.
- Linux tests run on the Linux MCP host, through the Linux MCP server (the Linux leg, [§5](#5-verification-after-the-push-ad-0020);
  [AD-0019](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0019-mcp-first-verification.md)). Local WSL is never used for development or verification, not even as a fallback, and need
  not be installed; no WSL distribution, `ArcForgesTest` included, is a test venue. No SSH.
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
  developer environment (`Launch-VsDevShell.ps1`); Linux targets are published on Linux
  (clang and zlib). linux-arm64 links only on an arm64 host or with an arm64 sysroot (hosted CI).
- **Tests:** select suites by trait with `eng/test.ps1` or `eng/test.sh` (`-List` / `--list`
  shows suites and task kinds; definitions in `eng/test-suites.conf`). The scripts run up to `-Parallel` / `--parallel` test
  projects at once (default 2, measured: the longest project bounds the run; each project's log in `artifacts/test-logs/`); `-Repeat` /
  `--repeat N` reruns the selected suites until the first failing iteration. Tests run in parallel inside their projects too, each
  with its own node, platform, data root, endpoint and slice; never add a serial collection. A timing-, CPU-share- or memory-sensitive
  test, or one that changes machine-wide state, carries `isolation=exclusive` and `DisableParallelization = true`; the parallel suites
  leave it out and the `exclusive` suite runs it alone afterwards (`-Suite ci,exclusive`). Real-OS tests carry
  `env=windows-real|linux-real` and skip with a reason elsewhere (the Linux leg's `linux-real-os` step makes sure they
  do not skip there); tool-dependent tests
  carry `tool=...` and skip with a reason when the tool is missing. Closed-loop tests (`loop=local`)
  run real `arcforges` processes (JIT next to the tests, or `ARCFORGES_HOST_PATH`), each node isolated with
  `--test-mode` and the `ARCFORGES_ENDPOINT` / `ARCFORGES_CONFIG_DIR` hooks; their fixture fails a test that leaves a
  node or supervisor of its own environment (its endpoint, or on Linux its slice) running and deletes the node data key it created in
  its data root's isolated secret store, then verifies its absence. On Linux each test node gets its
  own slice `arcforges-test-<id>.slice` (`ARCFORGES_SLICE`) and the fixtures stop its units, slice and test units and fail on anything
  left running (the shared parent slices stay); a test that freezes a unit must thaw it before it is killed (the user manager blocks spawning into a frozen cgroup). On Windows a
  shell inside a job without breakaway (an AI-client sandbox) refuses auto-start by design, so the auto-start
  test skips there with its reason.
- **OS secret stores (16-testing-strategy sections 1-2; the user's decisions of 2026-10-17).** Routine tests, the host verification and
  the deep tier never reach the real Windows Credential Manager or Secret Service. Tests use `tests/Shared/IsolatedSecretStore.cs`
  (in memory, scripted faults); nodes started with `--test-mode` and `arcforges-bench` keep keys in the file-backed store under
  their data root (`NodeSecretStores`, the only production source that names the OS selection). The guard: every test project sets
  the AppContext switch `ArcForges.Security.Secrets.DenyOsStores` (`tests/Directory.Build.props`), so the adapters refuse before
  any OS call; `eng/test.ps1`/`eng/test.sh` remove a stray `ARCFORGES_OS_SECRET_STORE_TESTS`, `eng/verify_steps.py` refuses to
  run with it, and `ArcForges.Repository.Tests` (`OsSecretStoreGuardPolicyTests`) checks sources, `--test-mode`, the tier's
  isolation and every runtime configuration. The OS secret-store tier (`tests/ArcForges.OsSecretStoreTier`: one sequential
  write, read, overwrite, delete and absence cycle of the node data key, at most 4 entries, 32 calls, 10 s per call, 5 minutes,
  exact-name cleanup from its name list) runs only in `.github/workflows/os-secret-store-tier.yml` (external PRs, merge queue,
  dispatch, weekly; the opt-in on its test step only) or, on the user's explicit opt-in, through `eng/os_secret_store_tier.py`.
  Agents never set the opt-in, never run the tier and never stress an OS store.
- **Workloads and benchmarks:** `arcforges-testload` (cpu, mem-ramp, output, fork) is a
  deterministic synthetic workload, not a fake; evidence names the scenario and parameters.
  `arcforges-bench` (size, startup, compare-startup, store-growth) produces the JSON results of
  15-performance-targets. The verification (the host verification, and hosted CI for external PRs) gates sizes and node store growth,
  and gates the CLI cold start (`arcforges --version`) against the base commit's CLI built on the same machine
  (`eng/compare-startup.ps1 -RuntimeIdentifier <rid> -BaselineExecutable <base host>`): the host verification builds the merge base
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
  dispatch (CodeQL and the secret scan also weekly) and show as skipped on the owner's PRs. No status check is required on this
  repository. `Verify` requires every `Native (<rid>)` job, not the Security jobs or code scanning's separate `CodeQL`
  alert check: an external PR merges only when none of them is failing.

## 5. Verification after the push (AD-0020)

Every PR into `main` is verified after the push, on the two verification hosts, and gated by GitHub
([AD-0016](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0016-local-first-verification.md) as amended by
[AD-0020](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0020-post-push-verification-and-required-checks.md)). The flow: Push → Fetch → Local verification → Report status → Required checks → Review → Merge.
The cross-repository rules are the Plan [AGENTS.md](https://github.com/ArcForges/Plan/blob/main/AGENTS.md) rules 6 and 7.

- **Push** the branch to GitHub; nothing is verified before a push and there is no pre-push hook.
  `python eng/verify.py install`, once per clone from the main checkout on `main`, removes the retired pre-push hook
  (and any `core.hooksPath`).
- **Two legs on two hosts** ([AD-0019](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0019-mcp-first-verification.md)).
  - Each step runs on one host: `win` (native Windows) or `linux` (native Linux). `eng/verify.py` runs only the leg of
    the host's own operating system, never through WSL or a remote shell.
  - The Windows leg runs on the Windows 11 workstation, through the Windows MCP server.
  - The Linux leg runs on the Linux MCP host, through the Linux MCP server. That host has a systemd user manager with
    cpu, memory and pids delegated on cgroups v2, which the leg's first step, `linux-real-os`, checks. An agent's own
    sandbox, such as the Claude Code Cloud container, has no user manager, so this repository's Linux leg fails there
    by design.
  - Both are standard MCP servers that Claude Code and Codex share; their client configuration and credentials stay
    outside this repository. Local WSL is never a venue, not even as a fallback.
- **Fetch and verify on each host.** In the host's clone, fetch the pushed commit from GitHub and run the command in a
  worktree at it:

  ```
  git fetch origin <branch>
  git worktree add --detach .worktree/verify-<sha> <sha>
  cd .worktree/verify-<sha>
  python eng/verify.py run-and-report
  cd ../.. && git worktree remove --force .worktree/verify-<sha>
  ```

  For a pull request from a fork, read the diff first, then fetch `refs/pull/<n>/head`.
- **Report status.** Each host reports the commit status `arcforges/windows` or `arcforges/linux` on that exact
  commit:
  - `pending` when it starts;
  - `success` only when every step of its leg ran and passed. For a `docs` change, which has no Windows steps, Windows
    reports success saying so;
  - `failure` when a step failed, `error` when the leg could not complete.

  The command exits 0 after success, 1 when a step failed and 2 when the leg could not complete or be reported. The host
  reports with `ARCFORGES_STATUS_TOKEN` when set (a token limited to commit statuses), otherwise with its own `gh`
  login. Steps never see either; never print them.
- **Required checks.** The `main` ruleset requires both statuses for every PR, with no bypass actors, and the branch must
  be up to date with `main`; every new push needs verifying again on both hosts. The hosted `Verify` check of external
  PRs is unchanged ([§4](#4-repository-rules)).
- **Stop rule** (AD-0019 §5). If the Linux (or Windows) MCP server is unavailable, unreachable or its host lacks a
  prerequisite, stop and report the exact failure: the status stays missing and the PR cannot merge. Never skip, mock
  or weaken a step, or run the leg on another host (local WSL or an agent's own sandbox included).
- `python eng/verify.py list` shows the profile and each host's steps for `HEAD`. `python eng/verify.py run` runs this
  host's leg of `HEAD` without reporting.
- **What runs.** The commit, never the working tree: on Windows in `.worktree/_verify` of the main checkout, on Linux in
  `~/.cache/arcforges-verify/ArcForges`, both checked out at the commit; ignored build output stays, so builds are
  incremental. The steps are in `eng/verify_steps.py`.
  - `full` profile, lanes concurrently: `win` (locked restore, Release build with analyzers as errors, the `ci` suite,
    the store schema check, Native AOT publish of host, supervisor, desktop, testload and bench for win-x64 with zero
    warnings in the Visual Studio developer environment, the `tools` suite against the native TestLoad and Bench, the
    `closed-loop` suite against the native host, `eng/bench.ps1`, `eng/package.ps1`); `linux` (`linux-real-os`, then the
    same for linux-x64, plus `dotnet format --verify-no-changes`, once, where hosted CI runs it); `win-base` and
    `linux-base` (the merge base's Native AOT host in `.worktree/_verify-base` and
    `~/.cache/arcforges-verify/ArcForges-base`, rebuilt only when the merge base changed); `scan` (the pinned gitleaks
    image over the commits since the merge base with `.gitleaksignore`, in Docker on the Linux host without network); `actionlint` when `.github/workflows/**` changed. Then, alone: the `exclusive` suite on the JIT
    build and against the native host, on Windows and on Linux, and the startup gate per platform against the merge
    base's host.
  - `docs` profile, when every changed path is Markdown outside `src/`, `tests/`, `tools/`, `eng/` and `.github/`
    (and not `THIRD_PARTY_NOTICES.md`, which the desktop ships): the secret scan.
  - The Linux host needs no PowerShell: `eng/verify_linux.py` does there what `eng/publish.ps1`, `bench.ps1`,
    `compare-startup.ps1` and `package.ps1` do; keep them in step. The `tool=pwsh` tests run on Windows only.
  - Not reproduced: CodeQL (external PRs and weekly) and dependency review (external PRs), GitHub services; win-arm64
    and linux-arm64 (removed from the owner path by the user's instruction; a manual `workflow_dispatch` runs them).
- **Prerequisites** (installs are the user's):
  - **Windows:** the .NET SDK selected by `global.json`, PowerShell 7, Python, and Visual Studio with the MSVC x64 tools.
  - **Linux host:** the same .NET SDK, clang and zlib, Python (`python` on PATH), a systemd user manager with cpu, memory
    and pids delegated on cgroups v2, and Docker with the pinned gitleaks image.
  - **Both:** `gh` with a credential that can write commit statuses, and network access to GitHub and NuGet (and once to
    the actionlint release).
- **Failures.** A failed, timed-out or unrunnable step reports `failure` and prints:
  - the step;
  - the last log lines;
  - the log path, `<git common dir>/arcforges-verify/logs/<time>-<sha>-<host>/<step>.log`, with `summary.json` (every
    step's result and duration) beside it.

  The test projects' own logs are in the verification checkout's `artifacts/test-logs/`. Read the log, fix the cause,
  push, and verify again.
- **Statuses and rulesets.** A status is reported only by `python eng/verify.py run-and-report` on the host it names, at
  the commit it verified. Never post, edit or copy an `arcforges/*` status by hand, and never change the ruleset or
  required checks to get a PR merged.
- AI agents must never use `git push --no-verify` to bypass required validation.
- They must also never disable, remove, modify, or otherwise circumvent the hooks or required checks merely to get a
  change through.
- If validation fails, investigate and fix the underlying issue.
- If a required local test cannot run, do not silently skip it or claim successful verification.
- Changing `eng/verify*.py`, `.githooks/` or the ruleset as reviewed engineering work is allowed; changing them to get a
  change through is not.

## 6. Efficient execution

The Plan's rule 7 applies. In this repository:

- Restore once (`dotnet restore ArcForges.slnx --locked-mode`) and build once
  (`dotnet build ArcForges.slnx -c Release --no-restore`); then run tests with `-NoBuild` / `--no-build`.
- While iterating, run the affected suites: `./eng/test.ps1 -Kind <kind> -NoBuild` or `-Suite <name>`
  (`eng/test.sh --kind <kind> --no-build` on Linux; `-List` shows kinds and suites). `-Parallel` (default 2,
  measured) runs test projects concurrently; never lower it without a measurement. Run the `exclusive` suite when you
  change an exclusive test or the code it covers; `-Repeat <n>` is the deep tier's stress and flake hunt.
- Format only the changed files: `dotnet format ArcForges.slnx --include <files> --no-restore`.
- Publish only the changed component with Native AOT: `./eng/publish.ps1 -RuntimeIdentifier win-x64 -Component <name>
  -NoRestore` in the Visual Studio developer environment, `python eng/verify_linux.py publish <name>` on Linux.
- The full profile runs once per pushed head, on each host (§5); `python eng/verify.py run` checks a leg before handover
  without reporting.
- Reviewers add a worktree to the existing clone (`git worktree add .worktree/<key> <sha>`) and re-run only distinct
  evidence; a head whose required statuses passed is not verified again in full.
