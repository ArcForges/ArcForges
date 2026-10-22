# SPDX-License-Identifier: AGPL-3.0-only
"""Local verification steps of ArcForges, loaded by eng/verify.py (which injects `Step`).

The full profile is what the hosted `Native (win-x64)` and `Native (linux-x64)` jobs of .github/workflows/ci.yml and the
`Workflow lint` and `Secret scan` jobs of .github/workflows/security.yml verify, in two legs on two native machines after the push,
reported as the commit statuses arcforges/windows and arcforges/linux (eng/verify.py; AGENTS.md section 5): the Windows leg on the Windows 11 workstation, the Linux leg on a real Linux host:
- lane `win` (Windows, in <main checkout>/.worktree/_verify): locked restore, Release build with analyzers as errors,
  the ci suite, the store schema check, Native AOT publish of every win-x64 component with zero warnings (in the Visual
  Studio developer environment), the tools suite against the native TestLoad and Bench, the closed-loop suite against
  the native host, the size and store-growth gates, packaging.
- lane `linux` (Linux, in ~/.cache/arcforges-verify/ArcForges): first `linux-real-os`, which fails unless a systemd user
  manager runs for the user with cpu, memory and pids delegated on cgroups v2 (the linux-real, closed-loop and exclusive
  tests skip with a reason without them, so a Linux leg on a machine without them would pass without the real tests;
  it must fail instead), then the same as lane `win` for linux-x64, plus the format check, which runs once, here, as
  hosted CI runs it on linux-x64.
- lanes `win-base` and `linux-base`: the Native AOT host of the merge base, for the startup gate, in
  <main checkout>/.worktree/_verify-base and ~/.cache/arcforges-verify/ArcForges-base; rebuilt only when the merge base
  changed since the last run.
- exclusive phase, alone after every lane: the exclusive suite on the JIT build and against the native host (as hosted
  CI runs it twice), on Windows and on Linux, then the startup regression gate per platform: the merge base's CLI and this
  commit's CLI measured here interleaved (p50 of 50 runs; a regression exceeds both 25 % and 5 ms).
- lane `scan`: gitleaks over the pushed range ({range}) with the pinned image digest and .gitleaksignore, in Docker on
  the Linux host without network and with a read-only mount of the verification clone.
- lane `actionlint`: only when .github/workflows/** changed.

Differences from the hosted jobs:
- The Linux host needs no PowerShell: eng/verify_linux.py does for linux-x64 what eng/publish.ps1, bench.ps1,
  compare-startup.ps1 and package.ps1 do there; the Windows lane runs the scripts themselves. The `tool=pwsh` tests
  (eng/compare-startup.ps1) therefore run on Windows only.
- The startup gate's baseline is the merge base with main built here, where external-PR CI builds the PR's base commit
  on its runner.
- `CI` is not set: on this repository it only turns on locked restores, which every restore here requests explicitly,
  and deterministic source paths.
- Not reproduced: CodeQL (external PRs and the weekly schedule) and dependency review (external PRs), GitHub services;
  win-arm64 and linux-arm64 (removed from the owner path by the user's instruction), the artifact uploads.
Only Markdown outside the code, test, tool, script and workflow directories (and not THIRD_PARTY_NOTICES.md, which the
desktop publish ships) selects the `docs` profile: the secret scan alone.
No step runs the OS secret-store tier, and the verification refuses to run at all while the tier's opt-in is set (below);
eng/test.ps1 and eng/test.sh also remove it for every suite they run.
"""

import os

# The single opt-in of the OS secret-store integration tier (ArcForges-Design 16-testing-strategy section 1). Only the tier's runner
# (eng/os_secret_store_tier.py) and its hosted job set it; the host verification refuses to run while it is present, so a stray
# value can never reach a routine suite.
OS_SECRET_STORE_OPT_IN = "ARCFORGES_OS_SECRET_STORE_TESTS"
if OS_SECRET_STORE_OPT_IN in os.environ:
    raise SystemExit(
        f"arcforges-verify: FAIL {OS_SECRET_STORE_OPT_IN} is set in this environment. It is the opt-in of the OS secret-store "
        "integration tier, which only that tier's runner or hosted job sets, and the host verification refuses to run with it "
        f"(routine suites never reach a real OS secret store). Remove it (PowerShell: Remove-Item Env:{OS_SECRET_STORE_OPT_IN}; "
        f"bash: unset {OS_SECRET_STORE_OPT_IN}) and run again.")

REPOSITORY = "ArcForges"
RID_WIN, RID_LINUX = "win-x64", "linux-x64"

# The Visual Studio developer environment for the MSVC linker (Native AOT on Windows). Launch-VsDevShell puts the
# machine-wide dotnet first on PATH, so the dotnet that was selected before (the user-local SDK root) is put back first.
VSDEV = (
    "$dotnet = Split-Path (Get-Command dotnet).Source; "
    "$installer = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\\Installer'; "
    "$env:PATH = \"$installer;$env:PATH\"; "
    "$vs = & vswhere.exe -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 "
    "-property installationPath; "
    "if (-not $vs) { throw 'Visual Studio with the MSVC x64 tools was not found; Native AOT on Windows needs its linker.' }; "
    "& (Join-Path $vs 'Common7\\Tools\\Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; "
    "$env:PATH = \"$dotnet;$env:PATH\"; "
)

# Tool versions recorded in each leg's summary (the python running eng/verify.py is added by the core).
FINGERPRINT = {
    "win": {
        "dotnet-sdks": ["dotnet", "--list-sdks"],
        "dotnet-runtimes": ["dotnet", "--list-runtimes"],
        "msvc": ["pwsh", "-NoProfile", "-NonInteractive", "-Command", VSDEV + "$env:VCToolsVersion"],
        "pwsh": ["pwsh", "--version"],
    },
    "linux": {
        "dotnet-sdks": "dotnet --list-sdks | tr '\\n' ' '",
        "dotnet-runtimes": "dotnet --list-runtimes | tr '\\n' ' '",
        "clang": "clang --version | head -n 1",
    },
}

# The environment of ci.yml, without CI=true (see above).
ENV = {"DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1", "AVALONIA_TELEMETRY_OPTOUT": "1"}

# Timeouts are five to ten times the cold durations measured on the workstation (18 logical processors, the Windows and
# Linux lanes then ran concurrently on it, fresh verification checkouts), with a floor of five minutes.

# Paths of the merge base's host.
WIN_BASE = "(Join-Path (Split-Path (git rev-parse --path-format=absolute --git-common-dir) -Parent) '.worktree/_verify-base')"
LINUX_BASE = "$HOME/.cache/arcforges-verify/ArcForges-base"
BASE_SOURCE = "merge base {base}, built and measured on this machine"


def pwsh(script: str, devshell: bool = False) -> list[str]:
    return ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference = 'Stop'; " + (VSDEV if devshell else "") + script + "; exit $LASTEXITCODE"]


def tests(*suites: str, native: bool = False) -> list[str]:
    """eng/test.ps1 on the Release build; with native, against the published win-x64 host (ARCFORGES_HOST_PATH)."""
    host = f"$env:ARCFORGES_HOST_PATH = Join-Path $PWD 'artifacts/publish/{RID_WIN}/host/arcforges.exe'; " if native else ""
    return pwsh(f"{host}./eng/test.ps1 -Suite {','.join(suites)} -NoBuild")


def linux_tests(*suites: str, native: bool = False) -> str:
    host = f"export ARCFORGES_HOST_PATH=\"$PWD/artifacts/publish/{RID_LINUX}/host/arcforges\"; " if native else ""
    return f"set -e; {host}bash eng/test.sh --suite {','.join(suites)} --no-build"


# Native AOT publish with zero warnings, in two concurrent groups that share no project (host and bench both build
# ArcForges.Node.Store, so they stay in one group); measured on linux-x64 for a new commit: 85 s in sequence, 56 s in two
# groups. On Windows each group is one eng/publish.ps1 run with its own log; the supervisor is in the host's group, whose
# run copies it beside the host (eng/publish.ps1 copies only in a run that published one of them).
PUBLISH_GROUPS_WIN = ("host,supervisor,bench", "desktop,testload")
PUBLISH_GROUPS_LINUX = ("host,bench", "desktop,testload")
WIN_PUBLISH = (
    "$root = $PWD.Path; "
    f"$results = @({', '.join(repr(group) for group in PUBLISH_GROUPS_WIN)}) | ForEach-Object -ThrottleLimit 2 -Parallel {{ "
    "$log = Join-Path $using:root \"artifacts/publish-$($_.Replace(',', '-')).log\"; "
    "$null = New-Item -ItemType Directory -Force -Path (Split-Path $log); "
    "& pwsh -NoProfile -NonInteractive -Command "
    f"\"Set-Location -LiteralPath '$($using:root)'; ./eng/publish.ps1 -RuntimeIdentifier {RID_WIN} -Component $_ -NoRestore\" *> $log; "
    "[pscustomobject]@{ Group = $_; Exit = $LASTEXITCODE; Log = $log } }; "
    "foreach ($result in $results) { Get-Content -LiteralPath $result.Log | Write-Host; "
    "Write-Host \"==> group $($result.Group): exit $($result.Exit)\" }; "
    "if (@($results | Where-Object Exit -ne 0).Count -gt 0) { throw 'Native AOT publish failed.' }; $global:LASTEXITCODE = 0"
)

# The merge base's host, Native AOT, built in its own persistent checkout with the base's own SDK (global.json) and
# skipped when that checkout already holds the build of this base.
WIN_BASE_HOST = (
    f"$base = {WIN_BASE}; $exe = Join-Path $base 'artifacts/publish/{RID_WIN}/host/arcforges.exe'; "
    "$marker = Join-Path $base 'artifacts/verify-base-sha'; "
    "if (-not (Test-Path (Join-Path $base '.git'))) { git worktree prune; git worktree add --force --detach $base {base}; "
    "if ($LASTEXITCODE) { throw 'git worktree add failed' } } "
    "elseif ((git -C $base rev-parse HEAD) -eq '{base}' -and (Test-Path $exe) -and "
    "((Get-Content -LiteralPath $marker -ErrorAction SilentlyContinue) -eq '{base}')) { "
    "Write-Host \"The host of the merge base {base} is current: $exe\"; exit 0 } "
    "else { git -C $base checkout --force --detach {base}; if ($LASTEXITCODE) { throw 'git checkout failed' }; "
    "git -C $base clean -ffdq; if ($LASTEXITCODE) { throw 'git clean failed' } } "
    "Remove-Item -LiteralPath $marker -ErrorAction SilentlyContinue; Set-Location $base; "
    "dotnet restore src/ArcForges.Host/ArcForges.Host.csproj --locked-mode; if ($LASTEXITCODE) { throw 'restore failed' }; "
    f"dotnet publish src/ArcForges.Host/ArcForges.Host.csproj -c Release -r {RID_WIN} --no-restore -tl:off "
    "-p:IlcUseEnvironmentalTools=true -o (Split-Path $exe); if ($LASTEXITCODE) { throw 'publish failed' }; "
    "Set-Content -LiteralPath $marker -Value '{base}'"
)
LINUX_BASE_HOST = (
    f"set -euo pipefail; b=\"{LINUX_BASE}\"; exe=\"$b/artifacts/publish/{RID_LINUX}/host/arcforges\"; "
    "marker=\"$b/artifacts/verify-base-sha\"; "
    "if [ ! -e \"$b/.git\" ]; then git worktree prune; git worktree add --force --detach \"$b\" {base}; "
    "elif [ \"$(git -C \"$b\" rev-parse HEAD)\" = {base} ] && [ -x \"$exe\" ] && [ \"$(cat \"$marker\" 2>/dev/null)\" = {base} ]; "
    "then echo \"The host of the merge base {base} is current: $exe\"; exit 0; "
    "else git -C \"$b\" checkout -q --force --detach {base}; git -C \"$b\" clean -ffdq; fi; "
    "rm -f \"$marker\"; cd \"$b\"; "
    "dotnet restore src/ArcForges.Host/ArcForges.Host.csproj --locked-mode; "
    f"dotnet publish src/ArcForges.Host/ArcForges.Host.csproj -c Release -r {RID_LINUX} --no-restore -tl:off "
    "-o \"$(dirname \"$exe\")\"; echo {base} > \"$marker\""
)

# security.yml's Secret scan (same pinned image digest, .gitleaksignore and redaction), over the pushed range, without
# network and with a read-only mount of the verification clone.
SECRET_SCAN = (
    "docker run --rm --network none -v \"$PWD:/repo:ro\" "
    "-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo "
    "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f "
    "git /repo --redact=100 --no-banner --verbose --gitleaks-ignore-path /repo/.gitleaksignore "
    "--log-opts=\"--full-history {range}\""
)

# security.yml's Workflow lint: actionlint as pinned there, cached once on the Linux host; the archive is checked on every
# run.
ACTIONLINT = (
    "set -euo pipefail; v=1.7.12; "
    "sum=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8; "
    "d=\"$HOME/.cache/arcforges-verify/tools\"; t=\"$d/actionlint_${v}_linux_amd64.tar.gz\"; mkdir -p \"$d\"; "
    "if [ ! -f \"$t\" ]; then "
    "curl --fail --silent --show-error --location --output \"$t.part\" "
    "\"https://github.com/rhysd/actionlint/releases/download/v${v}/actionlint_${v}_linux_amd64.tar.gz\"; "
    "echo \"$sum  $t.part\" | sha256sum --check --quiet; mv \"$t.part\" \"$t\"; fi; "
    "echo \"$sum  $t\" | sha256sum --check --quiet; "
    "mkdir -p \"$d/actionlint-$v\"; tar -xzf \"$t\" -C \"$d/actionlint-$v\" actionlint; "
    "\"$d/actionlint-$v/actionlint\""
)

CODE = ("src/", "tests/", "tools/", "eng/", ".github/")


def select_profile(changed: list[str]) -> str:
    docs = all(path.endswith(".md") and not path.startswith(CODE) and path != "THIRD_PARTY_NOTICES.md" for path in changed)
    return "docs" if changed and docs else "full"


def workflows_changed(changed: list[str]) -> bool:
    return any(path.startswith(".github/workflows/") for path in changed)


def win(step_id: str, cmd: list[str], timeout: int, **options) -> Step:
    return Step(step_id, "win", cmd, timeout=timeout, env=ENV, **options)


def linux(step_id: str, cmd: str, timeout: int, **options) -> Step:
    return Step(step_id, "linux", cmd, timeout=timeout, env=ENV, **options)


LINUX_BASE_EXE = f"{LINUX_BASE}/artifacts/publish/{RID_LINUX}/host/arcforges"

# The Linux leg's real-OS prerequisites, as tests/Shared/SystemdTestEnvironment.cs reads them (UserManagerAvailable and
# FullyEnforced): without them the linux-real, closed-loop and exclusive tests skip with a reason, so this step fails the
# leg instead of letting it pass without its real tests (AD-0018 section 5).
LINUX_REAL_OS = (
    "set -euo pipefail; uid=$(id -u); "
    "s=\"${XDG_RUNTIME_DIR:-}/systemd/private\"; "
    "if [ -z \"${XDG_RUNTIME_DIR:-}\" ] || [ ! -S \"$s\" ]; then "
    "echo \"No systemd user manager runs for uid $uid (XDG_RUNTIME_DIR='${XDG_RUNTIME_DIR:-}', no $s). The Linux leg needs a "
    "real Linux host with a systemd user manager and cpu, memory and pids delegated on cgroups v2 (AGENTS.md section 5).\" >&2; "
    "exit 1; fi; "
    "if [ ! -x /usr/bin/systemctl ] && [ ! -x /bin/systemctl ]; then echo 'systemctl is not installed.' >&2; exit 1; fi; "
    "c=/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service/cgroup.controllers; "
    "if [ ! -r \"$c\" ]; then echo \"$c is missing: cgroups v2 with a user manager slice is required.\" >&2; exit 1; fi; "
    "have=\" $(cat \"$c\") \"; "
    "for x in cpu memory pids; do case \"$have\" in *\" $x \"*) ;; *) "
    "echo \"The user manager delegates only '$(cat \"$c\")'; cpu, memory and pids are required.\" >&2; exit 1;; esac; done; "
    "echo \"systemd user manager for uid $uid with delegated controllers:$have\"; systemctl --version | head -n 1"
)

STEPS = [
    # ci.yml, Native (win-x64)
    win("win-restore", ["dotnet", "restore", "ArcForges.slnx", "--locked-mode"], 600),
    win("win-build", ["dotnet", "build", "ArcForges.slnx", "-c", "Release", "--no-restore"], 900),
    win("win-ci", tests("ci"), 1200),
    win("win-store-schema", tests("store-schema"), 300),
    win("win-publish", pwsh(WIN_PUBLISH, devshell=True), 900),
    win("win-tools-native", pwsh(
        f"$p = Join-Path $PWD 'artifacts/publish/{RID_WIN}'; "
        "$env:ARCFORGES_TESTLOAD_PATH = Join-Path $p 'testload/arcforges-testload.exe'; "
        "$env:ARCFORGES_BENCH_PATH = Join-Path $p 'bench/arcforges-bench.exe'; "
        "./eng/test.ps1 -Suite tools -NoBuild"), 300),
    win("win-closed-loop-native", tests("closed-loop", native=True), 600),
    win("win-bench", pwsh(f"./eng/bench.ps1 -RuntimeIdentifier {RID_WIN}"), 600),
    win("win-package", pwsh(f"./eng/package.ps1 -RuntimeIdentifier {RID_WIN}"), 300),
    # ci.yml, Native (linux-x64)
    linux("linux-real-os", LINUX_REAL_OS, 60),
    linux("linux-restore", "dotnet restore ArcForges.slnx --locked-mode", 600),
    linux("linux-format", "dotnet format ArcForges.slnx --verify-no-changes --no-restore", 600),
    linux("linux-build", "dotnet build ArcForges.slnx -c Release --no-restore", 900),
    linux("linux-ci", linux_tests("ci"), 1200),
    linux("linux-store-schema", linux_tests("store-schema"), 300),
    linux("linux-publish", f"python eng/verify_linux.py publish {' '.join(PUBLISH_GROUPS_LINUX)}", 900),
    linux("linux-tools-native", f"set -e; export ARCFORGES_TESTLOAD_PATH=\"$PWD/artifacts/publish/{RID_LINUX}/testload/arcforges-testload\" "
        f"ARCFORGES_BENCH_PATH=\"$PWD/artifacts/publish/{RID_LINUX}/bench/arcforges-bench\"; "
        "bash eng/test.sh --suite tools --no-build", 300),
    linux("linux-closed-loop-native", linux_tests("closed-loop", native=True), 600),
    linux("linux-bench", "python eng/verify_linux.py bench", 600),
    linux("linux-package", "python eng/verify_linux.py package", 300),
    # The merge base's host for the startup gate
    win("win-base-host", pwsh(WIN_BASE_HOST, devshell=True), 1200, lane="win-base"),
    linux("linux-base-host", LINUX_BASE_HOST, 1200, lane="linux-base"),
    # security.yml, Secret scan (over the pushed range) and Workflow lint (when a workflow changed)
    linux("secret-scan", SECRET_SCAN, 300, lane="scan", profiles=frozenset({"full", "docs"})),
    linux("actionlint", ACTIONLINT, 300, lane="actionlint", when=workflows_changed),
    # Exclusive phase: timing-, CPU-share- and memory-sensitive tests and the startup gates, alone
    win("win-exclusive", tests("exclusive"), 600, exclusive=True),
    win("win-exclusive-native", tests("exclusive", native=True), 600, exclusive=True),
    linux("linux-exclusive", linux_tests("exclusive"), 600, exclusive=True),
    linux("linux-exclusive-native", linux_tests("exclusive", native=True), 600, exclusive=True),
    win("win-startup-gate", pwsh(
        f"./eng/compare-startup.ps1 -RuntimeIdentifier {RID_WIN} "
        f"-BaselineExecutable (Join-Path {WIN_BASE} 'artifacts/publish/{RID_WIN}/host/arcforges.exe') "
        f"-BaselineSource '{BASE_SOURCE}'"), 300, exclusive=True),
    linux("linux-startup-gate", f"python eng/verify_linux.py compare-startup \"{LINUX_BASE_EXE}\" --baseline-source '{BASE_SOURCE}'",
        300, exclusive=True),
]
