# SPDX-License-Identifier: AGPL-3.0-only
"""Local verification steps of ArcForges, loaded by eng/verify.py (which injects `Step`).

The full profile is what the hosted `Native (win-x64)` and `Native (linux-x64)` jobs of .github/workflows/ci.yml and the
`Workflow lint` and `Secret scan` jobs of .github/workflows/security.yml verify, on this workstation:
- lane `win` (Windows, in <main checkout>/.worktree/_verify): locked restore, Release build with analyzers as errors,
  the ci suite, the store schema check, Native AOT publish of every win-x64 component with zero warnings (in the Visual
  Studio developer environment), the tools suite against the native TestLoad and Bench, the closed-loop suite against
  the native host, the size and store-growth gates, packaging.
- lane `wsl` (WSL Debian, in ~/.cache/arcforges-verify/ArcForges): the same for linux-x64, plus the format check, which
  runs once, here, as hosted CI runs it on linux-x64 (measured warm: 29 s here against 47 s on Windows, where the win
  lane is the longer one).
- lanes `win-base` and `wsl-base`: the Native AOT host of the merge base, for the startup gate, in
  <main checkout>/.worktree/_verify-base and ~/.cache/arcforges-verify/ArcForges-base; rebuilt only when the merge base
  changed since the last run.
- exclusive phase, alone after every lane: the exclusive suite on the JIT build and against the native host (as hosted
  CI runs it twice), on Windows and on Linux, then the startup regression gate per platform: the merge base's CLI and this
  commit's CLI measured here interleaved (p50 of 50 runs; a regression exceeds both 25 % and 5 ms).
- lane `scan`: gitleaks over the pushed range ({range}) with the pinned image digest and .gitleaksignore, in WSL Docker
  without network and with a read-only mount of the verification clone.
- lane `actionlint`: only when .github/workflows/** changed.

Differences from the hosted jobs:
- WSL Debian has no PowerShell, so eng/verify_linux.py does for linux-x64 what eng/publish.ps1, bench.ps1,
  compare-startup.ps1 and package.ps1 do there; the Windows lane runs the scripts themselves. The `tool=pwsh` tests
  (eng/compare-startup.ps1) therefore run on Windows only.
- The startup gate's baseline is the merge base with main built here, where external-PR CI builds the PR's base commit
  on its runner.
- `CI` is not set: on this repository it only turns on locked restores, which every restore here requests explicitly,
  and deterministic source paths.
- Not reproduced: CodeQL and dependency review (GitHub services; external PRs and the weekly schedule run them),
  win-arm64 and linux-arm64 (removed from the owner path by the user's instruction), the artifact uploads.
Only Markdown outside the code, test, tool, script and workflow directories (and not THIRD_PARTY_NOTICES.md, which the
desktop publish ships) selects the `docs` profile: the secret scan alone.
"""

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

# Tool versions that key a reusable pass (the python running eng/verify.py is added by the core).
FINGERPRINT = {
    "win": {
        "dotnet-sdks": ["dotnet", "--list-sdks"],
        "dotnet-runtimes": ["dotnet", "--list-runtimes"],
        "msvc": ["pwsh", "-NoProfile", "-NonInteractive", "-Command", VSDEV + "$env:VCToolsVersion"],
        "pwsh": ["pwsh", "--version"],
    },
    "wsl": {
        "dotnet-sdks": "dotnet --list-sdks | tr '\\n' ' '",
        "dotnet-runtimes": "dotnet --list-runtimes | tr '\\n' ' '",
        "clang": "clang --version | head -n 1",
    },
}

# The environment of ci.yml, without CI=true (see above).
ENV = {"DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1", "AVALONIA_TELEMETRY_OPTOUT": "1"}

# Timeouts are five to ten times the cold durations measured on this workstation (18 logical processors, Windows and WSL
# lanes concurrently, fresh verification checkouts), with a floor of five minutes.

# Paths of the merge base's host.
WIN_BASE = "(Join-Path (Split-Path (git rev-parse --path-format=absolute --git-common-dir) -Parent) '.worktree/_verify-base')"
WSL_BASE = "$HOME/.cache/arcforges-verify/ArcForges-base"
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
# groups. On Windows each group is one eng/publish.ps1 run with its own log; the supervisor is copied beside the host
# once both have ended, as eng/publish.ps1 does.
PUBLISH_GROUPS_WIN = ("host,bench", "supervisor,desktop,testload")
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
    "if (@($results | Where-Object Exit -ne 0).Count -gt 0) { throw 'Native AOT publish failed.' }; "
    f"$publish = Join-Path $root 'artifacts/publish/{RID_WIN}'; "
    "Copy-Item -LiteralPath (Join-Path $publish 'supervisor/arcforges-supervisor.exe') -Destination (Join-Path $publish 'host') -Force; "
    "Write-Host '==> copied arcforges-supervisor.exe beside arcforges.exe'; $global:LASTEXITCODE = 0"
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
WSL_BASE_HOST = (
    f"set -euo pipefail; b=\"{WSL_BASE}\"; exe=\"$b/artifacts/publish/{RID_LINUX}/host/arcforges\"; "
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

# security.yml's Workflow lint: actionlint as pinned there, cached once in WSL; the archive is checked on every run.
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


def wsl(step_id: str, cmd: str, timeout: int, **options) -> Step:
    return Step(step_id, "wsl", cmd, timeout=timeout, env=ENV, **options)


LINUX_HOST = f"{WSL_BASE}/artifacts/publish/{RID_LINUX}/host/arcforges"

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
    wsl("wsl-restore", "dotnet restore ArcForges.slnx --locked-mode", 600),
    wsl("wsl-format", "dotnet format ArcForges.slnx --verify-no-changes --no-restore", 600),
    wsl("wsl-build", "dotnet build ArcForges.slnx -c Release --no-restore", 900),
    wsl("wsl-ci", linux_tests("ci"), 1200),
    wsl("wsl-store-schema", linux_tests("store-schema"), 300),
    wsl("wsl-publish", f"python eng/verify_linux.py publish {' '.join(PUBLISH_GROUPS_LINUX)}", 900),
    wsl("wsl-tools-native", f"set -e; export ARCFORGES_TESTLOAD_PATH=\"$PWD/artifacts/publish/{RID_LINUX}/testload/arcforges-testload\" "
        f"ARCFORGES_BENCH_PATH=\"$PWD/artifacts/publish/{RID_LINUX}/bench/arcforges-bench\"; "
        "bash eng/test.sh --suite tools --no-build", 300),
    wsl("wsl-closed-loop-native", linux_tests("closed-loop", native=True), 600),
    wsl("wsl-bench", "python eng/verify_linux.py bench", 600),
    wsl("wsl-package", "python eng/verify_linux.py package", 300),
    # The merge base's host for the startup gate
    win("win-base-host", pwsh(WIN_BASE_HOST, devshell=True), 1200, lane="win-base"),
    wsl("wsl-base-host", WSL_BASE_HOST, 1200, lane="wsl-base"),
    # security.yml, Secret scan (over the pushed range) and Workflow lint (when a workflow changed)
    wsl("secret-scan", SECRET_SCAN, 300, lane="scan", profiles=frozenset({"full", "docs"})),
    wsl("actionlint", ACTIONLINT, 300, lane="actionlint", when=workflows_changed),
    # Exclusive phase: timing-, CPU-share- and memory-sensitive tests and the startup gates, alone
    win("win-exclusive", tests("exclusive"), 600, exclusive=True),
    win("win-exclusive-native", tests("exclusive", native=True), 600, exclusive=True),
    wsl("wsl-exclusive", linux_tests("exclusive"), 600, exclusive=True),
    wsl("wsl-exclusive-native", linux_tests("exclusive", native=True), 600, exclusive=True),
    win("win-startup-gate", pwsh(
        f"./eng/compare-startup.ps1 -RuntimeIdentifier {RID_WIN} "
        f"-BaselineExecutable (Join-Path {WIN_BASE} 'artifacts/publish/{RID_WIN}/host/arcforges.exe') "
        f"-BaselineSource '{BASE_SOURCE}'"), 300, exclusive=True),
    wsl("wsl-startup-gate", f"python eng/verify_linux.py compare-startup \"{LINUX_HOST}\" --baseline-source '{BASE_SOURCE}'",
        300, exclusive=True),
]
