# SPDX-License-Identifier: AGPL-3.0-only
<#
.SYNOPSIS
  CI startup regression gate (15-performance-targets): measures this run's CLI and the previous successful
  main-push CI run's CLI for the same runtime identifier on this runner, interleaved, and compares them.
.DESCRIPTION
  Rule (arcforges-bench compare-startup): the statistic is the median (p50 of 50 runs of `arcforges --version`
  after one warm-up). A regression is a p50 increase above BOTH 25% AND 5 ms; the absolute noise floor keeps
  millisecond-scale startups from failing on jitter.

  Same runner: the previous main run's published CLI (its startup-host-<rid>-<sha> artifact, uploaded by every
  main-push run) is downloaded and both executables run here, alternating run by run with the same warm-up and
  count, so the comparison is free of the machine-to-machine variance of hosted runners. A p50 recorded on another
  VM is never compared.

  The baseline is the newest of the last -RunWindow (20) successful main-push runs that has an unexpired startup-host
  artifact, so an expired or failed upload never skips the gate. Only when none of them has one (for example the first
  main run after this gate was introduced, or a new RID) is this run's own result recorded as passing, with the runs
  checked in the reason. The download must match the artifact's SHA-256 digest from the API. Any other API or download
  failure fails the step; the downloaded CLI is removed at the end.

  Needs eng/bench.ps1 output (artifacts/bench/<rid>/startup-arcforges-version.json) and the published host and
  arcforges-bench. In GitHub Actions it reads GITHUB_TOKEN (actions: read), GITHUB_REPOSITORY, GITHUB_API_URL and
  GITHUB_RUN_ID; the token is sent only to the GitHub API (the redirect to the artifact storage does not carry it) and is
  removed from the environment before arcforges-bench and the measured CLIs start.
  Locally, pass -BaselineExecutable (for example a main build) to run the same comparison without the API.
  Writes artifacts/bench/<rid>/startup-comparison.json (both p50 and p95, the samples and the rule). Exit: the
  step fails on a regression, on an API or download failure other than a missing baseline, or on a failed run.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet('win-x64', 'win-arm64', 'linux-x64', 'linux-arm64')]
  [string] $RuntimeIdentifier,
  [string] $BaselineExecutable,
  [string] $Workflow = 'ci.yml',
  [double] $MaxRegressionPercent = 25,
  [double] $NoiseFloorMs = 5,
  [int] $Runs = 50,
  [int] $Warmup = 1,
  # How many recent successful main-push runs are searched for the newest one with the CLI artifact.
  [ValidateRange(1, 100)]
  [int] $RunWindow = 20,
  # The measured command (the CLI cold start since AF-NODE-01).
  [string[]] $Arguments = @('--version'),
  [string] $Name = 'arcforges --version',
  # This run's recorded result (eng/bench.ps1), used when there is no baseline.
  [string] $ResultFile = 'startup-arcforges-version.json',
  # Overrides of the published and result paths (tests).
  [string] $CurrentExecutable,
  [string] $Bench,
  [string] $ResultsDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Every failure ends the step with one plain line on stderr ("compare-startup: <reason>"): no error view, colour or console
# width (pwsh's ConciseView on Linux puts the script position first and wraps at the console width) gets between the reason and
# the log or a test reading it. The download is removed by the inner finally before this handler runs.
try {
  $repository = Split-Path $PSScriptRoot -Parent
  $results = if ($ResultsDirectory) { $ResultsDirectory } else { Join-Path $repository "artifacts/bench/$RuntimeIdentifier" }
  $suffix = if ($RuntimeIdentifier.StartsWith('win-')) { '.exe' } else { '' }
  if (-not $Bench) { $Bench = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/bench/arcforges-bench$suffix" }
  if (-not $CurrentExecutable) { $CurrentExecutable = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/host/arcforges$suffix" }
  foreach ($required in @($Bench, $CurrentExecutable)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Run eng/publish.ps1 first: $required is missing." }
  }
  $null = New-Item -ItemType Directory -Path $results -Force

  # The token is read once and removed from this process's environment, so neither arcforges-bench nor the measured CLIs inherit
  # it (nor any other credential the runner provides); it is sent only to the GitHub API.
  $token = $env:GITHUB_TOKEN
  foreach ($credential in @('GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL')) {
    Remove-Item -LiteralPath "Env:$credential" -ErrorAction SilentlyContinue
  }

  function Get-MainBaseline {
    $api = if ($env:GITHUB_API_URL) { $env:GITHUB_API_URL } else { 'https://api.github.com' }
    if (-not $token -or -not $env:GITHUB_REPOSITORY) {
      throw 'GITHUB_TOKEN and GITHUB_REPOSITORY are required to find the previous main run (or pass -BaselineExecutable).'
    }
    $headers = @{
      Authorization = "Bearer $token"
      Accept = 'application/vnd.github+json'
      'X-GitHub-Api-Version' = '2022-11-28'
    }
    $runs = Invoke-RestMethod -Headers $headers -Uri "$api/repos/$env:GITHUB_REPOSITORY/actions/workflows/$Workflow/runs?branch=main&event=push&status=success&per_page=$RunWindow"
    $candidates = @($runs.workflow_runs | Where-Object { "$($_.id)" -ne "$env:GITHUB_RUN_ID" })
    if ($candidates.Count -eq 0) { return @{ Reason = 'No successful main-push CI run exists yet; there is no main CLI to measure against.' } }

    # The newest successful main-push run that has the CLI: one whose artifact expired or failed to upload is skipped, never the gate.
    $checked = @()
    foreach ($run in $candidates) {
      $artifactName = "startup-host-$RuntimeIdentifier-$($run.head_sha)"
      $artifacts = Invoke-RestMethod -Headers $headers -Uri "$api/repos/$env:GITHUB_REPOSITORY/actions/runs/$($run.id)/artifacts?name=$artifactName"
      $artifact = @($artifacts.artifacts | Where-Object { $_.name -eq $artifactName -and -not $_.expired }) | Select-Object -First 1
      if ($artifact) {
        $skipped = if ($checked.Count -gt 0) { "; newer runs without it: $($checked -join ', ')" } else { '' }
        return @{ Run = $run; Artifact = $artifact; Name = $artifactName; Source = "CI run $($run.id) on main at $($run.head_sha) (its CLI, measured on this runner)$skipped" }
      }
      $checked += "$($run.id) ($($run.head_sha))"
    }

    return @{ Reason = "None of the last $($candidates.Count) successful main-push CI runs has an unexpired startup-host-$RuntimeIdentifier artifact (main runs upload it since the same-runner gate; the RID may be new). Checked: $($checked -join ', ')." }
  }

  function Get-BaselineCli([hashtable] $found, [string] $download) {
    $headers = @{ Authorization = "Bearer $token"; Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
    $archive = Join-Path $download 'artifact.zip'
    # PowerShell drops the Authorization header on the redirect to the storage host.
    Invoke-WebRequest -Headers $headers -Uri $found.Artifact.archive_download_url -OutFile $archive

    # The archive must be the one the API lists: its SHA-256 digest (upload-artifact v4 and later records it for every artifact).
    $digest = if ($found.Artifact.PSObject.Properties['digest']) { "$($found.Artifact.digest)" } else { '' }
    if ($digest -notmatch '^sha256:[0-9a-fA-F]{64}$') { throw "$($found.Name) of CI run $($found.Run.id) has no SHA-256 digest to verify the download against." }
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if ($actual -ne $digest.Substring(7).ToUpperInvariant()) {
      throw "$($found.Name) of CI run $($found.Run.id): the download's SHA-256 $actual does not match the artifact digest $digest."
    }

    $directory = Join-Path $download 'host'
    Expand-Archive -LiteralPath $archive -DestinationPath $directory
    $executable = Join-Path $directory "arcforges$suffix"
    if (-not (Test-Path -LiteralPath $executable)) { throw "$($found.Name) of CI run $($found.Run.id) has no arcforges$suffix." }
    if (-not $IsWindows) { & chmod +x $executable; if ($LASTEXITCODE -ne 0) { throw "chmod +x $executable failed." } }
    return $executable
  }

  $download = $null
  try {
    $baseline = if ($BaselineExecutable) {
      if (-not (Test-Path -LiteralPath $BaselineExecutable)) { throw "-BaselineExecutable $BaselineExecutable is missing." }
      @{ Path = (Resolve-Path -LiteralPath $BaselineExecutable).Path; Source = "$BaselineExecutable (measured on this machine)" }
    } else {
      $found = Get-MainBaseline
      if ($found.Contains('Artifact')) {
        $download = Join-Path ([IO.Path]::GetTempPath()) "arcforges-baseline-$([guid]::NewGuid().ToString('N'))"
        $null = New-Item -ItemType Directory -Path $download
        @{ Path = (Get-BaselineCli $found $download); Source = $found.Source }
      } else {
        $found
      }
    }

    $output = Join-Path $results 'startup-comparison.json'
    $rule = @('--max-regression-percent', "$MaxRegressionPercent", '--noise-floor-ms', "$NoiseFloorMs", '--output', $output)
    if ($baseline.Contains('Path')) {
      $benchArguments = @('compare-startup', '--baseline-exe', $baseline.Path, '--current-exe', $CurrentExecutable, '--runs', "$Runs", '--warmup', "$Warmup",
        '--name', $Name, '--baseline-source', $baseline.Source)
      foreach ($argument in $Arguments) { $benchArguments += @('--arg', $argument) }
    } else {
      $current = Join-Path $results $ResultFile
      if (-not (Test-Path -LiteralPath $current)) { throw "Run eng/bench.ps1 first: $current is missing." }
      $benchArguments = @('compare-startup', '--current', $current, '--reason', $baseline.Reason)
    }
    & $Bench @($benchArguments + $rule)
    if ($LASTEXITCODE -ne 0) { throw "The startup comparison failed (exit $LASTEXITCODE); see $output." }
  } finally {
    # The downloaded CLI is removed whatever happened (the measurement has ended: arcforges-bench waits for every run).
    if ($download -and (Test-Path -LiteralPath $download)) { Remove-Item -LiteralPath $download -Recurse -Force }
  }
} catch {
  [Console]::Error.WriteLine("compare-startup: $($_.Exception.Message)")
  exit 1
}
