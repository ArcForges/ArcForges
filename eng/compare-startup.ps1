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

  When no successful main run, or no unexpired startup-host artifact of it, exists (for example the first main run
  after this gate was introduced), this run's own result is recorded as passing with that reason. Any other API or
  download failure fails the step.

  Needs eng/bench.ps1 output (artifacts/bench/<rid>/startup-arcforges-version.json) and the published host and
  arcforges-bench. In GitHub Actions it reads GITHUB_TOKEN (actions: read), GITHUB_REPOSITORY, GITHUB_API_URL and
  GITHUB_RUN_ID; the token is sent only to the GitHub API (the redirect to the artifact storage does not carry it).
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
$repository = Split-Path $PSScriptRoot -Parent
$results = if ($ResultsDirectory) { $ResultsDirectory } else { Join-Path $repository "artifacts/bench/$RuntimeIdentifier" }
$suffix = if ($RuntimeIdentifier.StartsWith('win-')) { '.exe' } else { '' }
if (-not $Bench) { $Bench = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/bench/arcforges-bench$suffix" }
if (-not $CurrentExecutable) { $CurrentExecutable = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/host/arcforges$suffix" }
foreach ($required in @($Bench, $CurrentExecutable)) {
  if (-not (Test-Path -LiteralPath $required)) { throw "Run eng/publish.ps1 first: $required is missing." }
}
$null = New-Item -ItemType Directory -Path $results -Force

function Get-MainBaseline {
  $api = if ($env:GITHUB_API_URL) { $env:GITHUB_API_URL } else { 'https://api.github.com' }
  if (-not $env:GITHUB_TOKEN -or -not $env:GITHUB_REPOSITORY) {
    throw 'GITHUB_TOKEN and GITHUB_REPOSITORY are required to find the previous main run (or pass -BaselineExecutable).'
  }
  $headers = @{
    Authorization = "Bearer $env:GITHUB_TOKEN"
    Accept = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
  }
  $runs = Invoke-RestMethod -Headers $headers -Uri "$api/repos/$env:GITHUB_REPOSITORY/actions/workflows/$Workflow/runs?branch=main&event=push&status=success&per_page=10"
  $run = @($runs.workflow_runs | Where-Object { "$($_.id)" -ne "$env:GITHUB_RUN_ID" }) | Select-Object -First 1
  if (-not $run) { return @{ Reason = 'No successful main-push CI run exists yet; there is no main CLI to measure against.' } }

  $artifactName = "startup-host-$RuntimeIdentifier-$($run.head_sha)"
  $source = "CI run $($run.id) on main at $($run.head_sha) (its CLI, measured on this runner)"
  $artifacts = Invoke-RestMethod -Headers $headers -Uri "$api/repos/$env:GITHUB_REPOSITORY/actions/runs/$($run.id)/artifacts?name=$artifactName"
  $artifact = @($artifacts.artifacts | Where-Object { -not $_.expired }) | Select-Object -First 1
  if (-not $artifact) {
    return @{ Reason = "CI run $($run.id) on main at $($run.head_sha) has no unexpired $artifactName artifact (main runs upload it since the same-runner gate; the RID may be new)." }
  }

  $download = Join-Path ([IO.Path]::GetTempPath()) "arcforges-baseline-$([guid]::NewGuid().ToString('N'))"
  $null = New-Item -ItemType Directory -Path $download
  $archive = Join-Path $download 'artifact.zip'
  # PowerShell drops the Authorization header on the redirect to the storage host.
  Invoke-WebRequest -Headers $headers -Uri $artifact.archive_download_url -OutFile $archive
  $directory = Join-Path $download 'host'
  Expand-Archive -LiteralPath $archive -DestinationPath $directory
  $executable = Join-Path $directory "arcforges$suffix"
  if (-not (Test-Path -LiteralPath $executable)) { throw "$artifactName of CI run $($run.id) has no arcforges$suffix." }
  if (-not $IsWindows) { & chmod +x $executable; if ($LASTEXITCODE -ne 0) { throw "chmod +x $executable failed." } }
  return @{ Path = $executable; Source = $source }
}

$baseline = if ($BaselineExecutable) {
  if (-not (Test-Path -LiteralPath $BaselineExecutable)) { throw "-BaselineExecutable $BaselineExecutable is missing." }
  @{ Path = (Resolve-Path -LiteralPath $BaselineExecutable).Path; Source = "$BaselineExecutable (measured on this machine)" }
} else {
  Get-MainBaseline
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
