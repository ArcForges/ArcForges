# SPDX-License-Identifier: AGPL-3.0-only
<#
.SYNOPSIS
  CI startup regression gate (15-performance-targets): compares this run's startup result with the
  previous successful main-push CI run for the same runtime identifier.
.DESCRIPTION
  Rule (arcforges-bench compare-startup): the statistic is the median (p50 of 50 runs). A regression
  is a p50 increase above BOTH 25% AND 5 ms; the absolute noise floor keeps millisecond-scale
  startups on noisy hosted runners from failing on jitter. When no successful main run, or no
  unexpired bench artifact of it, exists (for example the first run), the result is recorded as
  passing with that reason. Any other API failure fails the step.

  Needs eng/bench.ps1 output (artifacts/bench/<rid>/startup-arcforges-version.json, the CLI cold start of
  `arcforges --version`) and the published
  arcforges-bench. In GitHub Actions it reads GITHUB_TOKEN (actions: read), GITHUB_REPOSITORY,
  GITHUB_API_URL and GITHUB_RUN_ID; the token is sent only to the GitHub API. Locally, pass
  -BaselineFile to compare with a saved result instead.
  Writes artifacts/bench/<rid>/startup-comparison.json.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet('win-x64', 'win-arm64', 'linux-x64', 'linux-arm64')]
  [string] $RuntimeIdentifier,
  [string] $BaselineFile,
  [string] $Workflow = 'ci.yml',
  [double] $MaxRegressionPercent = 25,
  [double] $NoiseFloorMs = 5,
  # The startup result compared: the CLI cold start since AF-NODE-01 (before it, the empty host's startup-arcforges.json).
  [string] $ResultFile = 'startup-arcforges-version.json'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path $PSScriptRoot -Parent
$results = Join-Path $repository "artifacts/bench/$RuntimeIdentifier"
$current = Join-Path $results $ResultFile
$suffix = if ($RuntimeIdentifier.StartsWith('win-')) { '.exe' } else { '' }
$bench = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/bench/arcforges-bench$suffix"
if (-not (Test-Path -LiteralPath $current)) { throw "Run eng/bench.ps1 first: $current is missing." }

function Get-MainBaseline {
  $api = if ($env:GITHUB_API_URL) { $env:GITHUB_API_URL } else { 'https://api.github.com' }
  if (-not $env:GITHUB_TOKEN -or -not $env:GITHUB_REPOSITORY) {
    throw 'GITHUB_TOKEN and GITHUB_REPOSITORY are required to find the previous main run (or pass -BaselineFile).'
  }
  $headers = @{
    Authorization = "Bearer $env:GITHUB_TOKEN"
    Accept = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
  }
  $runs = Invoke-RestMethod -Headers $headers -Uri "$api/repos/$env:GITHUB_REPOSITORY/actions/workflows/$Workflow/runs?branch=main&event=push&status=success&per_page=10"
  $run = @($runs.workflow_runs | Where-Object { "$($_.id)" -ne "$env:GITHUB_RUN_ID" }) | Select-Object -First 1
  if (-not $run) { return @{ Reason = 'No successful main-push CI run exists yet; this result becomes the first baseline.' } }

  $name = "bench-$RuntimeIdentifier-$($run.head_sha)"
  $source = "CI run $($run.id) on main at $($run.head_sha)"
  $artifacts = Invoke-RestMethod -Headers $headers -Uri "$api/repos/$env:GITHUB_REPOSITORY/actions/runs/$($run.id)/artifacts?name=$name"
  $artifact = @($artifacts.artifacts | Where-Object { -not $_.expired }) | Select-Object -First 1
  if (-not $artifact) { return @{ Reason = "$source has no unexpired $name artifact (the RID or the benchmark is new there)." } }

  $download = Join-Path ([IO.Path]::GetTempPath()) "arcforges-baseline-$([guid]::NewGuid().ToString('N'))"
  $null = New-Item -ItemType Directory -Path $download
  $archive = Join-Path $download 'artifact.zip'
  # The redirect to the storage host does not carry the Authorization header.
  Invoke-WebRequest -Headers $headers -Uri $artifact.archive_download_url -OutFile $archive
  Expand-Archive -LiteralPath $archive -DestinationPath $download
  $file = Join-Path $download $ResultFile
  if (-not (Test-Path -LiteralPath $file)) { return @{ Reason = "$source has no $ResultFile in $name (the benchmark is new there)." } }
  return @{ Path = $file; Source = $source }
}

$baseline = if ($BaselineFile) { @{ Path = $BaselineFile; Source = $BaselineFile } } else { Get-MainBaseline }
$arguments = @('compare-startup', '--current', $current,
  '--max-regression-percent', "$MaxRegressionPercent", '--noise-floor-ms', "$NoiseFloorMs",
  '--output', (Join-Path $results 'startup-comparison.json'))
if ($baseline.Contains('Path')) {
  $arguments += @('--baseline', $baseline.Path, '--baseline-source', $baseline.Source)
} else {
  $arguments += @('--reason', $baseline.Reason)
}
& $bench @arguments
if ($LASTEXITCODE -ne 0) { throw "The startup comparison failed (exit $LASTEXITCODE); see startup-comparison.json." }
