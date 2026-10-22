# SPDX-License-Identifier: AGPL-3.0-only
<#
.SYNOPSIS
  Startup regression gate (15-performance-targets): measures this build's CLI and the CLI of the base commit on this
  machine, interleaved, and compares them.
.DESCRIPTION
  Rule (arcforges-bench compare-startup): the statistic is the median (p50 of 50 runs of `arcforges --version`
  after one warm-up). A regression is a p50 increase above BOTH 25% AND 5 ms; the absolute noise floor keeps
  millisecond-scale startups from failing on jitter.

  Same machine: -BaselineExecutable is the Native AOT host of the base commit built on this machine (external-PR CI: the
  PR's base commit, published on the same runner; the host verification after the push: the merge base with main). Both
  executables run here, alternating run by run with the same warm-up and count, so the comparison is free of the
  machine-to-machine variance of hosted runners. A p50 recorded on another machine is never compared.

  Needs the published host and arcforges-bench (eng/publish.ps1). Writes artifacts/bench/<rid>/startup-comparison.json
  (both p50 and p95, the samples and the rule). Exit: the step fails on a regression, on a failed run or when an
  executable is missing.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet('win-x64', 'win-arm64', 'linux-x64', 'linux-arm64')]
  [string] $RuntimeIdentifier,
  [Parameter(Mandatory)]
  [string] $BaselineExecutable,
  # Where the baseline came from, recorded in the result (for example the base commit).
  [string] $BaselineSource,
  [double] $MaxRegressionPercent = 25,
  [double] $NoiseFloorMs = 5,
  [int] $Runs = 50,
  [int] $Warmup = 1,
  # The measured command (the CLI cold start since AF-NODE-01).
  [string[]] $Arguments = @('--version'),
  [string] $Name = 'arcforges --version',
  # Overrides of the published and result paths (tests).
  [string] $CurrentExecutable,
  [string] $Bench,
  [string] $ResultsDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Every failure ends the step with one plain line on stderr ("compare-startup: <reason>"): no error view, colour or console
# width (pwsh's ConciseView on Linux puts the script position first and wraps at the console width) gets between the reason and
# the log or a test reading it.
try {
  $repository = Split-Path $PSScriptRoot -Parent
  $results = if ($ResultsDirectory) { $ResultsDirectory } else { Join-Path $repository "artifacts/bench/$RuntimeIdentifier" }
  $suffix = if ($RuntimeIdentifier.StartsWith('win-')) { '.exe' } else { '' }
  if (-not $Bench) { $Bench = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/bench/arcforges-bench$suffix" }
  if (-not $CurrentExecutable) { $CurrentExecutable = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/host/arcforges$suffix" }
  foreach ($required in @($Bench, $CurrentExecutable)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Run eng/publish.ps1 first: $required is missing." }
  }
  if (-not (Test-Path -LiteralPath $BaselineExecutable)) { throw "-BaselineExecutable $BaselineExecutable is missing." }
  $baseline = (Resolve-Path -LiteralPath $BaselineExecutable).Path
  if (-not $BaselineSource) { $BaselineSource = "$BaselineExecutable (measured on this machine)" }
  $null = New-Item -ItemType Directory -Path $results -Force

  $output = Join-Path $results 'startup-comparison.json'
  $benchArguments = @('compare-startup', '--baseline-exe', $baseline, '--current-exe', $CurrentExecutable, '--runs', "$Runs", '--warmup', "$Warmup",
    '--name', $Name, '--baseline-source', $BaselineSource)
  foreach ($argument in $Arguments) { $benchArguments += @('--arg', $argument) }
  $benchArguments += @('--max-regression-percent', "$MaxRegressionPercent", '--noise-floor-ms', "$NoiseFloorMs", '--output', $output)
  & $Bench @benchArguments
  if ($LASTEXITCODE -ne 0) { throw "The startup comparison failed (exit $LASTEXITCODE); see $output." }
} catch {
  [Console]::Error.WriteLine("compare-startup: $($_.Exception.Message)")
  exit 1
}
