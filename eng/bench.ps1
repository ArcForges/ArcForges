# SPDX-License-Identifier: AGPL-3.0-only
<#
.SYNOPSIS
  Runs the CI benchmarks of 15-performance-targets with the published arcforges-bench:
  size gates for arcforges and arcforges-desktop, and the startup benchmark of arcforges.
.DESCRIPTION
  Needs eng/publish.ps1 output for host, desktop and bench. JSON results go to
  artifacts/bench/<rid>/. Sizes gate (exit 1 when over a target). Startup is recorded only:
  hosted runners are noisy, and the 25% regression check against main is not wired yet.
  Pass -StartupP50Ms/-StartupP95Ms to check limits on the workstation.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet('win-x64', 'win-arm64', 'linux-x64')]
  [string] $RuntimeIdentifier,
  [int] $Runs = 50,
  [double] $StartupP50Ms = 0,
  [double] $StartupP95Ms = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path $PSScriptRoot -Parent
$publish = Join-Path $repository "artifacts/publish/$RuntimeIdentifier"
$results = Join-Path $repository "artifacts/bench/$RuntimeIdentifier"
$suffix = if ($RuntimeIdentifier.StartsWith('win-')) { '.exe' } else { '' }
$bench = Join-Path $publish "bench/arcforges-bench$suffix"
$null = New-Item -ItemType Directory -Path $results -Force

function Invoke-Bench([string[]] $Arguments) {
  & $bench @Arguments
  if ($LASTEXITCODE -ne 0) { throw "arcforges-bench $($Arguments[0]) failed with exit code $LASTEXITCODE." }
}

Invoke-Bench @('size', '--target', 'arcforges', '--path', (Join-Path $publish "host/arcforges$suffix"),
  '--output', (Join-Path $results 'size-arcforges.json'))
Invoke-Bench @('size', '--target', 'arcforges-desktop', '--path', (Join-Path $publish 'desktop'),
  '--output', (Join-Path $results 'size-arcforges-desktop.json'))
$startup = @('startup', '--exe', (Join-Path $publish "host/arcforges$suffix"), '--runs', "$Runs", '--warmup', '1',
  '--name', 'arcforges', '--output', (Join-Path $results 'startup-arcforges.json'))
if ($StartupP50Ms -gt 0) { $startup += @('--max-p50-ms', "$StartupP50Ms") }
if ($StartupP95Ms -gt 0) { $startup += @('--max-p95-ms', "$StartupP95Ms") }
Invoke-Bench $startup
