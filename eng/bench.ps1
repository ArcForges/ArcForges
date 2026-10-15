# SPDX-License-Identifier: AGPL-3.0-only
<#
.SYNOPSIS
  Runs the CI benchmarks of 15-performance-targets with the published arcforges-bench:
  size gates for arcforges and arcforges-desktop, the node store growth gate, and the startup
  benchmark of arcforges.
.DESCRIPTION
  Needs eng/publish.ps1 output for host, desktop and bench. JSON results go to
  artifacts/bench/<rid>/. Sizes gate (exit 1 when over a target). Store growth gates at 50 MB per
  10,000 attempts (-StoreAttempts, default 10000) submitted from the captured environments in
  tests/ArcForges.Node.Store.Tests/Fixtures/environments (node-store.md section 4). Startup has no absolute limit
  on hosted runners; CI gates it with eng/compare-startup.ps1 against the previous successful
  main run (a regression is a p50 increase above both 25% and 5 ms). Pass
  -StartupP50Ms/-StartupP95Ms to check the absolute targets on the workstation.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet('win-x64', 'win-arm64', 'linux-x64', 'linux-arm64')]
  [string] $RuntimeIdentifier,
  [int] $Runs = 50,
  [int] $StoreAttempts = 10000,
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
$growth = @('store-growth', '--attempts', "$StoreAttempts", '--output', (Join-Path $results 'store-growth.json'))
foreach ($environment in Get-ChildItem -LiteralPath (Join-Path $repository 'tests/ArcForges.Node.Store.Tests/Fixtures/environments') -Filter '*.json' | Sort-Object Name) {
  $growth += @('--environment', $environment.FullName)
}
Invoke-Bench $growth
$startup = @('startup', '--exe', (Join-Path $publish "host/arcforges$suffix"), '--runs', "$Runs", '--warmup', '1',
  '--name', 'arcforges', '--output', (Join-Path $results 'startup-arcforges.json'))
if ($StartupP50Ms -gt 0) { $startup += @('--max-p50-ms', "$StartupP50Ms") }
if ($StartupP95Ms -gt 0) { $startup += @('--max-p95-ms', "$StartupP95Ms") }
Invoke-Bench $startup
