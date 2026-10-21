# SPDX-License-Identifier: AGPL-3.0-only
<#
.SYNOPSIS
  Publishes Native AOT executables for one runtime identifier and fails on any build, trim or AOT warning.
.DESCRIPTION
  Output: artifacts/publish/<rid>/<component>/. Components: host (arcforges), supervisor
  (arcforges-supervisor.exe; Windows RIDs only; the install layout puts it beside arcforges.exe),
  desktop (arcforges-desktop), testload (arcforges-testload), bench (arcforges-bench).
  Windows targets need the MSVC linker (Visual Studio C++ tools); Linux targets need clang and
  zlib1g-dev and are published on Linux.
.EXAMPLE
  ./eng/publish.ps1 -RuntimeIdentifier win-x64
  ./eng/publish.ps1 -RuntimeIdentifier linux-x64 -Component host,testload
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet('win-x64', 'win-arm64', 'linux-x64', 'linux-arm64')]
  [string] $RuntimeIdentifier,
  [ValidateSet('host', 'supervisor', 'desktop', 'testload', 'bench')]
  [string[]] $Component = @('host', 'supervisor', 'desktop', 'testload', 'bench'),
  [string] $Configuration = 'Release',
  [switch] $NoRestore
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path $PSScriptRoot -Parent
$env:AVALONIA_TELEMETRY_OPTOUT = '1'
$projects = @{
  host = 'src/ArcForges.Host'
  supervisor = 'src/ArcForges.Supervisor'
  desktop = 'src/ArcForges.Desktop'
  testload = 'tools/ArcForges.TestLoad'
  bench = 'tools/ArcForges.Bench'
}

foreach ($name in $Component) {
  if ($name -eq 'supervisor' -and -not $RuntimeIdentifier.StartsWith('win-')) {
    Write-Host "==> supervisor: Windows only (systemd fills the role on Linux); skipped for $RuntimeIdentifier"
    continue
  }
  $output = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/$name"
  if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Recurse -Force }
  $arguments = @(
    'publish', (Join-Path $repository $projects[$name]),
    '-c', $Configuration, '-r', $RuntimeIdentifier, '-o', $output,
    '-warnaserror', '-tl:off', '-clp:Summary;ForceNoAlign', '-p:TrimmerSingleWarn=false'
  )
  if ($NoRestore) { $arguments += '--no-restore' }
  # Inside a Visual Studio developer shell, link with its environment instead of re-running vcvarsall.
  if ($IsWindows -and $env:VCToolsInstallDir) { $arguments += '-p:IlcUseEnvironmentalTools=true' }
  Write-Host "==> publish $name ($RuntimeIdentifier)"
  $lines = @(& dotnet @arguments 2>&1 | ForEach-Object { "$_" } | Tee-Object -Variable echoed)
  $echoed | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "Publishing $name for $RuntimeIdentifier failed with exit code $LASTEXITCODE." }
  $warnings = @($lines | Where-Object { $_ -match ':\s+warning\s+[A-Z]+[0-9]+' } | Select-Object -Unique)
  if ($warnings.Count -gt 0) { throw "Publishing $name for $RuntimeIdentifier reported $($warnings.Count) warning(s)." }
  if (-not ($lines -match '^\s*0 Warning\(s\)')) { throw "Publishing $name for $RuntimeIdentifier did not report its warning count." }
  Write-Host "==> $name ($RuntimeIdentifier): Native AOT publish with 0 warnings -> $output"
}

# The install layout puts arcforges-supervisor.exe beside arcforges.exe (13 section 3.1); the auto-start finds it there.
# Only a run that published the host or the supervisor copies it, so a concurrent run of other components never writes
# into a host directory that is being published.
$hostDirectory = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/host"
$supervisorBinary = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/supervisor/arcforges-supervisor.exe"
if (($Component -contains 'host' -or $Component -contains 'supervisor') -and
  (Test-Path -LiteralPath $hostDirectory) -and (Test-Path -LiteralPath $supervisorBinary)) {
  Copy-Item -LiteralPath $supervisorBinary -Destination $hostDirectory -Force
  Write-Host "==> copied arcforges-supervisor.exe beside arcforges.exe in $hostDirectory"
}
