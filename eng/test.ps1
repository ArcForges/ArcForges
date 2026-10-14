# SPDX-License-Identifier: AGPL-3.0-only
<#
.SYNOPSIS
  Runs test suites selected by traits (16-testing-strategy section 4; suites in eng/test-suites.conf).
.DESCRIPTION
  Options: -Suite <name[,name]> (repeatable), -Kind <name>, -Configuration <name> (Release),
  -NoBuild, -List. Every argument from the first one that starts with '--' (or after a bare '--')
  is passed to each test application. The script parses its own arguments so that pass-through
  works both as `./eng/test.ps1 ...` and as `pwsh -File eng/test.ps1 ...`.
.EXAMPLE
  ./eng/test.ps1                         # the unit suite
  ./eng/test.ps1 -Suite tools,repository
  ./eng/test.ps1 -Kind windows           # the suites for a kind of change
  ./eng/test.ps1 -Suite ci -NoBuild -- --output Detailed
  pwsh -File eng/test.ps1 -Suite ci -NoBuild -- --output Detailed
  ./eng/test.ps1 -List
#>

$Suite = @()
$Kind = $null
$Configuration = 'Release'
$NoBuild = $false
$List = $false
$PassThru = @()
# -Command mode passes 'a,b' as one array argument; -File mode passes it as one string.
$arguments = @(foreach ($item in $args) { foreach ($element in @($item)) { "$element" } })
$i = 0
while ($i -lt $arguments.Count) {
  $argument = $arguments[$i]
  if ($argument -eq '--') { $PassThru = @($arguments | Select-Object -Skip ($i + 1)); break }
  if ($argument.StartsWith('--')) { $PassThru = @($arguments | Select-Object -Skip $i); break }
  $values = @($arguments | Select-Object -Skip ($i + 1) | ForEach-Object -Begin { $open = $true } -Process {
      if ($open -and -not $_.StartsWith('-')) { $_ } else { $open = $false } })
  if ($argument -in '-Suite', '-Kind', '-Configuration' -and $values.Count -eq 0) { throw "test.ps1: $argument needs a value." }
  switch ($argument) {
    '-Suite' { $Suite += @($values | ForEach-Object { $_ -split ',' }); $i += 1 + $values.Count; continue }
    '-Kind' { $Kind = $values[0]; $i += 2; continue }
    '-Configuration' { $Configuration = $values[0]; $i += 2; continue }
    '-NoBuild' { $NoBuild = $true; $i++; continue }
    '-List' { $List = $true; $i++; continue }
    default { throw "test.ps1: unknown argument '$argument'. Options: -Suite, -Kind, -Configuration, -NoBuild, -List; test application arguments start with '--'." }
  }
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path $PSScriptRoot -Parent
$env:AVALONIA_TELEMETRY_OPTOUT = '1'

$suites = [ordered]@{}
$kinds = [ordered]@{}
foreach ($line in Get-Content -LiteralPath (Join-Path $PSScriptRoot 'test-suites.conf')) {
  $fields = @(($line -replace '#.*$', '').Trim() -split '\s+' | Where-Object { $_ })
  if ($fields.Count -eq 0) { continue }
  switch ($fields[0]) {
    'suite' { $suites[$fields[1]] = @{ Projects = $fields[2]; Filters = @($fields | Select-Object -Skip 3) } }
    'kind' { $kinds[$fields[1]] = @($fields | Select-Object -Skip 2) }
    default { throw "test-suites.conf: unknown entry '$($fields[0])'." }
  }
}

$allProjects = @(Get-ChildItem -Path (Join-Path $repository 'tests') -Filter '*.Tests.csproj' -Recurse -Depth 1 |
  Sort-Object Name | ForEach-Object { $_.BaseName })

if ($List) {
  foreach ($name in $suites.Keys) {
    "suite {0,-13} {1,-28} {2}" -f $name, $suites[$name].Projects, ($suites[$name].Filters -join ' ')
  }
  foreach ($name in $kinds.Keys) { "kind  {0,-13} {1}" -f $name, ($kinds[$name] -join ' ') }
  "projects: $($allProjects -join ', ')"
  return
}

if ($Kind) {
  if (-not $kinds.Contains($Kind)) { throw "Unknown kind '$Kind'. Known: $($kinds.Keys -join ', ')." }
  $Suite += $kinds[$Kind]
}
if ($Suite.Count -eq 0) { $Suite = @('unit') }
$Suite = @($Suite | ForEach-Object { $_ -split ',' } | Where-Object { $_ } | Select-Object -Unique)
foreach ($name in $Suite) {
  if (-not $suites.Contains($name)) { throw "Unknown suite '$name'. Known: $($suites.Keys -join ', ')." }
}

if (-not $NoBuild) {
  dotnet build (Join-Path $repository 'ArcForges.slnx') -c $Configuration
  if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE." }
}

$failures = @()
foreach ($name in $Suite) {
  $definition = $suites[$name]
  $projects = if ($definition.Projects -eq '*') { $allProjects } else { @($definition.Projects -split ',') }
  foreach ($project in $projects) {
    $path = Join-Path $repository "tests/$project/$project.csproj"
    if (-not (Test-Path -LiteralPath $path)) { throw "Suite '$name' names a missing project: $project." }
    Write-Host "==> suite $name : $project $($definition.Filters -join ' ')"
    # Exit code 8 (no test ran) is accepted only where trait filters select a subset of a project.
    $ignore = if ($definition.Filters.Count -gt 0) { @('--ignore-exit-code', '8') } else { @() }
    dotnet test --project $path -c $Configuration --no-build @ignore @($definition.Filters) @PassThru
    if ($LASTEXITCODE -ne 0) { $failures += "$name/$project (exit $LASTEXITCODE)" }
  }
}

if ($failures.Count -gt 0) {
  Write-Host "Failed: $($failures -join '; ')"
  exit 1
}
Write-Host "Suites passed: $($Suite -join ', ')"
