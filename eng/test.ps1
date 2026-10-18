# SPDX-License-Identifier: AGPL-3.0-only
<#
.SYNOPSIS
  Runs test suites selected by traits (16-testing-strategy section 4; suites in eng/test-suites.conf).
.DESCRIPTION
  Options: -Suite <name[,name]> (repeatable), -Kind <name>, -Configuration <name> (Release),
  -NoBuild, -List, -Parallel <n>, -Repeat <n>. Every argument from the first one that starts with '--'
  (or after a bare '--') is passed to each test application. The script parses its own arguments so that
  pass-through works both as `./eng/test.ps1 ...` and as `pwsh -File eng/test.ps1 ...`.

  -Parallel <n> runs up to n test projects at once (default 2: measured on 18 logical processors, the ci suite takes as long
  at 2 as at 4 or 9, because its longest project bounds it, and uses the least CPU; projects also run their tests in parallel).
  Each project's output goes to artifacts/test-logs/ and is printed when the project completes.
  -Parallel 1 runs the projects one after another with live output. A suite that selects
  isolation=exclusive (the exclusive suite) runs after the other suites, one project at a time.
  -Repeat <n> runs the selected suites n times, stops at the first failing iteration and prints the
  duration of every iteration (stress and flake hunting).
.EXAMPLE
  ./eng/test.ps1                         # the unit suite
  ./eng/test.ps1 -Suite tools,repository
  ./eng/test.ps1 -Kind windows           # the suites for a kind of change
  ./eng/test.ps1 -Suite ci -NoBuild -- --output Detailed
  ./eng/test.ps1 -Suite ci,exclusive -NoBuild -Repeat 5
  pwsh -File eng/test.ps1 -Suite ci -NoBuild -- --output Detailed
  ./eng/test.ps1 -List
#>

$Suite = @()
$Kind = $null
$Configuration = 'Release'
$NoBuild = $false
$List = $false
$Parallel = 2
$Repeat = 1
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
  if ($argument -in '-Suite', '-Kind', '-Configuration', '-Parallel', '-Repeat' -and $values.Count -eq 0) { throw "test.ps1: $argument needs a value." }
  switch ($argument) {
    '-Suite' { $Suite += @($values | ForEach-Object { $_ -split ',' }); $i += 1 + $values.Count; continue }
    '-Kind' { $Kind = $values[0]; $i += 2; continue }
    '-Configuration' { $Configuration = $values[0]; $i += 2; continue }
    '-NoBuild' { $NoBuild = $true; $i++; continue }
    '-List' { $List = $true; $i++; continue }
    '-Parallel' { $Parallel = [int]$values[0]; $i += 2; continue }
    '-Repeat' { $Repeat = [int]$values[0]; $i += 2; continue }
    default { throw "test.ps1: unknown argument '$argument'. Options: -Suite, -Kind, -Configuration, -NoBuild, -List, -Parallel, -Repeat; test application arguments start with '--'." }
  }
}
if ($Parallel -lt 1 -or $Repeat -lt 1) { throw 'test.ps1: -Parallel and -Repeat need a positive number.' }

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path $PSScriptRoot -Parent
$env:AVALONIA_TELEMETRY_OPTOUT = '1'
# The single opt-in of the OS secret-store tier (16-testing-strategy section 1). Every suite this script runs is routine, so none
# inherits it: a stray value is removed before anything runs. Only eng/os_secret_store_tier.py runs the tier, never this script.
if (Test-Path Env:ARCFORGES_OS_SECRET_STORE_TESTS) {
  Remove-Item Env:ARCFORGES_OS_SECRET_STORE_TESTS
  Write-Host 'test.ps1: removed ARCFORGES_OS_SECRET_STORE_TESTS from the environment: routine suites never reach a real OS secret store (only eng/os_secret_store_tier.py runs the OS secret-store tier).'
}

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

# One work item per suite and project. Exit code 8 (no test ran) is accepted only where trait filters select a subset of a project.
$work = @(foreach ($name in $Suite) {
    $definition = $suites[$name]
    $projects = if ($definition.Projects -eq '*') { $allProjects } else { @($definition.Projects -split ',') }
    foreach ($project in $projects) {
      $path = Join-Path $repository "tests/$project/$project.csproj"
      if (-not (Test-Path -LiteralPath $path)) { throw "Suite '$name' names a missing project: $project." }
      [pscustomobject]@{
        Suite = $name
        Project = $project
        Path = $path
        Filters = @($definition.Filters)
        Ignore = if ($definition.Filters.Count -gt 0) { @('--ignore-exit-code', '8') } else { @() }
        Exclusive = ($definition.Filters -join ' ') -match '--filter-trait isolation=exclusive'
        Log = Join-Path $repository "artifacts/test-logs/$name-$project.log"
      }
    }
  })

if (-not $NoBuild) {
  dotnet build (Join-Path $repository 'ArcForges.slnx') -c $Configuration
  if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE." }
}
New-Item -ItemType Directory -Force -Path (Join-Path $repository 'artifacts/test-logs') | Out-Null

$failures = [System.Collections.Generic.List[string]]::new()
$durations = @()
for ($iteration = 1; $iteration -le $Repeat; $iteration++) {
  $watch = [System.Diagnostics.Stopwatch]::StartNew()
  $failures.Clear()
  if ($Parallel -gt 1) {
    # Up to $Parallel projects at once, each into its own log; a log is printed when its project completes.
    $configuration = $Configuration
    $passThru = $PassThru
    @($work | Where-Object { -not $_.Exclusive }) | ForEach-Object -ThrottleLimit $Parallel -Parallel {
      $item = $_
      $started = [System.Diagnostics.Stopwatch]::StartNew()
      & dotnet test --project $item.Path -c $using:configuration --no-build @($item.Ignore) @($item.Filters) @($using:passThru) *> $item.Log
      [pscustomobject]@{ Item = $item; Exit = $LASTEXITCODE; Seconds = $started.Elapsed.TotalSeconds }
    } | ForEach-Object {
      $item = $_.Item
      Write-Host ("==> suite {0} : {1} {2} ({3:0.0} s, exit {4}, log {5})" -f $item.Suite, $item.Project, ($item.Filters -join ' '), $_.Seconds, $_.Exit, $item.Log)
      Get-Content -LiteralPath $item.Log | Write-Host
      if ($_.Exit -ne 0) { $failures.Add("$($item.Suite)/$($item.Project) (exit $($_.Exit), log $($item.Log))") }
    }
  }

  # One after another with live output: everything with -Parallel 1, otherwise the exclusive suite after the others.
  foreach ($item in @($work | Where-Object { $Parallel -eq 1 -or $_.Exclusive })) {
    Write-Host "==> suite $($item.Suite) : $($item.Project) $($item.Filters -join ' ')"
    dotnet test --project $item.Path -c $Configuration --no-build @($item.Ignore) @($item.Filters) @PassThru
    if ($LASTEXITCODE -ne 0) { $failures.Add("$($item.Suite)/$($item.Project) (exit $LASTEXITCODE)") }
  }

  $durations += $watch.Elapsed.TotalSeconds
  if ($Repeat -gt 1) { Write-Host ("Iteration {0}/{1}: {2:0.0} s, {3}" -f $iteration, $Repeat, $watch.Elapsed.TotalSeconds, $(if ($failures.Count -gt 0) { 'failed' } else { 'passed' })) }
  if ($failures.Count -gt 0) {
    Write-Host "Failed: $($failures -join '; ')"
    if ($Repeat -gt 1) { Write-Host "Stopped at iteration $iteration of $Repeat; durations: $(($durations | ForEach-Object { '{0:0.0} s' -f $_ }) -join ', ')" }
    exit 1
  }
}

if ($Repeat -gt 1) { Write-Host "All $Repeat iterations passed; durations: $(($durations | ForEach-Object { '{0:0.0} s' -f $_ }) -join ', ')" }
Write-Host "Suites passed: $($Suite -join ', ')"
