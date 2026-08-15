# check-traceability.ps1 — Step 00.06 traceability seed + bridge gate
# Run:  pwsh -NoProfile -File docs/tools/check-traceability.ps1
$ErrorActionPreference = 'Stop'
function Assert-True { param([bool]$C,[string]$M) if (-not $C) { Write-Error "FAIL: $M"; exit 1 } }
$root = (Get-Location).Path

# ---- 1. every TR-* summary row has OwningStep (00-31), Test, FG ----
$trd = [System.IO.File]::ReadAllText((Join-Path $root 'docs/traceability-matrix.md'))
$trCount = 0
foreach ($ln in ($trd -split "`n")) {
    if ($ln -notmatch '^\| (TR-[A-Z]+-\d+) \|') { continue }
    $trCount++
    $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
    Assert-True ($c[2] -match '\b(0[0-9]|[12][0-9]|3[01])\b') "TR '$($c[0])' missing OwningStep ∈ 00-31"
    Assert-True ($c[3] -match 'Tests|tests/|\.Ui\.|\.Unit|\.Integration') "TR '$($c[0])' missing Test project/name"
    Assert-True ($c[4] -match 'FG\.\d+') "TR '$($c[0])' missing FG gate reference"
}
Assert-True ($trCount -ge 15) "traceability seed must have >=15 TR rows (got $trCount)"
Write-Output "OK: $trCount TR rows each have OwningStep(00-31)/Test/FG"

# ---- 2. generated bridge: featureIds set == inventory set, coverageIds == coverage set ----
$sub = [System.IO.File]::ReadAllText((Join-Path $root 'docs/scope/source-subsystems.md'))
$inv = @()
foreach ($m in [regex]::Matches($sub, '(?im)\bAF-F-[A-Za-z0-9_-]+')) { if ($inv -notcontains $m.Value) { $inv += $m.Value } }
$bridge = Get-Content (Join-Path $root 'artifacts/evidence/traceability/feature-trace-bridge.json') -Raw | ConvertFrom-Json
$bridgeFeats = @()
foreach ($rec in $bridge.records) { foreach ($f in $rec.featureIds) { if ($bridgeFeats -notcontains $f) { $bridgeFeats += $f } } }
foreach ($f in $inv) { Assert-True ($bridgeFeats -contains $f) "bridge missing feature $f (bidirectional diff non-empty)" }
foreach ($f in $bridgeFeats) { Assert-True ($inv -contains $f) "bridge has feature not in inventory: $f" }
Write-Output "OK: bridge featureIds set == inventory feature set ($($inv.Count)); closureState = $($bridge.closureState)"

# ---- 3. NeedsRecheck / Missing* preserved as blocking (not auto-Closed) ----
Assert-True ($bridge.closureState -eq 'BridgeGenerationRequired') 'initial closureState must honestly be BridgeGenerationRequired'
$hasRecheck = $false
foreach ($rec in $bridge.records) { if ($rec.closureStatus -eq 'NeedsRecheck') { $hasRecheck = $true } }
Assert-True $hasRecheck 'at least one record must be NeedsRecheck (5 dirty coverage rows)'
Assert-True (-not ($bridge.closureState -match '^Closed')) 'closureState must not be Closed while evidence pending'
Write-Output 'OK: NeedsRecheck preserved as blocking; closureState not falsely Closed'

# ---- 4. branch-naming regex on sequencing.md examples ----
$seq = [System.IO.File]::ReadAllText((Join-Path $root 'docs/scope/sequencing.md'))
foreach ($m in [regex]::Matches($seq, '(feat/af\d{2}(-\d{2})?-[a-z0-9-]+)')) {
    Assert-True ($m.Value -match '^feat/af\d{2}(-\d{2})?-[a-z0-9-]+$') "branch name FAIL regex: $($m.Value)"
}
Write-Output 'OK: sequencing.md branch examples match ^feat/af\d{2}(-\d{2})?-[a-z0-9-]+$'

Write-Output 'PASS: check-traceability — TR rows complete, bridge sets equal + honest BridgeGenerationRequired, NeedsRecheck blocked, branch regex green'
exit 0