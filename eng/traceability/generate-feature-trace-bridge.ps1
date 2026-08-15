# generate-feature-trace-bridge.ps1 — Step 00.06 machine-readable Feature/Coverage trace bridge generator
# Reads FeatureIds from docs/scope/source-subsystems.md, CoverageIds from docs/scope/source-baseline.md,
# and TR requirement rows from docs/traceability-matrix.md; writes
# artifacts/evidence/traceability/feature-trace-bridge.json.
# Initial state is HONESTLY BridgeGenerationRequired (implementation evidence not yet generated); records
# touching a NeedsRecheck coverage row are NeedsRecheck. Feature/Coverage closure only happens at
# implementation/release when foreign keys + tests + gates exist.
# Run:  pwsh -NoProfile -File eng/traceability/generate-feature-trace-bridge.ps1
$ErrorActionPreference = 'Stop'
$root = (Get-Location).Path

# ---------- 1. feature IDs from source-subsystems.md ----------
$sub = [System.IO.File]::ReadAllText((Join-Path $root 'docs/scope/source-subsystems.md'))
$featureIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($m in [regex]::Matches($sub, '(?im)\bAF-F-[A-Za-z0-9_-]+')) {
    [void]$featureIds.Add($m.Value)
}
# ---------- 2. coverage IDs + status from source-baseline.md ----------
$bl = [System.IO.File]::ReadAllText((Join-Path $root 'docs/scope/source-baseline.md'))
$coverage = [ordered]@{}
foreach ($ln in ($bl -split "`n")) {
    if ($ln -match '\b(SC-[A-Z]+-\d+)\b') {
        $cid = $Matches[1]
        $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
        $status = if ($c.Count -gt 8) { ($c[8] -replace '`','') } else { 'Read' }
        if (-not $coverage.Contains($cid)) { $coverage[$cid] = $status }
    }
}
# ---------- 3. TR rows + owningSteps + Test + FG from docs/traceability-matrix.md ----------
$trd = [System.IO.File]::ReadAllText((Join-Path $root 'docs/traceability-matrix.md'))
$trs = [System.Collections.Generic.List[object]]::new()
foreach ($ln in ($trd -split "`n")) {
    if ($ln -notmatch '^\| (TR-[A-Z]+-\d+) \|') { continue }
    $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
    $trs.Add([pscustomobject]@{ Id=$Matches[1]; Summary=$c[1]; Steps=$c[2]; Test=$c[3]; Fg=$c[4] })
}

# product→feature-prefix mapping for primary ownership
$map = @{
  'CHAT'  = @('AF-F-AIONUI')
  'NOTE'  = @('AF-F-BLOCKSUITE','AF-F-SIYUAN')
  'SCOPE' = @('AF-F-SS')
  'SLATE' = @('AF-F-ARCV','AF-F-ARCVF')
  'CLOUD' = @('AF-F-AFFINE-BE')
  'MOB'   = @('AF-F-AIONUI-M')
}
function DomainFromId { param([string]$id) foreach ($k in $map.Keys) { foreach ($p in $map[$k]) { if ($id -like "$p*") { return $k } } }; return 'ARC' }

# assign every feature to its primary TR domain
$domainFeatures = @{}
foreach ($f in $featureIds) {
    $d = DomainFromId $f
    if (-not $domainFeatures.ContainsKey($d)) { $domainFeatures[$d] = [System.Collections.Generic.List[string]]::new() }
    $domainFeatures[$d].Add($f)
}

$records = [System.Collections.Generic.List[object]]::new()
$seenFeatures = [System.Collections.Generic.HashSet[string]]::new()
foreach ($tr in $trs) {
    $domain = ($tr.Id -replace '^TR-','') -replace '-.*$',''
    $feats = @()
    if ($domainFeatures.ContainsKey($domain)) { $feats = @($domainFeatures[$domain]) }
    foreach ($f in $feats) { [void]$seenFeatures.Add($f) }
    $covIds = @($coverage.Keys | Where-Object { $_ -like "SC-*" })
    $isNeedsRecheck = @($coverage.Keys | Where-Object { $coverage[$_] -eq 'NeedsRecheck' }).Count -gt 0
    $missing = @('implementation testIds','gateIds','evidenceHash','contractIds[]/dataIds[]/uiSurfaceIds[] registration')
    $records.Add([pscustomobject]@{
        traceId = $tr.Id
        featureIds = $feats
        coverageIds = $covIds
        requirementId = $tr.Id
        targetProduct = $domain
        owningSteps = @($tr.Steps)
        testIds = @()
        gateIds = @()
        sourceBaselines = @('AionUi@29c9271a…','AFFiNE@81df4751…','siyuan@eef10568…','Serial-Studio@639daafb…','ArcVideo@caf56513…','ArcVideoFoundation@139eecaa…')
        closureStatus = if ($isNeedsRecheck) { 'NeedsRecheck' } else { 'BridgeGenerationRequired' }
        missingFields = $missing
        evidenceHash = $null
    })
}
# feature NOT owned by any TR -> log (must be empty for closure; here ARC/FIPS...) — assign leftovers to TR-ARC-01
$leftover = @($featureIds | Where-Object { -not $seenFeatures.Contains($_) })
if ($leftover.Count -gt 0) {
    foreach ($rec in $records) { if ($rec.traceId -eq 'TR-ARC-01') { $rec.featureIds = @($rec.featureIds) + $leftover } }
}

$bridge = [pscustomobject]@{
    schemaVersion = 1
    generated = 'Step 00.06 seed'
    closureState = 'BridgeGenerationRequired'
    sourceBaselines = @('AionUi@29c9271a59484e4696778cb80164f705245a6186','AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6','siyuan@eef10568384e2e7cf547adb029ae46a72e43c287','Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f','ArcVideo@caf56513278703adec0c2933ec235bb864d72e31','ArcVideoFoundation@139eecaaa79dbad743a146f174a9c89a66ed594b')
    records = @($records)
}
$outDir = Join-Path $root 'artifacts/evidence/traceability'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$out = Join-Path $outDir 'feature-trace-bridge.json'
$bridge | ConvertTo-Json -Depth 8 | Set-Content -Path $out -Encoding utf8
Write-Output "WROTE: $out (records=$($records.Count), featureIds=$($featureIds.Count), coverageIds=$($coverage.Count), closureState=BridgeGenerationRequired)"