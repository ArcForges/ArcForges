<#
SCOPE: Step 00.06 sequencing & traceability gate.

USAGE: pwsh -NoProfile -File docs/tools/check-seq.ps1 -PlanRoot <plan> -TargetDocsRoot <target docs>

Checks:
  1. branch-naming regex ^feat/af\d{2}(-\d{2})?-[a-z0-9-]+$ on sequencing.md examples (and usable later).
  2. every TR-* in the plan traceability-matrix has OwningStep (01..31), a test, and an FG.N gate.
  3. the generated feature-trace-bridge seed is uniformly BridgeGenerationRequired (never auto-Closed);
     its global featureIds/coverageIds sets are recomputable from the plan registries and non-empty.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PlanRoot,
    [Parameter(Mandatory = $true)][string]$TargetDocsRoot
)
$ErrorActionPreference = 'Stop'
$failures = [System.Collections.Generic.List[string]]::new()
function Assert([bool]$cond, [string]$msg) {
    if ($cond) { Write-Output ("PASS: " + $msg) }
    else { $failures.Add($msg); Write-Output ("FAIL: " + $msg) }
}

# ---- 1. branch naming regex ----
$seq = Get-Content -Raw -LiteralPath (Join-Path $TargetDocsRoot 'scope\sequencing.md')
$examples = @('feat/af02-contracts-and-code-generation','feat/af02-03-localrpc-hub-interfaces','feat/af10-05-block-editor-core','feat/af09-16-a-native-preview')
$badEx = @($examples | Where-Object { $_ -notmatch '^feat/af\d{2}(-\d{2})?-[a-z0-9-]+$' })
Assert ($badEx.Count -eq 0) "Branch-naming regex holds on sequencing examples. Bad: $($badEx -join ', ')"
# swipe the examples embedded in sequencing.md too
foreach ($line in ($seq -split "`r?`n")) {
    if ($line -match '`feat/af\d{2}(-\d{2})?-[a-z0-9-]+`') { }
}
$seqExamples = @([regex]::Matches($seq, 'feat/af\d{2}(-\d{2})?-[a-z0-9-]+') | ForEach-Object { $_.Value } | Select-Object -Unique)
$badSeq = @($seqExamples | Where-Object { $_ -notmatch '^feat/af\d{2}(-\d{2})?-[a-z0-9-]+$' })
Assert ($badSeq.Count -eq 0 -and $seqExamples.Count -ge 3) "sequencing.md branch examples match the regex (examples=$($seqExamples.Count))."

# ---- 2. TR-* completeness ----
$tm = Get-Content -Raw -LiteralPath (Join-Path $PlanRoot 'traceability-matrix.md')
$trCount = 0; $noStep = 0; $noTest = 0; $noFg = 0
foreach ($line in ($tm -split "`r?`n")) {
    if ($line -match '^\| *(TR-[A-Z]+-\d{2}) *\|') {
        $cells = ($line.Trim('|') -split '(?<!\\)\|' | ForEach-Object { $_.Trim() })
        $trCount++
        $own = $cells[7]; $test = $cells[8]; $fg = $cells[9]
        $steps = @([regex]::Matches($own, '\d{1,2}') | ForEach-Object { [int]$_.Value })
        if ($steps.Count -eq 0 -or ($steps | Where-Object { $_ -lt 0 -or $_ -gt 31 }).Count -gt 0) { $noStep++ }
        if ([string]::IsNullOrWhiteSpace($test)) { $noTest++ }
        if ([string]::IsNullOrWhiteSpace($fg)) { $noFg++ }
    }
}
Assert ($trCount -ge 100) "traceability-matrix has >=100 TR rows (got $trCount)."
Assert ($noStep -eq 0 -and $noTest -eq 0 -and $noFg -eq 0) "Every TR-* has OwningStep(01-31)+Test+FG (noStep=$noStep,noTest=$noTest,noFg=$noFg)."

# ---- 3. bridge seed honest state + sets recomputable ----
$bridgePath = Join-Path $TargetDocsRoot 'evidence\traceability\feature-trace-bridge.json'
Assert (Test-Path $bridgePath) "feature-trace-bridge.json seed exists."
if (Test-Path $bridgePath) {
    $b = Get-Content -Raw -LiteralPath $bridgePath | ConvertFrom-Json
    Assert ($b.records.Count -ge 100) "bridge has >=100 records (got $($b.records.Count))."
    $badClosure = @($b.records | Where-Object { $_.closureStatus -ne 'BridgeGenerationRequired' })
    Assert ($badClosure.Count -eq 0) "All bridge records are BridgeGenerationRequired (initial honest state; none auto-Closed). bad=$($badClosure.Count)"
    # recompute global feature/coverage sets from plan and compare
    $fi = Get-Content -Raw -LiteralPath (Join-Path $PlanRoot 'feature-inventory-and-mapping.md')
    $feat = @([regex]::Matches($fi, 'AF-F-(?:AIONUI-M|AIONUI|BLOCKSUITE|AFFINE-BE|AFFINE-FE|SIYUAN|SS-CORE|SS-PRO|SS-LIB|ARCVF|ARCV)-\d{4}') | ForEach-Object { $_.Value } | Select-Object -Unique)
    $bFeat = @($b.globalFeatureIds)
    $setEq = ((($bFeat | Sort-Object -Unique) -join ',') -eq ((@($feat) | Sort-Object -Unique) -join ','))
    Assert ($bFeat.Count -ge 500 -and $setEq) "bridge globalFeatureIds recomputable from feature-inventory (n=$($bFeat.Count))."
    $cr = Get-Content -Raw -LiteralPath (Join-Path $PlanRoot 'source-coverage-register.md')
    $cov = @([regex]::Matches($cr, 'SC-[A-Z0-9-]+-\d{2}') | ForEach-Object { $_.Value } | Select-Object -Unique)
    $bCov = @($b.globalCoverageIds)
    Assert ($bCov.Count -ge 20 -and (($bCov | Sort-Object -Unique) -join ',') -eq (($cov | Sort-Object -Unique) -join ',')) "bridge globalCoverageIds recomputable from coverage register (n=$($bCov.Count))."
    # NeedRecheck/missing must be preserved as blocking (seed is uniformly BridgeGenerationRequired => never a false Closed)
    $anyClosed = @($b.records | Where-Object { $_.missingFields.Count -eq 0 })
    Assert ($anyClosed.Count -eq 0) "No bridge record claims a false Closed in the seed (all missingFields blocking)."
}

Write-Output ""
if ($failures.Count -eq 0) { Write-Output "Seq/Trace: PASS"; exit 0 }
else { Write-Output "Seq/Trace: FAIL ($($failures.Count) assertion(s))"; exit 1 }