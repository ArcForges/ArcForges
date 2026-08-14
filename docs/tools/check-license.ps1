<#
SCOPE: Step 00.03 license & reuse gate. Asserts license evidence paths, license-matrix non-empty fields,
trademark blacklist over target naming, and Pro/EE isolation.

USAGE:
  pwsh -NoProfile -File docs/tools/check-license.ps1 -PlanRoot <plan> -TargetDocsRoot <target docs>

Read-only: never modifies a source repo or the plan.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PlanRoot,
    [Parameter(Mandatory = $true)][string]$TargetDocsRoot
)
$ErrorActionPreference = 'Stop'
$srcRoot = 'C:\MyFile\ArcForges'
$failures = [System.Collections.Generic.List[string]]::new()
function Assert([bool]$cond, [string]$msg) {
    if ($cond) { Write-Output ("PASS: " + $msg) }
    else { $failures.Add($msg); Write-Output ("FAIL: " + $msg) }
}
# Extract the consecutive markdown table whose header row has cell[0] == $firstHeader.
# Returns array of row cell-arrays (data rows only).
function Get-Table([string[]]$lines, [string]$firstHeader) {
    $rows = [System.Collections.Generic.List[object]]::new()
    $seenHeader = $false
    foreach ($l in $lines) {
        if ($l -match '^\|') {
            if ($l -match '^\|-\s*') { continue }
            $cells = ($l.Trim('|') -split '(?<!\\)\|' | ForEach-Object { $_.Trim() })
            if (-not $seenHeader) { if ($cells[0] -eq $firstHeader) { $seenHeader = $true }; continue }
            $rows.Add($cells)
        } elseif ($seenHeader) { break }
    }
    return $rows
}
$docLines = @(Get-Content -LiteralPath (Join-Path $PlanRoot 'license-and-reuse-matrix.md'))

# ---- 1. Evidence path existence ----
$evRel = @('AionUi/LICENSE','AionUi/mobile/src/constants/agentModes.ts','AFFiNE/LICENSE',
    'AFFiNE/packages/backend/server/LICENSE','AFFiNE/packages/common/native/LICENSE',
    'siyuan/LICENSE','siyuan/app/appearance/LICENSE','Serial-Studio/LICENSE.md',
    'Serial-Studio/CMakeLists.txt','ArcVideo/LICENSE','ArcVideoFoundation/LICENSE')
foreach ($p in $evRel) {
    Assert (Test-Path (Join-Path $srcRoot $p)) "Evidence path exists: $p"
}
$ee = Get-Content -Raw -LiteralPath (Join-Path $srcRoot 'AFFiNE\packages\backend\server\LICENSE')
Assert ($ee -match 'Enterprise Edition') 'AFFiNE backend/server/LICENSE is the EE license.'
$bsPkgs = @(Get-ChildItem (Join-Path $srcRoot 'AFFiNE\blocksuite') -Recurse -Filter package.json -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch 'node_modules' } | Select-Object -First 20)
$mitCount = @($bsPkgs | Where-Object { (Get-Content -Raw -LiteralPath $_.FullName) -match '"license"\s*:\s*"MIT"' }).Count
Assert ($mitCount -ge 5) "blocksuite package.json MIT sample >=5 (got $mitCount)."

# ---- 2. license-and-reuse-matrix.md §2 / §3 non-empty ----
$r2 = @(Get-Table $docLines '来源')
$bad2 = 0
foreach ($row in $r2) {
    # §2 header: 来源|目标产品|确切许可证(证据)|复用决策(§9.2)|移植方式|关键约束
    if ($row.Count -lt 6) { $bad2++ ; continue }
    foreach ($idx in 2,3,4,5) { if ([string]::IsNullOrWhiteSpace($row[$idx])) { $bad2++ } }
}
Assert ($r2.Count -ge 5 -and $bad2 -eq 0) "license-and-reuse-matrix §2: rows=$($r2.Count), empty cell count=$bad2."
$r3 = @(Get-Table $docLines '库（路径）')
$bad3 = 0
foreach ($row in $r3) {
    if ($row.Count -lt 4 -or [string]::IsNullOrWhiteSpace($row[3])) { $bad3++ }
}
Assert ($r3.Count -ge 10 -and $bad3 -eq 0) "license-and-reuse-matrix §3 vendored: rows=$($r3.Count), empty-decision=$bad3."

# ---- 3. trademark blacklist over target product naming ----
$pfFull = Get-Content -Raw -LiteralPath (Join-Path $TargetDocsRoot 'scope\product-family.md')
$tf = ($pfFull -split '(?ms)^## Table 1')[1]
$tf = ($tf -split '(?ms)^## ')[0]
$nameHits = [System.Collections.Generic.List[string]]::new()
foreach ($line in ($tf -split "`r?`n")) {
    if ($line -match '^\|') {
        $cells = ($line.Trim('|') -split '(?<!\\)\|' | ForEach-Object { $_.Trim() })
        if ($cells[0] -eq '产品名' -or $cells[0] -eq '') { continue }
        if ($cells[0] -match '^\-') { continue }
        if ([regex]::IsMatch("$($cells[0])|$($cells[1])", '(?i)serial.?studio|affine|olive|aionui')) { $nameHits.Add("$($cells[0])/$($cells[1])") }
    }
}
Assert ($nameHits.Count -eq 0) "Trademark must not appear in product name/ProductId: $($nameHits -join '; ')"

# ---- 4. Pro / EE isolation (cross feature-inventory) ----
$sss = Get-Content -Raw -LiteralPath (Join-Path $TargetDocsRoot 'scope\source-subsystems.md')
$cols = @{}; $proBad = 0; $beBad = 0; $proN = 0; $beN = 0
foreach ($line in ($sss -split "`r?`n")) {
    if (-not $line.StartsWith('|')) { continue }
    $cells = ($line.Trim('|') -split '(?<!\\)\|' | ForEach-Object { $_.Trim() })
    if ($cells[0] -eq 'FeatureId' -and $cells.Count -ge 13) { for($i=0;$i -lt $cells.Count;$i++){ $cols[$cells[$i]]=$i }; continue }
    if ($cells[0] -match '^AF-F-') {
        $dec = ($cells[$cols['DecisionClass']] -replace '\*','').Trim()
        $oracle = ($cells[$cols['OracleClass']] -replace '\*','').Trim()
        if ($cells[0] -match '-SS-PRO-') { $proN++; if ($dec -notmatch '^Replace' -or $oracle -notmatch '^O4') { $proBad++ } }
        if ($cells[0] -match '-AFFINE-BE-') { $beN++; if ($dec -notmatch '^ReferenceOnly') { $beBad++ } }
    }
}
Assert ($proN -ge 1 -and $proBad -eq 0) "SS-PRO isolation: $proN row(s) all Replace+O4 (bad=$proBad) [UD-LIC-5]."
Assert ($beN -ge 1 -and $beBad -eq 0) "AFFINE-BE isolation: $beN row(s) all ReferenceOnly (bad=$beBad) [UD-LIC-4]."

Write-Output ""
if ($failures.Count -eq 0) { Write-Output "License: PASS"; exit 0 }
else { Write-Output "License: FAIL ($($failures.Count) assertion(s))"; exit 1 }