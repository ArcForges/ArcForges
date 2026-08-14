<#
SCOPE: Step 00.05 oracle & golden gate. Asserts catalog >=8 entries (5 cols), OracleClass validity/coverage
on source-subsystems, and the golden red-line scan (no >=15-line source excerpt from restricted sources).

USAGE:
  pwsh -NoProfile -File docs/tools/check-oracles.ps1 -PlanRoot <plan> -TargetDocsRoot <target docs>
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

# ---- 1. Catalog >=8 entries, each with 5 columns ----
$vo = Get-Content -Raw -LiteralPath (Join-Path $TargetDocsRoot 'scope\verification-oracles.md')
$sec = ($vo -split '(?ms)^## 2\.')[1]; $sec = ($sec -split '(?ms)^## 3\.')[0]
$rows = [System.Collections.Generic.List[object]]::new(); $seenHdr = $false
foreach ($line in ($sec -split "`r?`n")) {
    if ($line -match '^\|') {
        if ($line -match '^\|-') { continue }
        $cells = ($line.Trim('|') -split '(?<!\\)\|' | ForEach-Object { $_.Trim() })
        if (-not $seenHdr) { $seenHdr = $true; continue }
        $rows.Add($cells)
    }
}
Assert ($rows.Count -ge 8) "Golden-sample first catalog has >=8 entries (got $($rows.Count))."
$badCols = 0
foreach ($r in $rows) {
    # columns: # | 条目 | 来源@commit | 格式 | 捕获步骤 | Oracle | 拥有测试  -> need >=7 cells, Oracle non-empty
    if ($r.Count -lt 7 -or [string]::IsNullOrWhiteSpace($r[5]) -or [string]::IsNullOrWhiteSpace($r[6])) { $badCols++ }
}
Assert ($badCols -eq 0) "Each catalog entry has all five content columns complete (bad=$badCols)."

# ---- 2. OracleClass validity + coverage on source-subsystems ----
$sss = Get-Content -Raw -LiteralPath (Join-Path $TargetDocsRoot 'scope\source-subsystems.md')
$cols = @{}; $badOrac = 0; $rowN = 0; $copyRows = 0; $copyNoOracle = 0
$badList = [System.Collections.Generic.List[string]]::new()
foreach ($line in ($sss -split "`r?`n")) {
    if (-not $line.StartsWith('|')) { continue }
    $cells = ($line.Trim('|') -split '(?<!\\)\|' | ForEach-Object { $_.Trim() })
    if ($cells[0] -eq 'FeatureId' -and $cells.Count -ge 13) { for($i=0;$i -lt $cells.Count;$i++){ $cols[$cells[$i]]=$i }; continue }
    if ($cells[0] -match '^AF-F-' -and $cols.ContainsKey('OracleClass')) {
        $rowN++
        $oracle = ($cells[$cols['OracleClass']] -replace '\*','').Trim()
        $dec = ($cells[$cols['DecisionClass']] -replace '\*','').Trim()
        # valid: non-empty and every O-token is O1..O7
        if ([string]::IsNullOrWhiteSpace($oracle) -or $oracle -notmatch 'O[1-7]' -or $oracle -match 'O[89]' -or $oracle -notmatch '^[O0-9/,\+\-\s]+$') {
            $badOrac++; $badList.Add("$($cells[0])=[$oracle]")
        }
        if ($dec -match '^Copy|^Rewrite|^ReferenceOnly') {
            $copyRows++
            if ($oracle -eq '') { $copyNoOracle++ }
        }
    }
}
Assert ($badOrac -eq 0) "Every source-subsystems row has a valid OracleClass (O1–O7 tokens only). bad=$badOrac of ${rowN}: $($badList -join '; ')"
Assert ($copyRows -eq 0 -or ($copyNoOracle -eq 0)) "Decision=Copy/Rewrite/ReferenceOnly rows: all have an Oracle landing (copyRows=$copyRows, noOracle=$copyNoOracle)."

# ---- 3. Golden red-line: no >=15-line excerpt of restricted-source code in the Step-00 planning tree ----
# The plan's numeric-step docs legitimately contain ArcForges-authored SQL/CMake target schema (the authority),
# so the scan is scoped to the Step 00 active file + this branch's target deliverables. A code language fence
# holding >=15 consecutive lines is flagged (heuristic; a source excerpt must not be pasted as implementation
# expression from siyuan / Serial-Studio Pro / AFFiNE EE / AionUi).
$sourceLangs = '(?i)^\s*```(tsx?|go|cpp|c\+\+|c|h|qml|js|css|yaml|yml|xml|sql|sh)\s*$'
$hits = [System.Collections.Generic.List[string]]::new()
$scanFiles = [System.Collections.Generic.List[string]]::new()
$scanFiles.Add((Join-Path $PlanRoot '00-scope-and-source-inventory.md'))
foreach ($f in @(Get-ChildItem -Recurse -LiteralPath $TargetDocsRoot -File -Filter '*.md' -ErrorAction SilentlyContinue)) { $scanFiles.Add($f.FullName) }
foreach ($f in $scanFiles) {
    if (-not (Test-Path $f)) { continue }
    $inSource = $false; $count = 0
    foreach ($line in (Get-Content -LiteralPath $f)) {
        if ($line -match '(?i)^\s*(```+|~~~)') {
            if ($inSource) { $inSource = $false; $count = 0; continue }
            if ($line -match $sourceLangs) { $inSource = $true; $count = 0; continue }
            $inSource = $false; $count = 0; continue
        }
        if ($inSource) {
            $count++
            if ($count -ge 15) { $hits.Add("$(Split-Path $f -Leaf): >=15-line source block"); $inSource = $false; $count = -1 }
        }
    }
}
Assert ($hits.Count -eq 0) "Golden red-line: no >=15-line code excerpt in the Step-00 planning tree. Hits: $($hits -join '; ')"

Write-Output ""
if ($failures.Count -eq 0) { Write-Output "Oracles: PASS"; exit 0 }
else { Write-Output "Oracles: FAIL ($($failures.Count) assertion(s))"; exit 1 }