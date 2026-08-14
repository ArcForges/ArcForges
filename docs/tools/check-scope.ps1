<#
SCOPE: Step 00.00 completeness gate checker (pure text, touches no source repo).
Checks docs/scope/product-family.md against the frozen product-set contract.

USAGE:
  pwsh -File docs/tools/check-scope.ps1 -PlanRoot <plan root> -TargetDocsRoot <worktree docs root>

Pure-text assertions only; never runs git, dotnet, cmake, npm, or modifies any source repository.
Exit code 0 = all checks pass; otherwise non-zero with a description of the first failure.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PlanRoot,
    [Parameter(Mandatory = $false)][string]$TargetDocsRoot = (Join-Path $PSScriptRoot '..')
)

$ErrorActionPreference = 'Stop'
$failures = [System.Collections.Generic.List[string]]::new()

function Assert($cond, [string]$msg) {
    if (-not $cond) { $failures.Add($msg); Write-Output ("FAIL: " + $msg) }
    else { Write-Output ("PASS: " + $msg) }
}

$productFamily = Join-Path $TargetDocsRoot 'scope\product-family.md'
if (-not (Test-Path $productFamily)) {
    Assert $false "product-family.md not found at $productFamily"
    Write-Output "Result: FAIL"
    exit 1
}
$pf = Get-Content -Raw -LiteralPath $productFamily

# Canonical ProductId set (from the step specification / completion gate, verbatim).
$canonicalIds = @('arcchat','arcnotes','arcscope','arcslate','arcchat-mobile','arcforges-cloud','arcforges-web')

# ---- 1. Freeze table (Table 1) row count and ProductId set ----
# Find the Table 1 section, then parse its markdown rows.
$table1 = ($pf -split "(?ms)^## Table 1")[1]
$table1 = ($table1 -split "(?ms)^## ")[0]
$rows = @()
$inHeader = $false
foreach ($line in $table1 -split "`r?`n") {
    if ($line -match '^\|') {
        if ($line -match '^\|-') { continue }            # separator
        if (-not $inHeader) { $inHeader = $true; continue } # header row
        $cells = ($line.Trim('|') -split '\|' | ForEach-Object { $_.Trim() })
        if ($cells.Count -ge 2 -and $cells[1]) { $rows += ,$cells }
    }
}
$freezeCount = $rows.Count
Assert ($freezeCount -eq 7) "Product freeze table Table 1 must have exactly 7 product rows (got $freezeCount)."
$pidCol = 1
$idsInTable = @($rows | ForEach-Object { $_.Trim() } ) # product id is cell index 1
$actualIds = @($rows | ForEach-Object { $cells = $_; $cells[1] })
# verify each row has non-empty name + id + owning steps
$badId = $actualIds | Where-Object { -not $canonicalIds -contains $_ }
Assert ($badId.Count -eq 0) "Freeze-table ProductIds must be subset of canonical set. Unexpected: [$($badId -join ',')]"
Assert ($actualIds.Count -eq $canonicalIds.Count -and (($actualIds | Sort-Object) -join ',') -eq (($canonicalIds | Sort-Object) -join ',')) `
    "ProductId set must equal canonical set verbatim: $($canonicalIds -join ','). Got: $($actualIds -join ',')"

# ---- 2. Each ProductId has >=1 owning step within 00-31 ----
$stepPattern = '\b((?:\d{2})(?:[.,]\d+)*)\b'
foreach ($id in $canonicalIds) {
    $row = $rows | Where-Object { $_[1] -eq $id }
    if (-not $row) { Assert $false "No freeze row for ProductId '$id'."; continue }
    # owning-step cell supports comma-separated steps and en-dash ranges, e.g. "10–11,14–17"
    $ownSteps = [System.Collections.Generic.List[int]]::new()
    foreach ($seg in ($row[6] -split '[,，]')) {
        if ($seg -match '(\d{1,2})\s*[-–—]\s*(\d{1,2})') {
            $a = [int]$matches[1]; $b = [int]$matches[2]
            for ($k = $a; $k -le $b; $k++) { $ownSteps.Add($k) }
        } else {
            $m = [regex]::Matches($seg, '\d{2}')
            if ($m.Count -ge 1) { $ownSteps.Add([int]$m[0].Value) }
        }
    }
    $distinct = @($ownSteps | Sort-Object -Unique)
    Assert ($distinct.Count -ge 1) "ProductId '$id' must have >=1 owning step in freeze table (column 拥有步骤)."
    foreach ($n in $distinct) {
        Assert ($n -ge 0 -and $n -le 31) "ProductId '$id' owning step '$n' must be within 00-31."
    }
}

# ---- 3. ArcImage whitelist grep across the whole plan directory ----
$planFiles = @(Get-ChildItem -Recurse -LiteralPath $PlanRoot -File -Filter '*.md' -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\.git\\' })
$arcImageHits = @()
foreach ($f in $planFiles) {
    $ln = 0
    foreach ($l in (Get-Content -LiteralPath $f.FullName)) {
        $ln++
        if ($l -match 'ArcImage') { $arcImageHits += ("{0}:{1}: {2}" -f $f.Name, $ln, $l.Trim()) }
    }
}
# Whitelist: every 'ArcImage' hit must be inside a negative/exit context. The plan's own authoritative
# documents express the ArcImage exit with several markers; the matcher covers the exact vocabulary the
# plan uses so that a mention is legal only when it negates migration or names ArcImage as non-target.
$exitMarkers = '退出|不迁入|不属于|不得成为目标|不是.*改名|不复用|零.*命中|复活|Out\s*of\s*Scope'
$badArcImage = @($arcImageHits | Where-Object { $_ -notmatch $exitMarkers -and $_ -notmatch '不迁入' })
Assert ($badArcImage.Count -eq 0) "Every 'ArcImage' hit must be in exit/not-migrated context. Violations:`n" + ($badArcImage -join "`n")
# Zero ArcImage inside a target identifier (product/project/namespace/type/DB name). Scan only the
# target deliverables for the precise identifier patterns; a project path, assembly, type, namespace or
# freeze-table product-name/ProductId using the word is forbidden. Prose negation is checked above.
$namingHits = [System.Collections.Generic.List[string]]::new()
foreach ($f in @(Get-ChildItem -Recurse -LiteralPath $TargetDocsRoot -File -Filter '*.md' -ErrorAction SilentlyContinue)) {
    $ln = 0
    foreach ($l in (Get-Content -LiteralPath $f.FullName)) {
        $ln++
        if ($l -match '(src[\\/](?:[^\\/]*ArcImage|ArcImage[^\\/]*)|[Nn]amespace\s+(?:\w+\.)*ArcImage|ArcImage\.[A-Za-z]|ArcForges\.[A-Za-z]*ArcImage|arcimage(?:\.csproj|\.slnx)\b|`arcimage`\|)') {
            $namingHits.Add(("{0}:{1}: {2}" -f $f.Name, $ln, $l.Trim()))
        }
    }
}
# freeze table product-name (cell 0) and ProductId (cell 1) must not be ArcImage/arcimage
foreach ($r in $rows) { Assert ($r[0] -notmatch 'ArcImage' -and $r[1] -notmatch '(?i)arcimage') "Freeze-table product name/ProductId must not be ArcImage. Got: $($r[0]) / $($r[1])" }
Assert ($namingHits.Count -eq 0) "ArcImage must not appear in target project/namespace/naming context.`n" + ($namingHits -join "`n")

# ---- 4. ArcNotes Edgeless / Database / Slides owning steps 15 / 16 / 17 ----
$notesSection = ($pf -split '(?ms)^## ArcNotes 分阶段表')[1]
$notesSection = ($notesSection -split "(?ms)^## ")[0]
$phaseRows = @()
$hdrSeen = $false
foreach ($line in $notesSection -split "`r?`n") {
    if ($line -match '^\|') {
        if ($line -match '^\|-') { continue }
        if (-not $hdrSeen) { $hdrSeen = $true; continue }
        $phaseRows += (($line.Trim('|') -split '\|') | ForEach-Object { $_.Trim() })
    }
}
function Get-PhaseStep([string]$label) {
    # find the phase row whose first cell contains $label and return owning-step numbers
    for ($i = 0; $i -lt $phaseRows.Count; $i += 3) {
        $name = $phaseRows[$i]; $steps = $phaseRows[$i+2]
        if ($name -match $label) {
            $nums = @($steps -split '[,，]' | ForEach-Object { ($_ -replace '[^0-9]','').Trim() } | Where-Object { $_ })
            if ($nums.Count -ge 1) { return @($nums | ForEach-Object { [int]$_ }) }
        }
    }
    return @()
}
$edgelessSteps = @(Get-PhaseStep 'Edgeless')
$dbSteps        = @(Get-PhaseStep 'Database')
$slidesSteps    = @(Get-PhaseStep 'Slides')
Assert (($edgelessSteps -contains 15) -and ($edgelessSteps.Count -ge 1)) "ArcNotes Edgeless must own step 15. Got: $($edgelessSteps -join ',')"
Assert (($dbSteps -contains 16) -and ($dbSteps.Count -ge 1)) "ArcNotes Database must own step 16. Got: $($dbSteps -join ',')"
Assert (($slidesSteps -contains 17) -and ($slidesSteps.Count -ge 1)) "ArcNotes Slides must own step 17. Got: $($slidesSteps -join ',')"

# ---- 5. Product autonomy invariants: exactly 7, enforcement step cell non-empty ----
$invSection = ($pf -split '(?ms)^## Product autonomy invariants')[1]
$invSection = ($invSection -split "(?ms)^## ")[0]
$invRows = @(); $invHdr = $false
foreach ($line in $invSection -split "`r?`n") {
    if ($line -match '^\|') {
        if ($line -match '^\|-') { continue }
        if ($line -notmatch '\|') { continue }
        if (-not $invHdr) { $invHdr = $true; continue }
        $invRows += (($line.Trim('|') -split '\|') | ForEach-Object { $_.Trim() })
    }
}
$invCount = ($invRows.Count / 5)  # each row is 5 cells: #, invariant, meaning, verification, enforcement steps
Assert ($invCount -eq 7) "Product autonomy invariants must be exactly 7 (parsed $invCount)."
for ($i = 0; $i -lt $invRows.Count; $i += 5) {
    $enforce = $invRows[$i+4]
    Assert ([string]::IsNullOrWhiteSpace($enforce) -eq $false) "Invariant #$($invRows[$i]) 强制步骤 cell must be non-empty."
}

Write-Output ""
if ($failures.Count -eq 0) {
    Write-Output "Result: PASS"
    exit 0
} else {
    Write-Output "Result: FAIL ($($failures.Count) assertion(s))"
    exit 1
}