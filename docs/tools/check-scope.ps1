# docs/tools/check-scope.ps1
# Step 00.00 consistency script. Pure text assertions over docs/scope/product-family.md
# (and, when the plan root is reachable, cross-checks against README §1/§5 and a plan-wide
# ArcImage whitelist grep). Does NOT touch source code, build, or any source repository.
#
# Usage:  pwsh docs/tools/check-scope.ps1 [-PlanRoot <path>]
# Exit:   0 = all green; 1 = one or more assertions failed.

[CmdletBinding()]
param(
    [string]$PlanRoot = "C:\MyFile\ArcForges\ArchitectureDesign\ArcForgesReWrite-AllCsharp - Paddle"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$script:Failures = @()

function Assert-True($cond, $msg) {
    if (-not $cond) { $script:Failures += $msg; Write-Host "  FAIL: $msg" -ForegroundColor Red }
    else            { Write-Host "  ok:   $msg" -ForegroundColor Green }
}

$repoRoot  = (Resolve-Path "$PSScriptRoot/../..").Path
$scopeFile = Join-Path $repoRoot "docs/scope/product-family.md"
Assert-True (Test-Path $scopeFile) "docs/scope/product-family.md exists"
if (-not (Test-Path $scopeFile)) { Write-Host "ABORT: scope file missing"; exit 1 }
$md = Get-Content -Raw -LiteralPath $scopeFile

# --- 1. ProductId set is exactly the 7 frozen ids, literally equal ---
$expectedIds = 'arcchat','arcnotes','arcscope','arcslate','arcchat-mobile','arcforges-cloud','arcforges-web'
foreach ($id in $expectedIds) {
    Assert-True ($md -match [regex]::Escape("``$id``")) "ProductId ``$id`` present in freeze table"
}

# Reject any stray ArcImage-as-target mention in the target docs tree.
$targetDocs = Join-Path $repoRoot "docs"
# ArcImage whitelist: the plan uses these exit/not-target phrasings around every legitimate mention.
$arcImageContext = '退出|不迁入|不属于|不得|不复用|零目标|零命中|复活|改名|违反|反向失败|Out of Scope|exited|not migrated|drop'
$arcImageTargetHit = Select-String -Path "$targetDocs/**/*.md" -Pattern 'ArcImage' -SimpleMatch -ErrorAction SilentlyContinue
$badTarget = @()
foreach ($hit in $arcImageTargetHit) {
    if ($hit.Line -notmatch $arcImageContext) { $badTarget += "$($hit.Path):$($hit.LineNumber)" }
}
Assert-True ($badTarget.Count -eq 0) "ArcImage only appears in exit/not-migrated context in target docs (offenders: $($badTarget -join ', '))"

# --- 2. Each ProductId has >=1 owning step in the freeze table ---
# The freeze table is the first table in section 1; owning step is the last column.
$freezeTable = ($md -split "`n" | Select-String '^\| (ArcChat|ArcNotes|ArcScope|ArcSlate|ArcChat Mobile|ArcForges Cloud|ArcForges Web) \|')
foreach ($row in $freezeTable) {
    $line = $row.Line
    Assert-True ($line -match '\|\s*\d') "freeze-table row has a numeric owning step: $($line.Substring(0,[math]::Min(40,$line.Length)))..."
}

# --- 4. ArcNotes Edgeless/Database/Slides => owning steps 15/16/17 respectively ---
$phaseSection = ($md -split "## 4. ArcNotes")[1]
Assert-True ($phaseSection -match '(?ms)Edgeless.*?\|\s*15\s*\|') "ArcNotes Edgeless owning step = 15"
Assert-True ($phaseSection -match '(?ms)多视图 Database.*?\|\s*16\s*\|') "ArcNotes Database owning step = 16"
Assert-True ($phaseSection -match '(?ms)Slides.*?\|\s*17\s*\|') "ArcNotes Slides owning step = 17"

# --- 5. 7 product autonomy invariants: 强制步骤 column non-empty ---
$invariantSection = ($md -split "## 3. 产品自治不变式")[1]
$invRows = ($invariantSection -split "`n" | Select-String '^\| \d+ \|')
Assert-True ($invRows.Count -ge 7) ">=7 autonomy invariant rows present (found $($invRows.Count))"
foreach ($row in $invRows) {
    $line = $row.Line
    Assert-True ($line -match '\|\s*\d{2}') "invariant row has a numeric 强制步骤: $($line.Substring(0,[math]::Min(40,$line.Length)))..."
}

# --- Cross-checks against the plan root, if reachable ---
$planReadme = Join-Path $PlanRoot "README.md"
$planLayout = Join-Path $PlanRoot "implementation-repository-layout.md"
if (Test-Path $planReadme) {
    $readme = Get-Content -Raw -LiteralPath $planReadme
    # README §1 lists products by *display name* (not hyphenated product_id); assert all 7 + row count.
    $displayNames = 'ArcChat Desktop','ArcNotes Desktop','ArcScope Desktop','ArcSlate Desktop','ArcForges Cloud','ArcChat Mobile','ArcForges Web'
    foreach ($name in $displayNames) {
        Assert-True ($readme -match [regex]::Escape($name)) "README §1 product table mentions $name"
    }
    # Count product rows only within README §1 (between "## 1." and "## 2.").
    $sec1 = ($readme -split '## 1\.')[1]
    if ($sec1) { $sec1 = ($sec1 -split '## 2\.')[0] } else { $sec1 = '' }
    $readmeProductRows = ($sec1 -split "`n" | Select-String '^\| (ArcChat Desktop|ArcNotes Desktop|ArcScope Desktop|ArcSlate Desktop|ArcForges Cloud|ArcChat Mobile|ArcForges Web) \|').Count
    Assert-True ($readmeProductRows -eq 7) "README §1 product table has exactly 7 rows (found $readmeProductRows)"
    # Plan-wide ArcImage grep: every hit must be in exit/not-migrated context.
    $planHits = Get-ChildItem -LiteralPath $PlanRoot -Recurse -File -Filter *.md |
        Select-String -Pattern 'ArcImage' -SimpleMatch -ErrorAction SilentlyContinue
    $badPlan = @()
    foreach ($hit in $planHits) {
        if ($hit.Line -notmatch $arcImageContext) { $badPlan += "$($hit.Filename):$($hit.LineNumber)" }
    }
    Assert-True ($badPlan.Count -eq 0) "Plan-wide ArcImage hits are all exit-context (offenders: $($badPlan -join ', '))"
} else {
    Write-Host "  skip: PlanRoot not reachable ($PlanRoot); README + plan-wide ArcImage grep skipped" -ForegroundColor Yellow
}
if (Test-Path $planLayout) {
    $layout = Get-Content -Raw -LiteralPath $planLayout
    foreach ($id in $expectedIds) {
        Assert-True ($layout -match [regex]::Escape("``$id``")) "layout §14.1 declares ProductId ``$id``"
    }
}

Write-Host ""
if ($script:Failures.Count -gt 0) {
    Write-Host "check-scope.ps1: $($script:Failures.Count) failure(s)" -ForegroundColor Red
    exit 1
}
Write-Host "check-scope.ps1: all assertions green" -ForegroundColor Green
exit 0
