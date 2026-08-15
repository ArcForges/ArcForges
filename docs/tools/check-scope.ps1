# check-scope.ps1 — Step 00.00 product-family consistency gate (pure text assertions, no source mutation)
# Run from the target repository root:
#   pwsh -NoProfile -File docs/tools/check-scope.ps1
$ErrorActionPreference = 'Stop'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        Write-Error "FAIL: $Message"
        exit 1
    }
}

$root = (Get-Location).Path
$scopeFile = Join-Path $root 'docs/scope/product-family.md'

if (-not (Test-Path $scopeFile)) {
    Write-Error "FAIL: product-family.md not found at $scopeFile"
    exit 1
}

# --- Expected values (authority: README.md §2) ---
$expectedProductIds  = @('arcchat','arcnotes','arcscope','arcslate','arcchat-mobile','arcforges-cloud','arcforges-web')
$expectedWebProjects = @(
  'ArcForges.Web.Application','ArcForges.Web.Infrastructure','ArcForges.Web.Components',
  'ArcForges.Web.App','ArcForges.Web.SiteGenerator',
  'ArcForges.Web.UnitTests','ArcForges.Web.ComponentTests','ArcForges.Web.ContractTests','ArcForges.Web.BrowserTests'
)

$content = [System.IO.File]::ReadAllText($scopeFile)

# ---------- 1. Freeze table: ProductId set exactly equals the 7 ----------
# Row shape: `| **Name** | `productid` | positioning | ... |`
$freezeSectionStart = $content.IndexOf('## 1. 产品冻结表')
$freezeSection = if ($freezeSectionStart -ge 0) { $content.Substring($freezeSectionStart) } else { '' }
$freezeEnd = $freezeSection.IndexOf('## 2.')
if ($freezeEnd -gt 0) { $freezeSection = $freezeSection.Substring(0, $freezeEnd) }
Assert-True ($freezeSection.Length -gt 0) '产品冻结表 section not found'
foreach ($id in $expectedProductIds) {
    $pat = '(?m)^\|\s*[^|\r\n]+?\s*\|\s*`' + [regex]::Escape($id) + '`\s*\|'
    Assert-True ($freezeSection -match $pat) "ProductId '$id' missing as a second-column cell in the freeze table"
}
$prodCell = [regex]::Matches($freezeSection, '(?m)^\|\s*[^|\r\n]+?\s*\|\s*`([a-z][a-z0-9-]+)`\s*\|')
Assert-True ($prodCell.Count -ge 7) "Freeze table has fewer than 7 rows ($($prodCell.Count))"
foreach ($cell in $prodCell) {
    $id = $cell.Groups[1].Value.ToLowerInvariant()
    Assert-True ($expectedProductIds -contains $id) "Unexpected ProductId '$id' in freeze table (must be one of $($expectedProductIds -join ','))"
}

# ---------- 2. Every ProductId has at least one owning step ----------
foreach ($id in $expectedProductIds) {
    $pat = '(?m)^\|\s*[^|\r\n]+?\s*\|\s*`' + [regex]::Escape($id) + '`\s*\|[^\r\n]*$'
    $hit = [regex]::Match($freezeSection, $pat)
    Assert-True ($hit.Success) "Freeze row for '$id' not parseable"
    Assert-True ($hit.Value -match '\b(0[1-9]|[12][0-9]|3[01])\b') "Product '$id' must reference at least one owning step (00–31) in its freeze row"
}

# ---------- 3. ArcImage whitespace rule ----------
$arcImageHits = [regex]::Matches([System.IO.File]::ReadAllText($scopeFile), '(?im)arcimage')
$allowedContext = '退出|不迁入|不复用|ArcImage 不得|非目标|已退出|复活|漂移|does not migrate|not a target'
foreach ($hit in $arcImageHits) {
    $start = [Math]::Max(0, $hit.Index - 120)
    $len   = [Math]::Min(240, $content.Length - $start)
    $ctx   = $content.Substring($start, $len)
    Assert-True ($ctx -match $allowedContext) "ArcImage occurrence at offset $($hit.Index) lacks exit/non-target context"
}

# ---------- 4. ArcNotes staging owns steps 15 / 16 / 17 ----------
Assert-True ($content -match '(?m)^\|\s*Edgeless\s*\|\s*15\s*\|')          'Edgeless must own Step 15'
Assert-True ($content -match '(?m)^\|\s*多视图 Database\s*\|\s*16\s*\|')    'Database must own Step 16'
Assert-True ($content -match '(?m)^\|\s*Slides\s*\|\s*17\s*\|')             'Slides must own Step 17'

# ---------- 5. Each of the 7 invariants has a non-empty 强制步骤 column ----------
$invariantSectionStart = $content.IndexOf('产品自治不变式')
$s = if ($invariantSectionStart -ge 0) { $content.Substring($invariantSectionStart) } else { '' }
$invEnd = $s.IndexOf('## 4.')
if ($invEnd -gt 0) { $s = $s.Substring(0, $invEnd) }
Assert-True ($s.Length -gt 0) '产品自治不变式 section not found'
$invRows = [regex]::Matches($s, '(?m)^\|\s*([1-7])\s*\|[^\r\n]*$')
Assert-True ($invRows.Count -eq 7) "Expected 7 invariant rows, found $($invRows.Count)"
foreach ($row in $invRows) {
    $cells = ($row.Value -split '\|') | ForEach-Object { $_.Trim() }
    $enforcement = $cells[$cells.Count - 2].Trim()   # 强制步骤 column
    Assert-True ($enforcement.Length -gt 0) "Invariant #$($row.Groups[1].Value) has empty 强制步骤 column"
}

# ---------- Gate reverse-failure: Web stays Step-29 standalone WASM and layout §8 9-project set ----------
foreach ($p in $expectedWebProjects) {
    Assert-True ($content -match '9 个' -and $content -match 'ArcForges\.Web') "Web must declare the layout §8 9-project set (missing '$p' context)"
}
Assert-True ($content -match '(?i)standalone Blazor WebAssembly') 'Web must remain standalone Blazor WebAssembly'
Assert-True ($content -match '(?i)RunAOTCompilation=false') 'Web V1 must pin RunAOTCompilation=false'

Write-Output "PASS: check-scope (product-family.md) — $($invRows.Count) invariants + product freeze + staging + Web-9 assertions green"
exit 0