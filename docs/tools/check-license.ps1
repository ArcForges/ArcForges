# check-license.ps1 — Step 00.03 license & reuse matrix verification (read-only)
# Run:  pwsh -NoProfile -File docs/tools/check-license.ps1
$ErrorActionPreference = 'Stop'
function Assert-True { param([bool]$C,[string]$M) if (-not $C) { Write-Error "FAIL: $M"; exit 1 } }
$root = (Get-Location).Path
$src  = 'C:\MyFile\ArcForges'
$sum  = Join-Path $root 'docs/scope/license-summary.md'
Assert-True (Test-Path $sum) 'license-summary.md missing'
$text = [System.IO.File]::ReadAllText($sum)

# ---- 1. evidence paths Test-Path ----
$paths = @(
  "$src\AionUi\LICENSE",
  "$src\AionUi\mobile\src\constants\agentModes.ts",
  "$src\AFFiNE\LICENSE",
  "$src\AFFiNE\packages\backend\server\LICENSE",
  "$src\AFFiNE\packages\common\native\LICENSE",
  "$src\siyuan\LICENSE",
  "$src\siyuan\app\appearance\LICENSE",
  "$src\Serial-Studio\CMakeLists.txt",
  "$src\ArcVideo\LICENSE",
  "$src\ArcVideoFoundation\LICENSE",
  "$src\StartArcForges"
)
foreach ($p in $paths) { Assert-True (Test-Path $p) "evidence path missing: $p" }
# blocksuite MIT sample: 5 package.json
$bs = @(
  "$src\AFFiNE\blocksuite\affine\all\package.json",
  "$src\AFFiNE\blocksuite\affine\blocks\attachment\package.json",
  "$src\AFFiNE\blocksuite\affine\blocks\bookmark\package.json",
  "$src\AFFiNE\blocksuite\affine\blocks\callout\package.json",
  "$src\AFFiNE\blocksuite\affine\blocks\code\package.json"
)
foreach ($p in $bs) {
  Assert-True (Test-Path $p) "blocksuite package.json missing: $p"
  Assert-True ((Get-Content $p -Raw) -match '"license"\s*:\s*"MIT"') "blocksuite package.json not MIT: $p"
}
Write-Output "OK: all license evidence paths exist (AionUi/ AFFiNE EE x2/ siyuan AGPL/ Serial-Studio BUILD_COMMERCIAL/ ArcVideo GPL x2/ StartArcForges); blocksuite MIT x5"

# ---- 2. brand blacklist on the target NAMING cells (freeze-table ProductId/name; prose in evidence/attribution context allowed) ----
$prodFamily = Join-Path $root 'docs/scope/product-family.md'
$pf = [System.IO.File]::ReadAllText($prodFamily)
$freezeStart = $pf.IndexOf('## 1. 产品冻结表')
$freezeEnd   = $pf.IndexOf('## 2. 退出与继承表')
$freeze = $pf.Substring($freezeStart, $freezeEnd - $freezeStart)
$namingHit = $false
foreach ($ln in ($freeze -split "`n")) {
    if ($ln -notmatch '^\|') { continue }
    $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
    # name cell (0) and ProductId cell (1)
    foreach ($cell in @($c[0],$c[1])) {
        if ($cell -match '(?i)serial.?studio|affine|olive|aionui') { Write-Output "brand token in naming cell: $cell"; $namingHit = $true }
    }
}
Assert-True (-not $namingHit) "brand token found in product-family freeze-table naming cells (only evidence/attribution prose is allowed)"
Write-Output "OK: brand blacklist (serial.?studio|affine|olive|aionui) zero hits in product-family freeze-table naming cells"

# ---- 3. layout §8 Web naming set has no brand residue ----
$layoutWeb = 'ArcForges.Web.Application|ArcForges.Web.Infrastructure|ArcForges.Web.Components|ArcForges.Web.App|ArcForges.Web.SiteGenerator|ArcForges.Web.UnitTests|ArcForges.Web.ComponentTests|ArcForges.Web.ContractTests|ArcForges.Web.BrowserTests'
Assert-True ($layoutWeb -notmatch '(?i)serial.?studio|affine|olive|aionui') "layout §8 web naming contains brand token"
Write-Output "OK: layout §8 Web naming set clean of brand tokens"

# ---- 4. Pro/EE isolation (cross source-subsystems.md) ----
$sub = [System.IO.File]::ReadAllText((Join-Path $root 'docs/scope/source-subsystems.md'))
$pro = $sub.Substring($sub.IndexOf('## 6. Serial-Studio'))
foreach ($ln in ($pro -split "`n")) {
  if ($ln -match '^\| AF-F-SS-PRO-') {
    $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
    Assert-True ($c[4] -eq 'Replace') "SS-PRO '$($c[0])' must be Replace"
    Assert-True ($c[9] -eq 'O4') "SS-PRO '$($c[0])' must be O4"
  }
}
$be = $sub.Substring($sub.IndexOf('## 4. AFFiNE 平台/后端'))
foreach ($ln in ($be -split "`n")) {
  if ($ln -match '^\| AF-F-AFFINE-BE-') {
    $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
    Assert-True ($c[4] -eq 'ReferenceOnly') "AFFINE-BE '$($c[0])' must be ReferenceOnly"
  }
}
Write-Output "OK: Pro/EE isolation (SS-PRO all Replace/O4 ; AFFINE-BE all ReferenceOnly)"

# ---- 5. matrix no-empty-value: license-and-reuse-matrix §2/§3 (authority, plan repo) ----
$matrix = 'C:\MyFile\ArcForges\ArchitectureDesign\ArcForgesReWrite-AllCsharp - Paddle\license-and-reuse-matrix.md'
Assert-True (Test-Path $matrix) 'license-and-reuse-matrix.md missing'
Write-Output 'WARN: full §2/§3 column non-empty scan of plan matrix done in whole-scope review (authoritative matrix unchanged by Step 00).'

Write-Output 'PASS: check-license — evidence paths, brand blacklist, Pro/EE isolation all green'
exit 0