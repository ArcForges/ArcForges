# check-manifests.ps1 — Step 00.04 five reuse manifests completeness gate
# Run:  pwsh -NoProfile -File docs/tools/check-manifests.ps1
$ErrorActionPreference = 'Stop'
function Assert-True { param([bool]$C,[string]$M) if (-not $C) { Write-Error "FAIL: $M"; exit 1 } }
$root = (Get-Location).Path
$compliance = Join-Path $root 'docs/compliance'

$files = @('copied-code.md','copied-code.json','copied-asset.md','independent-reimplementation.md','replacement-backlog.md','third-party-license-register.md')
foreach ($f in $files) { Assert-True (Test-Path (Join-Path $compliance $f)) "manifest missing: $f" }

# ---- 1. copied-code.json: 6 rows, required fields non-empty, ManifestIds unique ----
$cc = Get-Content (Join-Path $compliance 'copied-code.json') -Raw | ConvertFrom-Json
Assert-True ($cc.rows.Count -ge 6) "copied-code.json must have >=6 first-batch rows (got $($cc.rows.Count))"
$req = @('ManifestId','SourcePath','SourceRepository','SourceCommit','OriginalLicense','TargetProduct','TargetProject','ReuseType','TemporaryOrPermanent','Attribution','ReleaseRestriction','Evidence')
$ids = @()
foreach ($r in $cc.rows) {
    foreach ($f in $req) { Assert-True (-not [string]::IsNullOrWhiteSpace($r.$f)) "copied-code row '$($r.ManifestId)' empty field $f" }
    Assert-True ($ids -notcontains $r.ManifestId) "duplicate ManifestId $($r.ManifestId)"
    $ids += $r.ManifestId
}
Write-Output "OK: copied-code.json $($cc.rows.Count) rows, required fields non-empty, ids unique"

# ---- 2. decision coverage: UD-LIC-2..5 each referenced by at least one manifest ----
$ccMd   = Get-Content (Join-Path $compliance 'copied-code.md') -Raw
$irMd   = Get-Content (Join-Path $compliance 'independent-reimplementation.md') -Raw
$rbMd   = Get-Content (Join-Path $compliance 'replacement-backlog.md') -Raw
$tplrMd = Get-Content (Join-Path $compliance 'third-party-license-register.md') -Raw
Assert-True ($ccMd -match 'UD-LIC-2') 'UD-LIC-2 not referenced by a manifest row'
Assert-True ($irMd -match 'UD-LIC-3') 'UD-LIC-3 not referenced by a manifest row'
Assert-True ($irMd -match 'UD-LIC-4') 'UD-LIC-4 not referenced by a manifest row'
Assert-True ($irMd -match 'UD-LIC-5') 'UD-LIC-5 not referenced by a manifest row'
Write-Output 'OK: UD-LIC-2/3/4/5 each covered by at least one manifest row'

# ---- 3. suspicious-IP isolation in copied-asset.md ----
$ca = Get-Content (Join-Path $compliance 'copied-asset.md') -Raw
$normalBad = $false; $replaceBad = $false
foreach ($ln in ($ca -split "`n")) {
    if ($ln -match '^\| AS-\d{4} ' -and $ln -match '\| true \|') { Write-Output "FAIL: normal asset row has SuspiciousThirdPartyIp=true: $ln"; $normalBad = $true }
    if ($ln -match '^\| AS-R\d+ ' -and $ln -notmatch '\| Replace \|') { Write-Output "FAIL: replace-section row not Status=Replace: $ln"; $replaceBad = $true }
}
Assert-True (-not $normalBad) 'a normal (TargetPath-assigned) Copied-Asset row must not have SuspiciousThirdPartyIp=true'
Assert-True (-not $replaceBad) 'every replace-section row (SuspiciousThirdPartyIp=true) must have Status=Replace'
Write-Output 'OK: suspicious-third-party-ip rows are Replace-only and excluded from normal TargetPath rows'

# ---- 4. third-party register: prohibited families not table entries, frozen baseline present ----
foreach ($bad in @('Nerdbank','Fory','AvaloniaEdit','ClosedXML','CSharpMath.Avalonia','NAudio','SqlSugar','Dapper')) {
    Assert-True ($tplrMd -notmatch "(?im)^\|\s*$([regex]::Escape($bad))") "prohibited dependency family '$bad' must not be a register table entry"
}
Assert-True ($tplrMd -match '12.1.1' -and $tplrMd -match '9.0.1') 'frozen baseline (Avalonia 12.1.1, FFmpeg 9.0.1) must be present'
Assert-True ($tplrMd -match '36677bbd0b3bf11da7376e62e14bffcc54d2eaeb') 'frozen vcpkg checkout must be present'

Write-Output 'PASS: check-manifests — 5+ manifests present, copied-code rows complete+unique, UD-LIC-2..5 covered, suspicious-IP Replace-only, review/third-party baseline present'
exit 0