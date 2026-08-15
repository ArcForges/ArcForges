# check-verification.ps1 — Step 00.05 verification-oracles gate
# Run:  pwsh -NoProfile -File docs/tools/check-verification.ps1
$ErrorActionPreference = 'Stop'
function Assert-True { param([bool]$C,[string]$M) if (-not $C) { Write-Error "FAIL: $M"; exit 1 } }
$root = (Get-Location).Path
$vo  = [System.IO.File]::ReadAllText((Join-Path $root 'docs/scope/verification-oracles.md'))
$sub = [System.IO.File]::ReadAllText((Join-Path $root 'docs/scope/source-subsystems.md'))

# ---- 1. OracleClass non-empty & in O1-O7; Copy/Rewrite/ReferenceOnly rows have an Oracle landing ----
$oracles = @('O1','O2','O3','O4','O5','O6','O7')
$bad = 0; $rows = 0
foreach ($ln in ($sub -split "`n")) {
    if ($ln -notmatch '^\| AF-F-') { continue }
    $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
    if ($c.Count -lt 13) { continue }
    $rows++
    $orc = $c[9] -replace '`',''
    Assert-True ($oracles -contains $orc) "row '$($c[0])' OracleClass '$orc' not in O1-O7"
    $dec = $c[4]
    if ($dec -match 'Copy|Rewrite|ReferenceOnly') {
        Assert-True ($oracles -contains $orc) "Copy/Rewrite/ReferenceOnly row '$($c[0])' must have an Oracle landing"
    }
}
Assert-True ($rows -ge 40) "source-subsystems.md has too few AF-F rows ($rows)"
Write-Output "OK: $rows AF-F rows, OracleClass all in O1-O7, Copy/Rewrite/ReferenceOnly all have Oracle landing"

# ---- 2. first-batch catalog >= 8 entries, 5 content columns complete ----
$catStart = $vo.IndexOf('## 2. 行为金样首批目录')
$catEnd   = $vo.IndexOf('## 3. 金样管理规则')
$cat = $vo.Substring($catStart, $catEnd - $catStart)
$entry = @()
foreach ($ln in ($cat -split "`n")) {
    if ($ln -match '^\| (\d+) \|') { $entry += $Matches[1] }
}
Assert-True ($entry.Count -ge 8) "golden first-batch catalog must have >=8 entries (got $($entry.Count))"
foreach ($ln in ($cat -split "`n")) {
    if ($ln -match '^\| \d+ \|') {
        $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
        # content cols: 条目,格式,捕获步骤,Oracle,拥有测试  (indices 1..5 after #)
        for ($i=1; $i -le 5; $i++) { Assert-True (-not [string]::IsNullOrWhiteSpace($c[$i])) "golden entry $($c[0]) missing content column $i" }
    }
}
Write-Output "OK: first-batch golden catalog has $($entry.Count) entries (>=8), 5 content columns complete"

# ---- 3. golden red-line: no 15+ consecutive lines of non-C# source code in the target docs tree ----
$redline = $false
foreach ($f in @('product-family.md','source-baseline.md','source-subsystems.md','license-summary.md','verification-oracles.md','sequencing.md','../compliance/copied-code.md','../compliance/copied-asset.md','../compliance/independent-reimplementation.md','../compliance/replacement-backlog.md','../compliance/third-party-license-register.md')) {
    $p = Join-Path $root (Join-Path 'docs/scope' $f)
    if (-not (Test-Path $p)) { $p = Join-Path $root (Join-Path 'docs/compliance' $f); if (-not (Test-Path $p)) { continue } }
    $lines = Get-Content $p
    $codeRun = 0
    foreach ($l in $lines) {
        $t = $l.Trim()
        if ($t -eq '' -or $t.StartsWith('#') -or $t.StartsWith('|') -or $t.StartsWith('>') -or $t.StartsWith('---')) { $codeRun = 0; continue }
        # only count compact source-like lines that are not markdown prose
        if ($t -match '^[a-zA-Z_][a-zA-Z0-9_]*\s*[=:{\(]' -or $t -match ';') { $codeRun++ } else { $codeRun = 0 }
        if ($codeRun -ge 15) { Write-Output "REDLINE: potential source snippet (>=15 lines) in $f"; $redline = $true }
    }
}
Assert-True (-not $redline) 'golden red-line violated: >=15 consecutive non-C# source lines found in target docs'
Write-Output 'OK: golden red-line — no 15+ consecutive non-C# source lines in target docs tree'

Write-Output 'PASS: check-verification — OracleClass coverage, first-batch catalog >=8, golden red-line clear'
exit 0