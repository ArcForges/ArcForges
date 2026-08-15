# check-source-coverage.ps1 — Step 00.02 source-coverage completeness gate (read-only verification)
# Verifies source-subsystems.md against the frozen source repos + feature-inventory merge expectations.
# Run:  pwsh -NoProfile -File docs/tools/check-source-coverage.ps1
$ErrorActionPreference = 'Stop'

function Assert-True { param([bool]$C,[string]$M) if (-not $C) { Write-Error "FAIL: $M"; exit 1 } }

$root = (Get-Location).Path
$doc  = Join-Path $root 'docs/scope/source-subsystems.md'
Assert-True (Test-Path $doc) 'source-subsystems.md missing'
$text = [System.IO.File]::ReadAllText($doc)

# ----- A: extract ipcBridge members from source and confirm each is covered in doc -----
function Get-IpcBridgeHtmlMembers {
    param([string]$Repo)
    $ps = [System.Diagnostics.ProcessStartInfo]::new(); $ps.FileName='git'
    $ps.ArgumentList.Add('-C'); $ps.ArgumentList.Add($Repo); $ps.ArgumentList.Add('show'); $ps.ArgumentList.Add('29c9271a59484e4696778cb80164f705245a6186:packages/desktop/src/common/adapter/ipcBridge.ts')
    $ps.RedirectStandardOutput=$true; $ps.UseShellExecute=$false
    $p=[System.Diagnostics.Process]::Start($ps); $t=$p.StandardOutput.ReadToEnd(); $p.WaitForExit()
    return $t
}
$ipc = Get-IpcBridgeHtmlMembers 'C:\MyFile\ArcForges\AionUi'
$memberSet = New-Object 'System.Collections.Generic.HashSet[string]'
$lines = $ipc -split "`n"
$ii = 0
while ($ii -lt $lines.Length) {
    $ln = $lines[$ii]
    if ($ln -match '^export const (\w+) = \{') {
        $depth = 1; $ii++
        while ($ii -lt $lines.Length -and $depth -gt 0) {
            $l = $lines[$ii]
            $lq = [regex]::Replace($l, "('[^']*'|`"[^`"]*`")", '')
            $depth += ([regex]::Matches($lq, '\{')).Count - ([regex]::Matches($lq, '\}')).Count
            if ($depth -eq 1 -and $l -match '^\s*([A-Za-z_$][\w$]*)\s*:') { [void]$memberSet.Add($Matches[1]) }
            $ii++
        }
    }
    $ii++
}
$covered = $true
foreach ($m in @($memberSet)) {
    if (-not ($text -match [regex]::Escape($m))) {
        Write-Output "MISSING ipcBridge member: $m"; $covered = $false
    }
}
Assert-True $covered 'ipcBridge export members not fully covered by source-subsystems.md (差集非空)'
Write-Output "OK: ipcBridge member coverage — $($memberSet.Count) members, diff set empty"

# ----- B: renderer pages / process dirs covered -----
$i14 = $text.IndexOf('### 1.4'); $i15 = $text.IndexOf('### 1.5'); $i12 = $text.IndexOf('### 1.2')
$rendererText = $text.Substring($i14, $i15 - $i14)
foreach ($d in @('conversation','cron','guid','login','settings','team')) {
    Assert-True ($rendererText -match "\b$d\b") "renderer page '$d' missing from 1.4"
}
$i16 = $text.IndexOf('### 1.6'); if ($i16 -lt 0) { $i16 = $text.IndexOf('## 2.') }
$processText = $text.Substring($i15, $i16 - $i15)
foreach ($d in @('bridge','services','pet','resources')) {
    Assert-True ($processText -match "\b$d\b") "process dir '$d' missing from 1.5"
}
# ----- C: three columns non-empty (DecisionClass / OracleClass / OwningStep) for every data row -----
$bad = 0
foreach ($ln in ($text -split "`n")) {
    if ($ln -notmatch '^\| AF-F-' ) { continue }
    $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
    if ($c.Count -ge 13) {
        if ([string]::IsNullOrWhiteSpace($c[4])) { Write-Output "empty DecisionClass in: $($c[0])"; $bad++ }
        if ([string]::IsNullOrWhiteSpace($c[9])) { Write-Output "empty OracleClass in: $($c[0])"; $bad++ }
        if ([string]::IsNullOrWhiteSpace($c[8])) { Write-Output "empty OwningStep in: $($c[0])"; $bad++ }
    }
}
Assert-True ($bad -eq 0) 'one or more feature rows have empty DecisionClass/OracleClass/OwningStep'

# ----- D: Serial-Studio Pro rows -> Decision Replace AND Oracle O4 (no Copy) -----
$proSectionStart = $text.IndexOf('## 6. Serial-Studio')
$proText = $text.Substring($proSectionStart)
foreach ($ln in ($proText -split "`n")) {
    if ($ln -match '^\| AF-F-SS-PRO-') {
        $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
        Assert-True ($c[4] -eq 'Replace') "SS-PRO row '$($c[0])' Decision must be Replace (UD-LIC-5)"
        Assert-True ($c[9] -eq 'O4') "SS-PRO row '$($c[0])' Oracle must be O4"
    }
}
# ----- E: AFFiNE BE rows -> all ReferenceOnly -----
$beText = $text.Substring($text.IndexOf('## 4. AFFiNE 平台/后端'))
foreach ($ln in ($beText -split "`n")) {
    if ($ln -match '^\| AF-F-AFFINE-BE-') {
        $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
        Assert-True ($c[4] -eq 'ReferenceOnly') "AFFINE-BE row '$($c[0])' Decision must be ReferenceOnly (UD-LIC-4)"
    }
}
# ----- F: siyuan rows -> ReferenceOnly + O3 -----
$syText = $text.Substring($text.IndexOf('## 5. siyuan'))
foreach ($ln in ($syText -split "`n")) {
    if ($ln -match '^\| AF-F-SIYUAN-') {
        $c = ($ln.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
        Assert-True ($c[4] -eq 'ReferenceOnly') "SIYUAN row '$($c[0])' Decision must be ReferenceOnly (UD-LIC-3)"
        Assert-True ($c[9] -eq 'O3') "SIYUAN row '$($c[0])' Oracle must be O3"
    }
}

Write-Output 'PASS: check-source-coverage — ipcBridge members covered (差集空), 3 columns non-empty, SS-PRO all Replace/O4, AFFINE-BE all ReferenceOnly, siyuan all ReferenceOnly/O3'
exit 0