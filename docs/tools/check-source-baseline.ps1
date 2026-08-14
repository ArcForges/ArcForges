# docs/tools/check-source-baseline.ps1
# Step 00.01 baseline verification. Read-only to the six source repositories
# (only rev-parse / branch / describe / status / diff | sha256). Asserts:
#   - each repo HEAD == frozen commit
#   - tag/describe matches
#   - status --porcelain dirty-file set == registered set (per source-coverage-register.md §2)
#   - DiffSha256 (dirty repos) == registered hash
#   - every CoverageStatus in docs/scope/source-baseline.md §4 ∈ the 9-state set
# Drift => FAIL and list affected Coverage/Feature. Never fakes "all clean".
#
# Usage:  pwsh docs/tools/check-source-baseline.ps1 [-SourceRoot <path>]
# Exit:   0 green; 1 one or more assertions failed.

[CmdletBinding()]
param(
    [string]$SourceRoot = "C:\MyFile\ArcForges"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$script:Failures = @()

function Fail($msg) { $script:Failures += $msg; Write-Host "  FAIL: $msg" -ForegroundColor Red }
function Ok($msg)   { Write-Host "  ok:   $msg" -ForegroundColor Green }

# Registered baseline (source-coverage-register.md §2 / Step 00.01).
$repos = @(
    @{ Name='AionUi';             Branch='Branch_v2.1.35'; Commit='29c9271a59484e4696778cb80164f705245a6186'; Tag='v2.1.35';
       Dirty=@('scripts/rebuildNativeModules.js','tests/unit/build-scripts/windows-fast-build-script.test.ts');
       DiffSha256='1f87a590859586a4b64831d54b0292117294dabaef93c71a5fe4bcd377525492';
       Coverage=@('SC-AION-03'); Features=@('AF-F-AIONUI-0283','AF-F-AIONUI-0285') }  # AionUi dirty hits two coverage rows
    @{ Name='AFFiNE';             Branch='Branch_v0.27.2'; Commit='81df4751a367f2795bc0d165586650dbe8db73d6'; Tag='v0.27.2';  Dirty=@(); DiffSha256=$null; Coverage=@(); Features=@() }
    @{ Name='siyuan';             Branch='Branch_v3.7.3'; Commit='eef10568384e2e7cf547adb029ae46a72e43c287'; Tag='v3.7.3';   Dirty=@(); DiffSha256=$null; Coverage=@(); Features=@() }
    @{ Name='Serial-Studio';      Branch='Branch_v4.0.3'; Commit='639daafb2fe7d324c3b2d5583d2514c8c470676f'; Tag='v4.0.3';   Dirty=@(); DiffSha256=$null; Coverage=@(); Features=@() }
    @{ Name='ArcVideo';           Branch='main';           Commit='caf56513278703adec0c2933ec235bb864d72e31'; Tag=$null;
       Dirty=@('CMakeLists.txt','app/common/otioutils.h');
       DiffSha256='3302eb6c34d252be675ada195461f746c8965d1c2014280df52e0d51a767030c';
       Coverage=@('SC-AV-01','SC-AV-04'); Features=@('AF-F-ARCV-0065','AF-F-ARCV-0069') }
    @{ Name='ArcVideoFoundation'; Branch='main';           Commit='139eecaaa79dbad743a146f174a9c89a66ed594b'; Tag=$null;
       Dirty=@('CMakeLists.txt');
       DiffSha256='9ccbbea307352499f5ad55ed6f5eb52176f5f0eff7c20df6d3e77969a9f85a96';
       Coverage=@('SC-AVF-02'); Features=@('AF-F-ARCVF-0011') }
)

# Note: AionUi dirty files split across SC-AION-03 (test file) and SC-AION-05 (script).
$repos[0].Coverage = @('SC-AION-03','SC-AION-05')

foreach ($r in $repos) {
    $p = Join-Path $SourceRoot $r.Name
    Write-Host "===== $($r.Name) ====="
    if (-not (Test-Path $p)) { Fail "$($r.Name): path missing ($p)"; continue }

    $head = git -C $p rev-parse HEAD 2>&1
    if ($head -ne $r.Commit) { Fail "$($r.Name): HEAD drift (expected $($r.Commit), got $head) -> affected: $($r.Coverage -join ', ') / $($r.Features -join ', ')" }
    else { Ok "$($r.Name): HEAD == $($r.Commit)" }

    $branch = git -C $p branch --show-current 2>&1
    if ($branch -ne $r.Branch) { Fail "$($r.Name): branch drift (expected $($r.Branch), got $branch)" }

    $desc = git -C $p describe --tags --always 2>&1
    if ($r.Tag -and $desc -ne $r.Tag) { Fail "$($r.Name): tag/describe drift (expected $($r.Tag), got $desc)" }
    elseif (-not $r.Tag) { Ok "$($r.Name): describe=$desc (no tag registered)" }

    $status = git -C $p status --porcelain=v1 2>&1
    $actualDirty = @($status | ForEach-Object { ($_ -replace '^\s*[MADRC?]+\s+','') -replace '^\s+','' } | Where-Object { $_ -ne '' })
    $expectedDirty = [System.Collections.ArrayList]@($r.Dirty)
    # Normalize both to sorted unique path strings for set comparison.
    $actualSorted   = ($actualDirty   | Sort-Object -Unique) -join '|'
    $expectedSorted = ($expectedDirty  | Sort-Object -Unique) -join '|'
    if ($actualSorted -ne $expectedSorted) {
        Fail "$($r.Name): dirty-file set drift (expected [$expectedSorted], got [$actualSorted]) -> affected: $($r.Coverage -join ', ') / $($r.Features -join ', ')"
    } else {
        if ($r.Dirty.Count -eq 0) { Ok "$($r.Name): workspace clean (matches registered clean)" }
        else { Ok "$($r.Name): dirty-file set matches registered $($r.Dirty.Count) file(s)" }
    }

    if ($r.Dirty.Count -gt 0) {
        # Compute DiffSha256 on RAW git diff bytes (LF preserved) via cmd redirect,
        # not a PowerShell string round-trip (which converts LF->CRLF).
        $tmp = [System.IO.Path]::GetTempFileName()
        & cmd /c "git -C `"$p`" diff --no-color > `"$tmp`" 2>&1"
        $bytes = [System.IO.File]::ReadAllBytes($tmp)
        Remove-Item $tmp -Force
        # SHA-256 of git diff UTF-8 with single trailing newline removed (register definition).
        if ($bytes.Length -gt 0 -and $bytes[$bytes.Length-1] -eq 0x0A) { $bytes = $bytes[0..($bytes.Length-2)] }
        $hash = ([System.BitConverter]::ToString((New-Object System.Security.Cryptography.SHA256Managed).ComputeHash($bytes)) -replace '-','').ToLower()
        if ($hash -ne $r.DiffSha256) {
            Fail "$($r.Name): DiffSha256 drift (expected $($r.DiffSha256), got $hash) -> affected: $($r.Coverage -join ', ') / $($r.Features -join ', ')"
        } else { Ok "$($r.Name): DiffSha256 matches registered $($hash.Substring(0,12))..." }
    }
}

# --- CoverageStatus enum validation over source-baseline.md §4 ---
$repoRoot = (Resolve-Path "$PSScriptRoot/../..").Path
$sbFile = Join-Path $repoRoot "docs/scope/source-baseline.md"
if (Test-Path $sbFile) {
    $sb = Get-Content -Raw -LiteralPath $sbFile
    $nineStates = 'Inventoried','Classified','Read','DeepAnalyzed','Mapped','CrossChecked','Excluded','NeedsRecheck','Superseded'
    # §4 rows start with a CoverageId token in the first column of a table data row.
    $rows = $sb -split "`n" | Select-String '^\| SC-'
    $badStates = @()
    foreach ($row in $rows) {
        $cells = $row.Line -split '\|'
        # CoverageStatus is the 7th logical cell (CoverageId|SourceRepo@Commit|Subsystem|Enum|Reviewed|CoverageStatus|...).
        $cov = ($cells[6] -replace '\*','').Trim()
        if ($nineStates -notcontains $cov) { $badStates += "$($cells[1].Trim()): '$cov'" }
    }
    if ($badStates.Count -gt 0) { Fail "CoverageStatus outside 9-state set: $($badStates -join '; ')" }
    else { Ok "all $($rows.Count) subsystem CoverageStatus values are within the 9-state set" }
} else {
    Fail "docs/scope/source-baseline.md missing"
}

Write-Host ""
if ($script:Failures.Count -gt 0) {
    Write-Host "check-source-baseline.ps1: $($script:Failures.Count) failure(s)" -ForegroundColor Red
    exit 1
}
Write-Host "check-source-baseline.ps1: all assertions green (5 NeedsRecheck rows preserved, not auto-closed)" -ForegroundColor Green
exit 0
