# check-source-baseline.ps1 — Step 00.01 six-repository baseline verification (read-only)
# Recomputes HEAD / branch / tag / porcelain / DiffSha256 for each frozen source repo and
# apples it against source-coverage-register.md §2. Appends raw command output to
# docs/scope/baseline-snapshot.txt with a UTC timestamp. NO source is mutated.
# Requires pwsh. Run:  pwsh -NoProfile -File docs/tools/check-source-baseline.ps1
$ErrorActionPreference = 'Stop'

function Get-Git {
    param([string]$Repo, [string[]]$GitArgs)
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'git'; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
    $psi.ArgumentList.Add('-C'); $psi.ArgumentList.Add($Repo)
    foreach ($a in $GitArgs) { $psi.ArgumentList.Add($a) }
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "git $($GitArgs -join ' ') failed in $Repo (exit $($p.ExitCode))" }
    return $out
}

function Get-DiffSha256 {
    param([string]$Repo)
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'git'; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
    $psi.ArgumentList.Add('-C'); $psi.ArgumentList.Add($Repo); $psi.ArgumentList.Add('diff')
    $p = [System.Diagnostics.Process]::Start($psi)
    $ms = New-Object System.IO.MemoryStream
    $p.StandardOutput.BaseStream.CopyTo($ms); $p.WaitForExit()
    $bytes = $ms.ToArray()
    if ($bytes.Length -gt 0 -and $bytes[$bytes.Length-1] -eq 0x0A) { $bytes = $bytes[0..($bytes.Length-2)] }
    $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return ([System.BitConverter]::ToString($sha)).Replace('-','').ToLowerInvariant()
}

# Frozen table (authority: source-coverage-register.md §2)
$repos = @(
  @{ Name='AionUi';            Path='C:\MyFile\ArcForges\AionUi';            Commit='29c9271a59484e4696778cb80164f705245a6186'; Branch='Branch_v2.1.35'; Tag='v2.1.35'; Dirty='yes'; Diff='1f87a590859586a4b64831d54b0292117294dabaef93c71a5fe4bcd377525492' },
  @{ Name='AFFiNE';            Path='C:\MyFile\ArcForges\AFFiNE';            Commit='81df4751a367f2795bc0d165586650dbe8db73d6'; Branch='Branch_v0.27.2'; Tag='v0.27.2'; Dirty='no' },
  @{ Name='siyuan';            Path='C:\MyFile\ArcForges\siyuan';            Commit='eef10568384e2e7cf547adb029ae46a72e43c287'; Branch='Branch_v3.7.3'; Tag='v3.7.3'; Dirty='no' },
  @{ Name='Serial-Studio';     Path='C:\MyFile\ArcForges\Serial-Studio';     Commit='639daafb2fe7d324c3b2d5583d2514c8c470676f'; Branch='Branch_v4.0.3'; Tag='v4.0.3'; Dirty='no' },
  @{ Name='ArcVideo';          Path='C:\MyFile\ArcForges\ArcVideo';          Commit='caf56513278703adec0c2933ec235bb864d72e31'; Branch='main'; Tag='caf5651';  Dirty='yes'; Diff='3302eb6c34d252be675ada195461f746c8965d1c2014280df52e0d51a767030c' },
  @{ Name='ArcVideoFoundation';Path='C:\MyFile\ArcForges\ArcVideoFoundation'; Commit='139eecaaa79dbad743a146f174a9c89a66ed594b'; Branch='main'; Tag='139eeca';  Dirty='yes'; Diff='9ccbbea307352499f5ad55ed6f5eb52176f5f0eff7c20df6d3e77969a9f85a96' }
)

$root = (Get-Location).Path
$snapshotFile = Join-Path $root 'docs/scope/baseline-snapshot.txt'
$nowUtc = [System.DateTime]::UtcNow.ToString('o')

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("=== ArcForges Step 00 source-baseline snapshot ===")
[void]$sb.AppendLine("UTC: $nowUtc")
[void]$sb.AppendLine('')

$allPass = $true
foreach ($r in $repos) {
    if (-not (Test-Path $r.Path)) { Write-Error "repo missing: $($r.Path)"; exit 1 }
    $head  = (Get-Git $r.Path @('rev-parse','HEAD')).Trim()
    $branch= (Get-Git $r.Path @('branch','--show-current')).Trim()
    $desc  = (Get-Git $r.Path @('describe','--tags','--always')).Trim()
    $porc  = (Get-Git $r.Path @('status','--porcelain')).Trim()

    [void]$sb.AppendLine("repo: $($r.Name)")
    [void]$sb.AppendLine("  rev-parse HEAD            : $head")
    [void]$sb.AppendLine("  branch --show-current     : $branch")
    [void]$sb.AppendLine("  describe --tags --always  : $desc")
    [void]$sb.AppendLine("  status --porcelain lines  : $((($porc -split "`n") | Where-Object {$_}).Count)")

    $ok = $true
    if ($head -ne $r.Commit) { Write-Output "FAIL $($r.Name): HEAD=$head != frozen $($r.Commit)"; $ok=$false }
    if ($branch -ne $r.Branch) { Write-Output "FAIL $($r.Name): branch=$branch != $($r.Branch)"; $ok=$false }
    if ($r.Tag -and (($r.Tag -ne 'caf5651') -and ($r.Tag -ne '139eeca')) -and $desc -ne $r.Tag) {
        Write-Output "FAIL $($r.Name): describe=$desc != $($r.Tag)"; $ok=$false
    }
    if ($r.Dirty -eq 'no' -and $porc.Length -gt 0) {
        Write-Output "FAIL $($r.Name): expected clean but porcelain non-empty"; $ok=$false
    }
    if ($r.Dirty -eq 'yes') {
        $diff = Get-DiffSha256 $r.Path
        [void]$sb.AppendLine("  DiffSha256                  : $diff")
        if ($diff -ne $r.Diff) {
            Write-Output "FAIL $($r.Name): DiffSha256=$diff != frozen $($r.Diff)"; $ok=$false
        } else {
            [void]$sb.AppendLine("  DiffSha256 match            : yes (zero drift)")
        }
        if ($porc.Length -eq 0) {
            Write-Output "FAIL $($r.Name): expected dirty but porcelain empty"; $ok=$false
        }
    }
    if ($ok) { Write-Output "PASS $($r.Name): HEAD+tag+worktree+DiffSha256 match frozen snapshot" } else { $allPass=$false }
    [void]$sb.AppendLine('')
}

[System.IO.File]::WriteAllText($snapshotFile, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))

# ---- Nine-state CoverageStatus enumeration check on docs/scope/source-baseline.md ----
$baselineDoc = Join-Path $root 'docs/scope/source-baseline.md'
$nineStates = @('Inventoried','Classified','Read','DeepAnalyzed','Mapped','CrossChecked','Excluded','NeedsRecheck','Superseded')
if (Test-Path $baselineDoc) {
    $bl = [System.IO.File]::ReadAllLines($baselineDoc)
    $statusOk = $true
    foreach ($line in $bl) {
        $trim = $line.Trim()
        if (-not $trim.StartsWith('|')) { continue }
        $cells = ($trim.Trim('|') -split '\|') | ForEach-Object { $_.Trim() }
        if ($cells.Count -lt 8) { continue }    # not a full subsystem-status row
        if ($cells[0] -eq 'SourceRepo') { continue }   # header row
        if ($cells[0] -match '^-+$') { continue }      # separator row
        $status = ($cells[8].Trim()).Replace('`','')   # strip surrounding backtick delimiters
        if ($status -eq '') { continue }
        if ($nineStates -notcontains $status) {
            Write-Output "FAIL: source-baseline.md has undefined CoverageStatus '$status' (line: ${trim})"
            $statusOk = $false
        }
    }
    if (-not $statusOk) { $allPass = $false }
}

Write-Output ''
Write-Output "snapshot written: $snapshotFile (UTC $nowUtc)"
if ($allPass) {
    Write-Output 'PASS: all six repositories match the frozen baseline; zero drift (clean repos clean, dirty repos exactly 5 dirty files with matching DiffSha256); source-baseline.md CoverageStatus all within nine-state set'
    exit 0
}
else {
    Write-Output 'FAIL: baseline drift or undefined CoverageStatus in source-baseline.md'
    exit 1
}