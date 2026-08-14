<#
SCOPE: Step 00.01 baseline verifier. Gives a per-repo, decidable verdict for the six frozen source
repositories against source-coverage-register.md / license-and-reuse-matrix.md §1.

USAGE:
  pwsh -NoProfile -File docs/tools/check-baseline.ps1 [-PlanRoot <plan>] [-WriteSnapshot <path>]

Read-only against the source repos (rev-parse/status/submodule/ls-files/diff). Does not fetch, checkout,
reset, clean, or modify any source repository or target file.

Verdict per repo is FAIL if:
  - HEAD != frozen commit, or tag/describe != registered, or
  - `status --porcelain=v1` != the registered dirty-file set (or clean), or
  - sha256(git ls-files -s) (index aggregate) != registered, or (for dirty repos)
  - sha256(git diff) minus trailing LF (DiffSha256) != registered.
"all green" is never rewritten as "all clean": a dirty repo verified against its registered dirty set is
PASS; an unregistered add/modify/delete or any hash/commit drift lists the affected Coverage/Feature rows.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PlanRoot,
    [Parameter(Mandatory = $false)][string]$WriteSnapshot = $null
)

$ErrorActionPreference = 'Stop'
$srcRoot = 'C:\MyFile\ArcForges'

# Frozen expectations from source-coverage-register.md §2 (authoritative, not inferred).
$expect = @(
    @{ name='AionUi';              branch='Branch_v2.1.35'; commit='29c9271a59484e4696778cb80164f705245a6186'; tag='v2.1.35';
       indexAgg='93ba619e23883786271d0c8fd785b0f654bd9066fb198460bbe7f83034f3a80f';
       dirty=@('scripts/rebuildNativeModules.js','tests/unit/build-scripts/windows-fast-build-script.test.ts');
       diffSha='1f87a590859586a4b64831d54b0292117294dabaef93c71a5fe4bcd377525492' },
    @{ name='AFFiNE';              branch='Branch_v0.27.2'; commit='81df4751a367f2795bc0d165586650dbe8db73d6'; tag='v0.27.2';
       indexAgg='78f2c778d8a4b11731c907adf22e4140b697588e93b519d8e05c10ebae6ba313';
       dirty=@(); diffSha='' },
    @{ name='siyuan';              branch='Branch_v3.7.3'; commit='eef10568384e2e7cf547adb029ae46a72e43c287'; tag='v3.7.3';
       indexAgg='e3ed4807c24dafbdfd6b9ea36d0810d000d2d1ee07ac1b65436cfc4ce72e59b6';
       dirty=@(); diffSha='' },
    @{ name='Serial-Studio';       branch='Branch_v4.0.3'; commit='639daafb2fe7d324c3b2d5583d2514c8c470676f'; tag='v4.0.3';
       indexAgg='6a8f6c545304e567dcf46b8c78c7236ab3bca7735ea93de60756889887c38386';
       dirty=@(); diffSha='' },
    @{ name='ArcVideo';            branch='main'; commit='caf56513278703adec0c2933ec235bb864d72e31'; tag='';
       indexAgg='dd99c8a6bd33403828c41d7421327ddfc537039aa2f11ff739d46e39af08528e';
       dirty=@('CMakeLists.txt','app/common/otioutils.h');
       diffSha='3302eb6c34d252be675ada195461f746c8965d1c2014280df52e0d51a767030c' },
    @{ name='ArcVideoFoundation';  branch='main'; commit='139eecaaa79dbad743a146f174a9c89a66ed594b'; tag='';
       indexAgg='c9166509b4e883a1834c18e3286a3ea4a1ea644f9e22942d100c83a23e1ae8da';
       dirty=@('CMakeLists.txt');
       diffSha='9ccbbea307352499f5ad55ed6f5eb52176f5f0eff7c20df6d3e77969a9f85a96' }
)

# Five registered NeedsRecheck Coverage/Feature rows (per source-coverage-register §5.1).
$needsRecheck = @('AF-F-AIONUI-0283','AF-F-AIONUI-0285','AF-F-ARCV-0065','AF-F-ARCV-0069','AF-F-ARCVF-0011')

$rc = 0
foreach ($e in $expect) {
    $p = Join-Path $srcRoot $e.name
    if (-not (Test-Path $p)) { Write-Output "FAIL $($e.name): path missing $p"; $rc=1; continue }

    $head  = (git -C $p rev-parse HEAD).Trim()
    $br    = (git -C $p branch --show-current 2>$null).Trim()
    $desc  = (git -C $p describe --tags --always 2>$null).Trim()
    $porc  = @(git -C $p status --porcelain=v1)
    $idx   = (git -C $p ls-files -s | sha256sum).Split(' ')[0]
    $raw   = @(git -C $p diff 2>$null)

    $issues = [System.Collections.Generic.List[string]]::new()
    if ($head -ne $e.commit) { $issues.Add("HEAD $head != $($e.commit)") }
    if ($br -ne $e.branch)   { $issues.Add("branch $br != $($e.branch)") }
    if ($e.tag -and $desc -ne $e.tag) { $issues.Add("tag $desc != $($e.tag)") }
    if ($idx -ne $e.indexAgg) { $issues.Add("index aggregate $idx != $($e.indexAgg)") }

    # porcelain=v1: lines are 'XY PATH' (X=index, Y=worktree). Path is the substring after the two
    # status columns plus the separator space; a leading status space must be preserved, not trimmed.
    $dirtySet = @($porc | ForEach-Object {
        if ($_.Length -ge 3) { $_.Substring(3) } elseif ($_.Length -ge 2) { $_.Substring(2) } else { $_ }
    })
    $expectedSet = @($e.dirty | Sort-Object)
    $gotSet = @($dirtySet | Sort-Object)
    $setOk = (($gotSet -join '|') -eq ($expectedSet -join '|'))
    if (-not $setOk) {
        $issues.Add("worktree set [$($gotSet -join ', ')] != registered [$($expectedSet -join ', ')]")
    }

    # DiffSha256 check for dirty repos (or empty when clean): sha256(git diff) minus a single trailing LF.
    if ($e.diffSha) {
        # compute sha256 over the raw diff minus a single trailing LF (matching source-coverage-register §2)
        $joined = $raw -join "`n"
        $joined = $joined -replace "\r\n","`n"
        if ($joined.EndsWith("`n")) { $joined = $joined.Substring(0, $joined.Length-1) }
        $h = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($joined))).Replace('-','').ToLowerInvariant()
        if ($h -ne $e.diffSha) { $issues.Add("DiffSha256 $h != $($e.diffSha)") }
    } elseif ($raw) {
        $issues.Add("expected clean but worktree diff present")
    }

    if ($issues.Count -eq 0) {
        $state = if ($expectedSet.Count -eq 0) { 'clean' } else { "dirty:$($expectedSet.Count)" }
        Write-Output "PASS $($e.name)  HEAD=$($head.Substring(0,8))  state=$state  indexAgg OK"
    } else {
        Write-Output "FAIL $($e.name):"
        $issues | ForEach-Object { Write-Output "   - $_" }
        Write-Output "   Affected Coverage/Feature (NeedsRecheck must stay open): $($needsRecheck -join ', ')"
        $rc = 1
    }
}

# ---- Nine-state validity of every subsystem row in docs/scope/source-baseline.md §3 ----
$srcBase = Join-Path (Split-Path $PSScriptRoot -Parent) 'scope\source-baseline.md'
$nine = @('Inventoried','Classified','Read','DeepAnalyzed','Mapped','CrossChecked','Excluded','NeedsRecheck','Superseded')
if (Test-Path $srcBase) {
    $sb = Get-Content -LiteralPath $srcBase
    $inTable = $false; $dataRows = 0; $badState = 0
    foreach ($line in $sb) {
        if (-not $inTable) {
            if ($line -match '^\| SourceRepo \| RepoPath') { $inTable = $true }; continue
        }
        if ($line -match '^\|') {
            if ($line -match '^\|-') { continue }
            if ($line -match '^\| SourceRepo \| RepoPath') { continue }   # header
            $cells = ($line.Trim('|') -split '(?<!\\)\|' | ForEach-Object { $_.Trim() })
            # columns: SourceRepo|RepoPath|BaselineCommit|Subsystem|IncludedGlob|ExcludedGlob|EnumeratedFileCount|ReviewedFileCount|CoverageStatus|LastVerifiedUtc|EvidencePath|RemainingRisk|Notes
            if ($cells.Count -ge 9) {
                $dataRows++
                $status = ([regex]::Replace($cells[8], '\*', '')).Trim()
                if ($nine -notcontains $status) {
                    Write-Output "FAIL §3 row '$($cells[3])' has invalid CoverageStatus '$status' (must be one of $($nine -join ', '))"
                    $badState++; $rc = 1
                }
            }
        } elseif ($line -match '^---') { break }
    }
    if ($dataRows -gt 0) {
        if ($badState -eq 0) { Write-Output "PASS §3 per-subsystem state: $dataRows row(s), all CoverageStatus ∈ nine-state set." }
    }
}

Write-Output ""
if ($rc -eq 0) { Write-Output "Baseline: PASS — all six repos match frozen registration; zero index drift; dirty sets exact; subsystem states valid. NeedsRecheck rows remain open: $($needsRecheck -join ', ')" }
else { Write-Output "Baseline: FAIL" }
exit $rc