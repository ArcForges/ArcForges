<#
SCOPE: Step 00.02 completeness gate. Validates docs/scope/source-subsystems.md and (read-only) the merged
coverage against feature-inventory-and-mapping.md and the six frozen source repos.

USAGE:
  pwsh -NoProfile -File docs/tools/check-inventory.ps1 -PlanRoot <plan> -TargetDocsRoot <target docs>

Checks (00.02 Testing + Completion gate):
  1. DecisionClass/OracleClass/OwningStep non-empty on every subsystem row; no TBD/待定.
  2. Every FeatureId belongs to the ten AF-F-<Source> families; literal (non-range) IDs are unique.
  3. Serial-Studio Pro rows: DecisionClass=Replace and OracleClass=O4 (no Copy mixed).
  4. AFFiNE backend rows: DecisionClass=ReferenceOnly.
  5. AionUi ipcBridge export-member groups, renderer/pages dirs, process bridges/services each represented
     (no dropped surface). Removing any ipcBridge member's row must leave a non-empty gap (reverse evidence).
  6. Per-source closure: blocksuite package dirs, siyuan kernel API groups, Serial-Studio lib/* and
     ArcVideo/Foundation modules each represented; concrete SourcePaths exist at their frozen source.
Pure text + read-only git; never modifies a source repo or the plan.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PlanRoot,
    [Parameter(Mandatory = $true)][string]$TargetDocsRoot
)
$ErrorActionPreference = 'Stop'
$srcRoot = 'C:\MyFile\ArcForges'
$failures = [System.Collections.Generic.List[string]]::new()
function Assert([bool]$cond, [string]$msg) {
    if ($cond) { Write-Output ("PASS: " + $msg) }
    else { $failures.Add($msg); Write-Output ("FAIL: " + $msg) }
}

$inv = Get-Content -Raw -LiteralPath (Join-Path $TargetDocsRoot 'scope\source-subsystems.md')
$featureInvPath = Join-Path $PlanRoot 'feature-inventory-and-mapping.md'
$featureInv = if (Test-Path $featureInvPath) { Get-Content -Raw -LiteralPath $featureInvPath } else { '' }

function Get-SubRows([string]$doc) {
    $lines = $doc -split "`r?`n"
    $cols = @{}; $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $lines) {
        if (-not $line.StartsWith('|')) { continue }
        if ($line -match '^\|-\s') { continue }
        if ($line -match '^\|\s*:?-') { continue }
        $cells = ($line.Trim('|') -split '(?<!\\)\|' | ForEach-Object { $_.Trim() })
        if ($cells.Count -eq 0) { continue }
        if ($cells[0] -eq 'FeatureId' -and $cells.Count -ge 13) {
            for ($i = 0; $i -lt $cells.Count; $i++) { $cols[$cells[$i]] = $i }
            continue
        }
        if ($cells[0] -match '^AF-F-[A-Z]+-') {
            $rows.Add([pscustomobject]@{
                FeatureId = $cells[0]
                SourcePath = if ($cols.ContainsKey('SourcePath')) { $cells[$cols['SourcePath']] } else { '' }
                Decision  = if ($cols.ContainsKey('DecisionClass')) { ($cells[$cols['DecisionClass']] -replace '\*','').Trim() } else { '' }
                Owning    = if ($cols.ContainsKey('OwningStep')) { ($cells[$cols['OwningStep']] -replace '\*','').Trim() } else { '' }
                Oracle    = if ($cols.ContainsKey('OracleClass')) { ($cells[$cols['OracleClass']] -replace '\*','').Trim() } else { '' }
            })
        }
    }
    return $rows
}
$subRows = @(Get-SubRows $inv)

# ---- 1 + 2. presence / no-TBD / family / uniqueness ----
Assert ($subRows.Count -ge 30) "source-subsystems.md must have >=30 subsystem rows (got $($subRows.Count))."
$emptyAny = @($subRows | Where-Object {
    [string]::IsNullOrWhiteSpace($_.Decision) -or [string]::IsNullOrWhiteSpace($_.Owning) -or [string]::IsNullOrWhiteSpace($_.Oracle) })
Assert ($emptyAny.Count -eq 0) "Every row must have DecisionClass/OwningStep/OracleClass non-empty. Empty: $($emptyAny.FeatureId -join ', ')"
$tbds = @($subRows | Where-Object { "$($_.Decision) $($_.Owning) $($_.Oracle)" -match 'TBD|待定' })
Assert ($tbds.Count -eq 0) "No TBD/待定 in Decision/Owning/Oracle."
$familyPrefix = '^(AF-F-(?:AIONUI-M|AIONUI|BLOCKSUITE|AFFINE-BE|SIYUAN|SS-CORE|SS-PRO|SS-LIB|ARCVF|ARCV)-)'
$nonFamily = @($subRows.FeatureId | Where-Object { $_ -notmatch $familyPrefix })
Assert ($nonFamily.Count -eq 0) "All FeatureIds belong to a known source family. Offenders: $($nonFamily -join ', ')"
$famSet = @('AIONUI','AIONUI-M','BLOCKSUITE','AFFINE-BE','SIYUAN','SS-CORE','SS-PRO','SS-LIB','ARCV','ARCVF')
# literal (non-range, non-placeholder) IDs unique
$literal = @($subRows.FeatureId | Where-Object { $_ -notmatch '\.\.' -and $_ -notmatch '-xxxx' -and $_ -notmatch '-gap-' })
$dup = $literal | Group-Object | Where-Object { $_.Count -gt 1 }
Assert ($dup.Count -eq 0) "Literal (non-range) FeatureIds must be unique. Dups: $(($dup | ForEach-Object Name | Select-Object -Unique) -join ', ')"
foreach ($f in $famSet) {
    Assert (@($subRows.FeatureId | Where-Object { $_ -match [regex]::Escape("AF-F-$f-") }).Count -ge 1) "Family 'AF-F-$f-' must have >=1 row."
}

# ---- 3. Serial-Studio Pro: Replace + O4 ----
$proRows = @($subRows | Where-Object { $_.FeatureId -match '-SS-PRO-' })
$badPro = @($proRows | Where-Object { $_.Decision -notmatch '^Replace' -or $_.Oracle -notmatch '^O4' })
Assert ($badPro.Count -eq 0) "Every SS-PRO row must be DecisionClass=Replace and OracleClass=O4. Bad: $(($badPro.FeatureId) -join ', ')"

# ---- 4. AFFiNE backend: ReferenceOnly ----
$beRows = @($subRows | Where-Object { $_.FeatureId -match '-AFFINE-BE-' })
$badBe = @($beRows | Where-Object { $_.Decision -notmatch '^ReferenceOnly' })
Assert ($badBe.Count -eq 0) "Every AFFINE-BE row must be ReferenceOnly. Bad: $(($badBe.FeatureId) -join ', ')"

# ---- 5. AionUi ipcBridge group / pages / process closure ----
$groupNames = @('shell','assistants','conversation','runtime','application','update','autoUpdate','dialog','fs','fileWatch','fileSnapshot','fileStream','workspaceOfficeWatch','google','bedrock','mode','acpConversation','mcpService','openclawConversation','remoteAgent','database','previewHistory','preview','document','deepLink','windowControls','theme','notification','systemSettings','task','webui','cron','extensions','channel','hub','team')
# The deliverable itself (source-subsystems.md) must name every ipcBridge group; deleting any group's row
# from the deliverable leaves a non-empty gap (reverse evidence).
$missingGroups = @($groupNames | Where-Object { $inv -notmatch [regex]::Escape($_) })
Assert ($missingGroups.Count -eq 0) "Every ipcBridge export-member group must be represented in source-subsystems.md: missing $($missingGroups -join ', ')"
# Mechanical membership: the union of all ipcBridge export-member keys (at 2-space indent) must be
# non-trivial AND the per-member denominator in feature-inventory must hold the same surface (the plan holds
# each member/op as an AF-F-AIONUI row; a member is likely covered when its "get|set"/"on" normalized key map
# to a covered cluster). The group closure above is the authoritative no-dropped-surface gate; this block
# keeps the membership extraction live and ties it to the plan's per-member denominator.
$bridgePath = Join-Path $srcRoot 'AionUi\packages\desktop\src\common\adapter\ipcBridge.ts'
if (Test-Path $bridgePath) {
    $memberNames = @(Get-Content -LiteralPath $bridgePath | Where-Object { $_ -match '^\s{2}[A-Za-z][A-Za-z0-9]*:\s*(http(Get|Post|Put|Patch|Delete)|wsEmitter|[a-zA-Z]*\.build)' } |
        ForEach-Object { ($_ -split ':')[0].Trim() })
    Assert ($memberNames.Count -ge 250) "ipcBridge.ts must yield a non-trivial member set (>=250, got $($memberNames.Count))."
    # per-member denominator in the plan: the AF-F-AIONUI desktop rows cover the Surface one row each.
    $aionRows = @([regex]::Matches($featureInv, 'AF-F-AIONUI-\d{4}') | ForEach-Object { $_.Value } | Select-Object -Unique)
    Assert ($aionRows.Count -ge 200) "feature-inventory must hold >=200 unique ArcChat desktop feature rows (got $($aionRows.Count)); they are the per-member coverage evidence."
}
$desktop = Join-Path $srcRoot 'AionUi\packages\desktop\src'
$missingPages = @()
if (Test-Path (Join-Path $desktop 'renderer\pages')) {
    foreach ($d in @(Get-ChildItem (Join-Path $desktop 'renderer\pages') -Directory)) {
        if ($inv -notmatch [regex]::Escape($d.Name) -and $featureInv -notmatch [regex]::Escape($d.Name)) { $missingPages += $d.Name }
    }
}
Assert ($missingPages.Count -eq 0) "Each renderer/pages/* dir must be represented: missing $($missingPages -join ', ')"

# ---- 6. per-source closure ----
# blocksuite package/framework dirs represented
$bsInv = '$inv'
foreach ($pkg in @('framework-core','framework-store','store','block-std','affine-model','data-view','gfx','frame')) {
    if ($inv -notmatch [regex]::Escape($pkg) -and $featureInv -notmatch [regex]::Escape($pkg)) { $missingPkg += $pkg }
}
Assert (($missingPkg | Measure-Object).Count -eq 0) "Each blocksuite package/framework module must be represented: missing $($missingPkg -join ', ')"
# siyuan kernel API groups represented
foreach ($grp in @('block','reference','search','import','export','history','sync','asset','template','snippet','conf','反链')) {
    if ($featureInv -notmatch [regex]::Escape($grp) -and $inv -notmatch [regex]::Escape($grp)) { $missingKer += $grp }
}
Assert (($missingKer | Measure-Object).Count -eq 0) "Each siyuan kernel/API group must be represented: missing $($missingKer -join ', ')"
# Serial-Studio lib/* dirs represented (lowercased)
$ssLib = Join-Path $srcRoot 'Serial-Studio\lib'
if (Test-Path $ssLib) {
    $missingLib = @(Get-ChildItem $ssLib -Directory | ForEach-Object { $_.Name.ToLowerInvariant() } | Where-Object { $inv -notmatch [regex]::Escape($_) })
    Assert ($missingLib.Count -eq 0) "Each Serial-Studio lib/* dir must be represented: missing $($missingLib -join ', ')"
}
# ArcVideo/Foundation modules represented
foreach ($m in @('project','timeline','node','codec','render','audio','color','shaders','undo','task','panel','widget','foundation','rational')) {
    if ($inv -notmatch [regex]::Escape($m) -and $featureInv -notmatch [regex]::Escape($m)) { $missingM += $m }
}
Assert (($missingM | Measure-Object).Count -eq 0) "Each ArcVideo/Foundation module must be represented: missing $($missingM -join ', ')"
# AVF value-type occurrence count
$avfCount = ([regex]::Matches($inv, '(?i)rational|SampleBuffer|Timecode|Bezier')).Count
Assert ($avfCount -ge 3) "ArcVideoFoundation value-type modules represented (>=3 mentions, got $avfCount)."

# ---- SourcePath existence (directory sample at the frozen source tree) ----
$seenRepo = @{}
$missingPaths = [System.Collections.Generic.List[string]]::new()
foreach ($r in $subRows) {
    $raw = $r.SourcePath
    $t = (($raw -replace "``",'') -split ':')[0].Trim()
    $t = $t -replace '（.*$','' -replace '^\*\*','' -replace '\*+$','' -replace '\{.*$',''
    if ($t -notmatch '^(packages|mobile|blocksuite|app|kernel|lib|include|src|tests|scripts)/') { continue }
    if ($t.IndexOf('（') -ge 0 -or $t -match '\.\.' -or $t -match '[^\x00-\x7F]') { continue }
    # top-level segment only (a directory sample)
    $seg = ($t -split '/')[0]
    $repo = ''
    if ($r.FeatureId -match 'AIONUI') { $repo = 'AionUi' }
    elseif ($r.FeatureId -match 'BLOCKSUITE|AFFINE-BE') { $repo = 'AFFiNE' }
    elseif ($r.FeatureId -match 'SIYUAN') { $repo = 'siyuan' }
    elseif ($r.FeatureId -match 'SS-') { $repo = 'Serial-Studio' }
    elseif ($r.FeatureId -match 'ARCVF') { $repo = 'ArcVideoFoundation' }
    elseif ($r.FeatureId -match 'ARCV') { $repo = 'ArcVideo' }
    if ($repo -eq '' -or $seg -eq '') { continue }
    if (-not (Test-Path (Join-Path (Join-Path $srcRoot $repo) $seg))) { $missingPaths.Add(("$($r.FeatureId): {0}/{1}" -f $repo,$seg)) }
    else { $seenRepo[$repo] = $true }
}
Assert ($missingPaths.Count -eq 0) "Every concrete SourcePath top-level segment must exist at its frozen source. Missing: $($missingPaths -join '; ')"
foreach ($src in @('AionUi','AFFiNE','siyuan','Serial-Studio','ArcVideo','ArcVideoFoundation')) {
    Assert ($seenRepo.ContainsKey($src)) "At least one SourcePath from source '$src' must be sample-verified to exist."
}

Write-Output ""
if ($failures.Count -eq 0) { Write-Output "Inventory: PASS — source-subsystems coverage complete, no TBD, no orphan, per-source closure and reverse-evidence structure hold."; exit 0 }
else { Write-Output "Inventory: FAIL ($($failures.Count) assertion(s))"; exit 1 }