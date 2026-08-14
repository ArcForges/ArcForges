<#
SCOPE: Step 00.04 compliance-manifest gate. Validates the five manifests (md + json) structure, required
fields of first entries, ID uniqueness, UD-LIC decision coverage, and suspicious-IP isolation.

USAGE:
  pwsh -NoProfile -File docs/tools/check-manifests.ps1 -TargetDocsRoot <target docs>
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$TargetDocsRoot)
$ErrorActionPreference = 'Stop'
$comp = Join-Path $TargetDocsRoot 'compliance'
$failures = [System.Collections.Generic.List[string]]::new()
function Assert([bool]$cond, [string]$msg) {
    if ($cond) { Write-Output ("PASS: " + $msg) }
    else { $failures.Add($msg); Write-Output ("FAIL: " + $msg) }
}
function Read-Json($p) {
    $raw = Get-Content -Raw -LiteralPath $p
    return ($raw | ConvertFrom-Json)
}

# ---- 1. Copied-Code ----
$ccMd = Join-Path $comp 'copied-code.md'; $ccJson = Join-Path $comp 'copied-code.json'
Assert ((Test-Path $ccMd) -and (Test-Path $ccJson)) "copied-code.md/.json exist."
$cc = Read-Json $ccJson
Assert ($cc.entries.Count -ge 6) "copied-code has >=6 first entries (got $($cc.entries.Count))."
Assert (@($cc.entries | Group-Object ManifestId | Where-Object { $_.Count -gt 1 }).Count -eq 0) "copied-code ManifestIds unique."
$ccReq = @('ManifestId','SourcePath','SourceRepository','SourceCommit','OriginalLicense','FileLevelLicense',
    'TargetProduct','TargetProject','ReuseType','Purpose','TemporaryOrPermanent','ValidationMethod',
    'Attribution','CurrentPlanningStatus','Evidence','Notes')
$ccBad = @(foreach ($e in $cc.entries) { foreach ($f in $ccReq) { if ([string]::IsNullOrWhiteSpace($e.$f)) { "$($e.ManifestId):$f" } } })
Assert ($ccBad.Count -eq 0) "copied-code required fields non-empty. Bad: $($ccBad -join '; ')"

# ---- 2. Copied-Asset ----
$caJson = Join-Path $comp 'copied-asset.json'; $caMd = Join-Path $comp 'copied-asset.md'
Assert ((Test-Path $caMd) -and (Test-Path $caJson)) "copied-asset.md/.json exist."
$ca = Read-Json $caJson
Assert ($ca.entries.Count -ge 5) "copied-asset has >=5 first entries."
Assert (@($ca.entries | Group-Object AssetId | Where-Object { $_.Count -gt 1 }).Count -eq 0) "copied-asset AssetIds unique."
$caReq = @('AssetId','SourcePath','AssetClass','License','NoticeLine','ReplacePlan','Status')
$caBad = @(foreach ($e in $ca.entries) { foreach ($f in $caReq) { if ([string]::IsNullOrWhiteSpace($e.$f)) { "$($e.AssetId):$f" } } })
Assert ($caBad.Count -eq 0) "copied-asset required fields non-empty. Bad: $($caBad -join '; ')"
# suspicious-IP isolation
$susp = @($ca.entries | Where-Object { $_.SuspiciousThirdPartyIp -eq $true })
$badSusp = @($susp | Where-Object { $_.Status -ne 'Replace' })
Assert ($badSusp.Count -eq 0) "SuspiciousThirdPartyIp=true entries must be Status=Replace. Bad: $(($badSusp|% AssetId) -join ', ')"
$badNorm = @($ca.entries | Where-Object { $_.SuspiciousThirdPartyIp -eq $true -and -not [string]::IsNullOrWhiteSpace($_.TargetPath) })
Assert ($badNorm.Count -eq 0) "SuspiciousThirdPartyIp=true entries must NOT carry a normal TargetPath."
Assert ($susp.Count -ge 2) "At least 2 suspicious-IP entries (AionUi covers + Serial-Studio brand)."

# ---- 3. Independent-Reimplementation ----
$irJson = Join-Path $comp 'independent-reimplementation.json'; $irMd = Join-Path $comp 'independent-reimplementation.md'
Assert ((Test-Path $irMd) -and (Test-Path $irJson)) "independent-reimplementation.md/.json exist."
$ir = Read-Json $irJson
Assert ($ir.entries.Count -ge 3) "independent-reimplementation has >=3 first entries."
Assert (@($ir.entries | Group-Object ItemId | Where-Object { $_.Count -gt 1 }).Count -eq 0) "independent-reimplementation ItemIds unique."
$irReq = @('ItemId','SourceRepo','WhyIndependent','BehaviorSpecPaths','TargetProduct','TargetProject','NoSourceCopyProof','ValidationOracle','Status')
$irBad = @(foreach ($e in $ir.entries) { foreach ($f in $irReq) { if ([string]::IsNullOrWhiteSpace($e.$f)) { "$($e.ItemId):$f" } } })
Assert ($irBad.Count -eq 0) "independent-reimplementation required fields non-empty. Bad: $($irBad -join '; ')"
$badOracle = @($ir.entries | Where-Object { $_.ValidationOracle -notin @('O3','O4') })
Assert ($badOracle.Count -eq 0) "independent-reimplementation ValidationOracle ∈ {O3,O4}. Bad: $(($badOracle|% ItemId) -join ', ')"

# ---- 4. Replacement-Backlog ----
$rbJson = Join-Path $comp 'replacement-backlog.json'; $rbMd = Join-Path $comp 'replacement-backlog.md'
Assert ((Test-Path $rbMd) -and (Test-Path $rbJson)) "replacement-backlog.md/.json exist."
$rb = Read-Json $rbJson
Assert ($rb.entries.Count -ge 5) "replacement-backlog has >=5 first entries."
Assert (@($rb.entries | Group-Object ItemId | Where-Object { $_.Count -gt 1 }).Count -eq 0) "replacement-backlog ItemIds unique."
$rbReq = @('ItemId','What','Why','TemporarySource','ReplacementDesign','ReplacementStage','ExitCriteria','Status')
$rbBad = @(foreach ($e in $rb.entries) { foreach ($f in $rbReq) { if ([string]::IsNullOrWhiteSpace($e.$f)) { "$($e.ItemId):$f" } } })
Assert ($rbBad.Count -eq 0) "replacement-backlog required fields non-empty. Bad: $($rbBad -join '; ')"
Assert (@($rb.entries | Where-Object { $_.TemporarySource -ne 'none' }).Count -eq 0) "replacement-backlog TemporarySource='none' (direct replacement, no temporary port)."

# ---- 5. Third-Party-License-Register ----
$tprJson = Join-Path $comp 'third-party-license-register.json'; $tprMd = Join-Path $comp 'third-party-license-register.md'
Assert ((Test-Path $tprMd) -and (Test-Path $tprJson)) "third-party-license-register.md/.json exist."
$tpr = Read-Json $tprJson
$tprReq = @('Dependency','Version','License','Source','Copyright','Notice','AGPLCompatibility','Owner')
$tprBad = @(foreach ($e in $tpr.entries) { foreach ($f in $tprReq) { if ([string]::IsNullOrWhiteSpace("$($e.$f)")) { "$($e.Dependency):$f" } } })
Assert ($tprBad.Count -eq 0) "third-party-license-register required fields non-empty. Bad: $($tprBad -join '; ')"
Assert ($tpr.forbidden.Count -ge 10) "third-party-license-register forbidden list present (>=10 items)."
Assert ($tpr.vcpkgBuiltinBaseline -eq '40f3c709db80acf154ac4b17a1f83c564ebd022e') "vcpkg builtin baseline verbatim."

# ---- UD-LIC coverage (2/3/4/5 each referenced by >=1 manifest row) ----
$allText = @(Get-Content -Raw -LiteralPath (Join-Path $comp 'copied-code.json')) + `
    (Get-Content -Raw -LiteralPath (Join-Path $comp 'independent-reimplementation.json')) + `
    (Get-Content -Raw -LiteralPath (Join-Path $comp 'replacement-backlog.json'))
foreach ($n in 2,3,4,5) {
    Assert (($allText -join ' ') -match "UD-LIC-$n") "UD-LIC-$n referenced by >=1 manifest row."
}

Write-Output ""
if ($failures.Count -eq 0) { Write-Output "Manifests: PASS"; exit 0 }
else { Write-Output "Manifests: FAIL ($($failures.Count) assertion(s))"; exit 1 }