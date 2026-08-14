<#
SCOPE: Step 00.06 traceability bridge generator scaffold. Reads the authoritative plan registries and emits
the Feature/Coverage trace bridge in its honest initial planning state (BridgeGenerationRequired).

INPUTS (all read-only):
  - feature-inventory-and-mapping.md  -> global unique AF-F-* feature ID set
  - source-coverage-register.md       -> SC-* coverage ID set
  - traceability-matrix.md            -> TR-* requirement summaries (owning steps / test / FG)
  - final-production-gate.md          -> FG.N ids (not required for seed)

OUTPUT:
  -Seed: docs/evidence/traceability/feature-trace-bridge.json (this scope's planning seed)
  - At implementation/release the same script is re-run to write artifacts/evidence/traceability/... once
    test/gate evidence exists; it never invents foreign keys and never sets Closed by itself.

USAGE: pwsh -NoProfile -File eng/traceability/generate-feature-trace-bridge.ps1 -PlanRoot <plan>
       [-WritePath <output json>]
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PlanRoot,
    [Parameter(Mandatory = $false)][string]$WritePath = $null
)
$ErrorActionPreference = 'Stop'

# ---- 1. Global feature ID set from feature-inventory ----
$fi = Get-Content -Raw -LiteralPath (Join-Path $PlanRoot 'feature-inventory-and-mapping.md')
$featureIds = @([regex]::Matches($fi, 'AF-F-(?:AIONUI-M|AIONUI|BLOCKSUITE|AFFINE-BE|AFFINE-FE|SIYUAN|SS-CORE|SS-PRO|SS-LIB|ARCVF|ARCV)-\d{4}') |
    ForEach-Object { $_.Value } | Select-Object -Unique)
# coverage IDs from source-coverage-register
$cr = Get-Content -Raw -LiteralPath (Join-Path $PlanRoot 'source-coverage-register.md')
$coverageIds = @([regex]::Matches($cr, 'SC-[A-Z-0-9]+-\d{2}') | ForEach-Object { $_.Value } | Select-Object -Unique)

# ---- 2. TR-* rows from traceability-matrix §2 ----
$tm = Get-Content -Raw -LiteralPath (Join-Path $PlanRoot 'traceability-matrix.md')
$trRows = [System.Collections.Generic.List[object]]::new()
foreach ($line in ($tm -split "`r?`n")) {
    if ($line -match '^\| *(TR-[A-Z]+-\d{2}) *\|') {
        $cells = ($line.Trim('|') -split '(?<!\\)\|' | ForEach-Object { $_.Trim() })
        if ($cells[0] -match 'TR-[A-Z]+-\d{2}') {
            $trRows.Add([pscustomobject]@{
                Id = $cells[0]
                TargetProduct = if ($cells.Count -ge 3) { $cells[2] } else { '' }
                Owning = if ($cells.Count -ge 8) { $cells[7] } else { '' }
                Test   = if ($cells.Count -ge 9) { $cells[8] } else { '' }
                Gate   = if ($cells.Count -ge 10) { $cells[9] } else { '' }
            })
        }
    }
}

# ---- 3. Emit one record per TR; honest initial state ----
$records = [System.Collections.Generic.List[object]]::new()
foreach ($t in $trRows) {
    $owning = @([regex]::Matches($t.Owning, '\d{1,2}') | ForEach-Object { [int]$_.Value } | Sort-Object -Unique)
    $gates  = @([regex]::Matches($t.Gate, 'FG\.\d+') | ForEach-Object { $_.Value } | Select-Object -Unique)
    $missing = [System.Collections.Generic.List[string]]::new()
    if ($featureIds.Count -eq 0) { $missing.Add('featureIds(global)') }
    if ($coverageIds.Count -eq 0) { $missing.Add('coverageIds(global)') }
    $missing.Add('arcForgesRequirementId')
    $missing.Add('featureIds(per-record)')
    $missing.Add('coverageIds(per-record)')
    $records.Add([ordered]@{
        traceId = $t.Id
        featureIds = @()
        coverageIds = @()
        requirementId = $t.Id
        arcForgesRequirementId = $null
        targetProduct = $t.TargetProduct
        targetProjects = @()
        targetTypes = @()
        contractIds = @()
        dataIds = @()
        uiSurfaceIds = @()
        owningSteps = @($owning)
        testIds = @()
        gateIds = @($gates)
        sourceBaselines = @()
        closureStatus = 'BridgeGenerationRequired'
        missingFields = @($missing)
        evidenceHash = ''
    })
}

$bridge = [ordered]@{
    schemaVersion = 1
    generatedUtc = '2026-08-14T00:00:00Z'
    initialState = 'BridgeGenerationRequired'
    globalFeatureIds = @($featureIds)
    globalCoverageIds = @($coverageIds)
    records = @($records)
}
$out = if ($WritePath) { $WritePath } else { Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'docs\evidence\traceability\feature-trace-bridge.json' }
New-Item -ItemType Directory -Force -Path (Split-Path $out -Parent) | Out-Null
($bridge | ConvertTo-Json -Depth 8) | Set-Content -NoNewline -Encoding utf8 -LiteralPath $out
Write-Output ("Generated {$($trRows.Count)} TR records; global featureIds=$($featureIds.Count), coverageIds=$($coverageIds.Count); wrote $out")