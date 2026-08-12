# SPDX-License-Identifier: AGPL-3.0-only

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $RuntimeIdentifier,
    [switch] $PublishOnly
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$products = @('ArcChat','ArcNotes','ArcScope','ArcSlate')
Push-Location $repoRoot
try {
    foreach ($product in $products) {
        $project = "src/$product/$product.Desktop/$product.Desktop.csproj"
        $output = "artifacts/smoke/$RuntimeIdentifier/$product"
        & dotnet restore $project --locked-mode
        if ($LASTEXITCODE -ne 0) { throw "[$RuntimeIdentifier,$product,restore] failed." }

        & dotnet publish $project -c Release -r $RuntimeIdentifier --self-contained true --no-restore -o $output
        if ($LASTEXITCODE -ne 0) { throw "[$RuntimeIdentifier,$product,publish] failed." }

        if (-not $PublishOnly) {
            $extension = if ($RuntimeIdentifier.StartsWith('win-')) { '.exe' } else { '' }
            $executable = Join-Path $output "$product.Desktop$extension"
            $result = & $executable --smoke
            if ($LASTEXITCODE -ne 0 -or $result -notmatch 'ok arcforges-smoke') {
                throw "[$RuntimeIdentifier,$product,run] failed: $result"
            }
        }
    }
}
finally {
    Pop-Location
}
