# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$expected = (Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'global.json') | ConvertFrom-Json).sdk.version
$actual = (& dotnet --version).Trim()
if ($LASTEXITCODE -ne 0 -or $actual -ne $expected) {
    throw "Required .NET SDK $expected, resolved $actual."
}
Write-Host ".NET SDK $actual verified."
