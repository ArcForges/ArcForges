# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$extensions = @('.cs','.cpp','.cc','.cxx','.h','.hpp','.cmake','.ps1','.sh','.props','.targets','.vcxproj')
$files = Get-ChildItem $repoRoot -Recurse -File | Where-Object { $_.Extension -in $extensions -and $_.FullName -notmatch '[\\/](bin|obj|artifacts|\.packages)[\\/]' }
$missing = @($files | Where-Object {
    $header = (Get-Content -LiteralPath $_.FullName -TotalCount 5) -join "`n"
    $header -notmatch 'SPDX-License-Identifier:'
})
if ($missing.Count) { throw "Missing SPDX header:`n$($missing.FullName -join "`n")" }
Write-Host "SPDX headers verified for $($files.Count) files."
