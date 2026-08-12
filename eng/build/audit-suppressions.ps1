# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$matches = @(Get-ChildItem $repoRoot -Recurse -Filter '*.cs' | Where-Object FullName -NotMatch '[\\/](bin|obj)[\\/]' | Select-String -Pattern 'UnconditionalSuppressMessage|RequiresUnreferencedCode')
$invalid = @($matches | Where-Object { $_.Line -notmatch 'reason:' -or $_.Line -notmatch 'evidence:' -or $_.Line -notmatch 'owner:' -or $_.Line -notmatch 'tracking:' -or $_.Line -match 'Scope\s*=\s*"(module|assembly)"' })
if ($invalid.Count) { throw "Invalid trimming suppression:`n$($invalid -join "`n")" }
[pscustomobject]@{ schemaVersion=1; count=$matches.Count } | ConvertTo-Json | Set-Content -Encoding utf8NoBOM -LiteralPath (Join-Path $repoRoot 'artifacts/suppression-count.json')
Write-Host "Suppression audit passed: $($matches.Count)."
