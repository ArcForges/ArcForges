# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$license = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'LICENSE')
if ($license -notmatch 'GNU AFFERO GENERAL PUBLIC LICENSE' -or $license -notmatch 'Version 3') {
    throw 'Root LICENSE is not the complete AGPL version 3 license.'
}
Write-Host 'Root AGPL-3.0 license verified.'
