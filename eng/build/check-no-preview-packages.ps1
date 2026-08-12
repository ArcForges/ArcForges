# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$allowedTransitivePreview = @{
    'Xamarin.AndroidX.Security.SecurityCrypto/1.1.0.4-alpha07' = 'Required transitively by stable Microsoft.Maui.Controls 10.0.90; not a direct ArcForges dependency.'
}
$lockFiles = Get-ChildItem $repoRoot -Recurse -Filter 'packages.lock.json' |
    Where-Object FullName -NotMatch '[\\/](artifacts|bin|obj|\.packages)[\\/]'
$preview = foreach ($lockFile in $lockFiles) {
    $json = Get-Content -Raw -LiteralPath $lockFile.FullName | ConvertFrom-Json -AsHashtable
    foreach ($framework in $json.dependencies.Values) {
        foreach ($package in $framework.GetEnumerator()) {
            $resolved = [string] $package.Value.resolved
            $identity = "$($package.Key)/$resolved"
            if ($package.Value.type -ne 'Project' -and $resolved.Contains('-', [StringComparison]::Ordinal) -and -not $allowedTransitivePreview.ContainsKey($identity)) {
                "$($lockFile.FullName): $identity"
            }
        }
    }
}
if ($preview) { throw "Preview packages are forbidden:`n$($preview -join "`n")" }
Write-Host "No unapproved preview package versions found; $($allowedTransitivePreview.Count) audited transitive exception."
