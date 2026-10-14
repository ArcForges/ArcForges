# SPDX-License-Identifier: AGPL-3.0-only
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet('win-x64', 'win-arm64', 'linux-x64')]
  [string] $RuntimeIdentifier
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path $PSScriptRoot -Parent
$publish = Join-Path $repository "artifacts/publish/$RuntimeIdentifier"
$executable = if ($RuntimeIdentifier.StartsWith('win-')) { 'ArcForges.exe' } else { 'ArcForges' }
if (-not (Test-Path -LiteralPath (Join-Path $publish $executable))) {
  throw "Publish the $RuntimeIdentifier executable before packaging."
}

# A fresh staging directory keeps repeated local packaging free of stale files.
$stage = Join-Path $repository "artifacts/staging/$RuntimeIdentifier-$([guid]::NewGuid().ToString('N'))"
$packages = Join-Path $repository 'artifacts/packages'
$null = New-Item -ItemType Directory -Path $stage, $packages -Force
Get-ChildItem -LiteralPath $publish -Exclude '*.pdb', '*.dbg', '*.dSYM' | Copy-Item -Destination $stage -Recurse
Copy-Item -LiteralPath (Join-Path $repository 'third-party') -Destination $stage -Recurse
Copy-Item -LiteralPath (Join-Path $repository 'src/ArcForges.Desktop/packages.lock.json') -Destination $stage

# Preserve native component notices from the actual restored application closure.
$assetsPath = Join-Path $repository 'src/ArcForges.Desktop/obj/project.assets.json'
$assets = Get-Content -LiteralPath $assetsPath -Raw | ConvertFrom-Json -AsHashtable
foreach ($library in $assets.libraries.Values) {
  if ($library.type -ne 'package') { continue }
  $packagePath = $null
  foreach ($cacheRoot in $assets.packageFolders.Keys) {
    $candidate = Join-Path $cacheRoot $library.path
    if (Test-Path -LiteralPath $candidate) { $packagePath = $candidate; break }
  }
  if (-not $packagePath) { throw "Restored package is missing: $($library.path)" }
  foreach ($file in Get-ChildItem -LiteralPath $packagePath -Recurse -File) {
    if ($file.Name -notmatch '(?i)(license|licence|notice|copying)' -and $file.Extension -ne '.nuspec') { continue }
    $relative = [IO.Path]::GetRelativePath($packagePath, $file.FullName)
    $destination = Join-Path $stage "third-party/packages/$($library.path)/$relative"
    $null = New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force
    Copy-Item -LiteralPath $file.FullName -Destination $destination
  }
}

$commit = git -C $repository rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Could not identify the source commit.' }
$changes = git -C $repository status --porcelain
if ($LASTEXITCODE -ne 0) { throw 'Could not identify local changes.' }
@{
  source = 'https://github.com/ArcForges/ArcForges'
  commit = $commit
  dirty = [bool] $changes
  runtimeIdentifier = $RuntimeIdentifier
  sdk = (Get-Content -LiteralPath (Join-Path $repository 'global.json') -Raw | ConvertFrom-Json).sdk.version
  distribution = 'unsigned-development-preview'
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'build-info.json') -Encoding utf8

if ($RuntimeIdentifier.StartsWith('win-')) {
  $archive = Join-Path $packages "ArcForges-$RuntimeIdentifier.zip"
  Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
} else {
  $archive = Join-Path $packages "ArcForges-$RuntimeIdentifier.tar.gz"
  tar -czf $archive -C $stage .
  if ($LASTEXITCODE -ne 0) { throw 'Archive creation failed.' }
}
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $([IO.Path]::GetFileName($archive))" | Set-Content -LiteralPath "$archive.sha256" -Encoding ascii
Write-Output $archive
