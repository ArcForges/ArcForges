# SPDX-License-Identifier: AGPL-3.0-only
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet('win-x64', 'win-arm64', 'linux-x64', 'linux-arm64')]
  [string] $RuntimeIdentifier,
  [string] $MxcReleaseZip,
  [string] $MxcInstallRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path $PSScriptRoot -Parent
$qualifiedMxcRid = $RuntimeIdentifier -in @('win-x64', 'linux-x64')
if ($MxcInstallRoot -and -not $qualifiedMxcRid) {
  throw "An MXC install requires a qualified x64 RID, not $RuntimeIdentifier."
}
# Packages Node/CLI and the supervisors belonging to this RID.
$publish = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/host"
$executable = if ($RuntimeIdentifier.StartsWith('win-')) { 'arcforges.exe' } else { 'arcforges' }
if (-not (Test-Path -LiteralPath (Join-Path $publish $executable))) {
  throw "Publish the $RuntimeIdentifier host (eng/publish.ps1) before packaging."
}
$supervisor = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/supervisor/arcforges-supervisor.exe"
if ($RuntimeIdentifier.StartsWith('win-') -and -not (Test-Path -LiteralPath $supervisor)) {
  throw "Publish the $RuntimeIdentifier supervisor (eng/publish.ps1) before packaging."
}

# A fresh staging directory keeps repeated local packaging free of stale files.
$stage = Join-Path $repository "artifacts/staging/$RuntimeIdentifier-$([guid]::NewGuid().ToString('N'))"
$packages = Join-Path $repository 'artifacts/packages'
$null = New-Item -ItemType Directory -Path $stage, $packages -Force
Get-ChildItem -LiteralPath $publish -Exclude '*.pdb', '*.dbg', '*.dSYM' | Copy-Item -Destination $stage -Recurse
if (Test-Path -LiteralPath (Join-Path $stage 'mxc')) {
  throw 'The host output must not supply mxc. Packaging stages the exact pinned runtime separately.'
}
Copy-Item -LiteralPath (Join-Path $repository 'third-party') -Destination $stage -Recurse
Copy-Item -LiteralPath (Join-Path $repository 'LICENSE'), (Join-Path $repository 'THIRD_PARTY_NOTICES.md') -Destination $stage
Copy-Item -LiteralPath (Join-Path $repository 'src/ArcForges.Host/packages.lock.json') -Destination $stage
if ($RuntimeIdentifier.StartsWith('win-')) {
  Copy-Item -LiteralPath $supervisor -Destination $stage -Force
  Copy-Item -LiteralPath (Join-Path $repository 'src/ArcForges.Supervisor/packages.lock.json') -Destination (Join-Path $stage 'supervisor.packages.lock.json')
} else {
  $units = Join-Path $stage 'packaging/linux'
  $null = New-Item -ItemType Directory -Path $units -Force
  Copy-Item -LiteralPath (Join-Path $repository 'packaging/linux/arcforges-node.service'),
    (Join-Path $repository 'packaging/linux/arcforges-guard.service'),
    (Join-Path $repository 'packaging/linux/arcforges.slice') -Destination $units
}

$projects = @('src/ArcForges.Host')
if ($qualifiedMxcRid) {
  $runSupervisorProject = 'src/ArcForges.RunSupervisor'
  $runPublish = Join-Path $repository "artifacts/publish/$RuntimeIdentifier/run-supervisor"
  if (-not (Test-Path -LiteralPath $runPublish -PathType Container)) {
    throw "Publish the $RuntimeIdentifier run-supervisor (eng/publish.ps1) before packaging."
  }
  $mxcArguments = @('--component', 'run-supervisor', '--rid', $RuntimeIdentifier, '--publish', $runPublish,
    '--output', (Join-Path $stage 'mxc'))
  if ($MxcReleaseZip) { $mxcArguments += @('--release', $MxcReleaseZip) }
  & python (Join-Path $PSScriptRoot 'mxc/stage.py') @mxcArguments | Out-Host
  if ($LASTEXITCODE -ne 0) { throw 'Staging the protected MXC installation failed.' }
  Copy-Item -LiteralPath (Join-Path $repository "$runSupervisorProject/packages.lock.json") -Destination (Join-Path $stage 'run-supervisor.packages.lock.json')
  $projects += $runSupervisorProject
}

# Preserve native component notices from each actual restored application closure.
foreach ($project in $projects) {
  $assetsPath = Join-Path $repository "$project/obj/project.assets.json"
  $assets = Get-Content -LiteralPath $assetsPath -Raw | ConvertFrom-Json -AsHashtable
  foreach ($library in $assets.libraries.Values) {
    if ($library.type -ne 'package') { continue }
    # Build-only policy package (PrivateAssets=all): nothing from it is redistributed.
    if ($library.path -like 'arcforges.build.policy/*') { continue }
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

# AD-0007 section 8: digests.json lists the SHA-256 of every file of the version directory except itself (relative paths with
# / separators); a node running from the version directory makes its files read-only and verifies them after startup.
$version = (Select-Xml -LiteralPath (Join-Path $repository 'Directory.Build.props') -XPath '//Version' | Select-Object -First 1).Node.InnerText
$relativePaths = [string[]] @(Get-ChildItem -LiteralPath $stage -Recurse -File | ForEach-Object { [IO.Path]::GetRelativePath($stage, $_.FullName).Replace('\', '/') })
[Array]::Sort($relativePaths, [StringComparer]::Ordinal)
$digests = [ordered]@{}
foreach ($relative in $relativePaths) {
  if ($relative -ceq 'digests.json') { continue }
  $digests[$relative] = (Get-FileHash -LiteralPath (Join-Path $stage $relative) -Algorithm SHA256).Hash.ToLowerInvariant()
}
[ordered]@{ version = $version; files = $digests } | ConvertTo-Json -Depth 3 |
  Set-Content -LiteralPath (Join-Path $stage 'digests.json') -Encoding utf8NoBOM

if ($RuntimeIdentifier.StartsWith('win-')) {
  $archive = Join-Path $packages "arcforges-$RuntimeIdentifier.zip"
  Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
} else {
  $archive = Join-Path $packages "arcforges-$RuntimeIdentifier.tar.gz"
  tar -czf $archive -C $stage .
  if ($LASTEXITCODE -ne 0) { throw 'Archive creation failed.' }
}
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $([IO.Path]::GetFileName($archive))" | Set-Content -LiteralPath "$archive.sha256" -Encoding ascii
if ($qualifiedMxcRid) {
  $verifyArguments = @('--rid', $RuntimeIdentifier, '--archive', $archive, '--commit', $commit)
  if ($MxcInstallRoot) { $verifyArguments += @('--output', $MxcInstallRoot) }
  & python (Join-Path $repository 'packaging/mxc/verify_install.py') @verifyArguments | Out-Host
  if ($LASTEXITCODE -ne 0) { throw 'Verification of the packaged MXC installation failed.' }
}
Write-Output $archive
