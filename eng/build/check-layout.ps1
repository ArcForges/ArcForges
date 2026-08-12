# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$required = @(
    'global.json','Directory.Build.props','Directory.Build.targets','Directory.Packages.props','NuGet.config',
    'ArcForges.slnx','win.slnx','CMakeLists.txt','CMakePresets.json','.editorconfig','.gitignore',
    '.gitattributes','LICENSE','README.md','NOTICE.md','eng','src','native','tests','docs','.github'
)
$missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $repoRoot $_)) })
if ($missing.Count) { throw "Missing repository entries: $($missing -join ', ')" }
$managed = @(Get-ChildItem -LiteralPath $repoRoot -Recurse -Filter '*.csproj' | Where-Object FullName -NotMatch '[\\/](bin|obj|artifacts)[\\/]')
$native = @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'native') -Recurse -Filter '*.vcxproj')
$shimDirectories = @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'native') -Directory | Where-Object Name -Match '-abi$')
if ($managed.Count -ne 166) { throw "Expected 166 managed projects, found $($managed.Count)." }
if ($native.Count -ne 5) { throw "Expected five Windows native projects, found $($native.Count)." }
if ($shimDirectories.Count -ne 6) { throw "Expected six native ABI directories, found $($shimDirectories.Count)." }
if (Test-Path (Join-Path $repoRoot 'vcpkg.json')) { throw 'A root vcpkg.json would create an unauthorized fourth dependency graph.' }
$cpp23 = @(Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Include '*.cmake','CMakeLists.txt','*.vcxproj','.clangd' | Where-Object FullName -NotMatch '[\\/](bin|obj|artifacts)[\\/]' | Select-String -Pattern 'c\+\+23|std:c\+\+latest|c\+\+2b')
if ($cpp23.Count) { throw "C++23/latest is forbidden: $($cpp23.Path -join ', ')" }
$nativeWildcards = @($native | Select-String -Pattern '<(?:ClCompile|ClInclude)\s+Include="[^"]*[?*]')
if ($nativeWildcards.Count) { throw "Visual Studio C++ project items must be explicit: $($nativeWildcards.Path -join ', ')" }
Write-Host 'Repository layout verified: 166 managed projects, five Windows native projects, six ABI shims.'
