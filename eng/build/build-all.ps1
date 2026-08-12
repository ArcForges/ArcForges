# SPDX-License-Identifier: AGPL-3.0-only

[CmdletBinding()]
param(
    [switch] $Locked,
    [switch] $SkipAndroid,
    [switch] $SkipNative
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repoRoot
try {
    & "$PSScriptRoot\check-sdk.ps1"
    & "$PSScriptRoot\check-layout.ps1"

    $restoreArguments = @('restore', 'ArcForges.slnx')
    if ($Locked) { $restoreArguments += '--locked-mode' }
    & dotnet @restoreArguments
    if ($LASTEXITCODE -ne 0) { throw 'Managed restore failed.' }

    & dotnet build ArcForges.slnx -c Debug --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Debug build failed.' }
    & dotnet build ArcForges.slnx -c Release --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
    & dotnet test ArcForges.slnx -c Release --no-build --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Managed tests failed.' }

    if (-not $SkipAndroid) {
        & dotnet build 'src\Mobile\ArcChat.Mobile\ArcChat.Mobile.csproj' -c Debug --no-restore
        if ($LASTEXITCODE -ne 0) { throw 'Android head build failed.' }
    }

    if (-not $SkipNative) {
        & cmake --preset windows-msvc-x64
        if ($LASTEXITCODE -ne 0) { throw 'Native configure failed.' }
        & cmake --build --preset windows-msvc-x64-release
        if ($LASTEXITCODE -ne 0) { throw 'Native build failed.' }
        & ctest --preset windows-msvc-x64
        if ($LASTEXITCODE -ne 0) { throw 'Native tests failed.' }
    }
}
finally {
    Pop-Location
}
