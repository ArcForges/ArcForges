# Foundation Verification Evidence

This file is updated after local verification and linked from the pull request. GitHub CI run IDs are added
after hosted jobs execute; local results never impersonate hosted CI.

| Check | Command | Environment | Result/evidence |
|---|---|---|---|
| Managed project count | `eng/build/check-layout.ps1` | Windows | Pending |
| Locked restore | `dotnet restore ArcForges.slnx --locked-mode` | Windows | Pending |
| Managed build/tests | `eng/build/build-all.ps1 -Locked` | Windows | Pending |
| Android head | `dotnet build src/Mobile/ArcChat.Mobile/ArcChat.Mobile.csproj` | Windows | Pending |
| CMake native | `cmake --preset windows-msvc-x64` | Windows | Pending |
| Independent VCXPROJ | `MSBuild.exe win.slnx` | Windows | Pending |
| Linux managed/native | `eng/build/build-all.sh` | WSL Debian | Pending |
