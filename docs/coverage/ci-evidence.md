# Foundation Verification Evidence

This file is updated after local verification and linked from the pull request. GitHub CI run IDs are added
after hosted jobs execute; local results never impersonate hosted CI.

| Check | Command | Environment | Result/evidence |
|---|---|---|---|
| Repository policy | `dotnet test tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --filter Category=Architecture` | Windows | Passed locally, 33/33, 2026-08-13 |
| Locked restore | `dotnet restore ArcForges.slnx --locked-mode` | Windows | Passed locally, 2026-08-13 |
| Managed build/tests | `dotnet build ArcForges.slnx -c Release --no-restore` + `dotnet test ArcForges.slnx -c Release --no-build --no-restore` | Windows | Passed locally, 0 warnings/errors and all tests, 2026-08-13 |
| Android head | full solution Release build includes `ArcChat.Mobile` | Windows | Passed locally, 2026-08-13 |
| CMake native | configure/build/test with `windows-msvc-x64` presets | Windows | Passed locally, 5/5 tests, 2026-08-13 |
| Independent VCXPROJ | `MSBuild.exe win.slnx -p:Configuration=Release -p:Platform=x64` | Windows | Passed locally, 2026-08-13 |
| Linux native | configure/build with `linux-clang-x64` and clang-tidy warnings as errors | WSL Debian | Passed locally, 2026-08-13 |
| Linux managed | locked restore/build/test | WSL Debian | Not executed locally; hosted CI is authoritative |
