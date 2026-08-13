# Foundation Verification Evidence

This file is updated after local verification and linked from the pull request. GitHub CI run IDs are added
after hosted jobs execute; local results never impersonate hosted CI.

| Check | Command | Environment | Result/evidence |
|---|---|---|---|
| Repository policy | `dotnet test tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --filter Category=Architecture` | Windows | Passed locally, 34/34, 2026-08-13 |
| Locked restore | `dotnet restore ArcForges.slnx --locked-mode` | Windows | Passed locally, 2026-08-13 |
| Managed build/tests | Debug + Release builds and Unit/Integration/Contract/Ui/Architecture category matrix | Windows | Passed locally, 0 warnings/errors and all selected tests, 2026-08-13 |
| Android head | full solution Release build includes `ArcChat.Mobile` | Windows | Passed locally, 2026-08-13 |
| CMake native x64 | both `windows-msvc-x64-*-*` profiles, build + CTest + install + managed P/Invoke | Windows | Passed locally, runtime 1/1 + shim 4/4 + P/Invoke, 2026-08-13 |
| Independent VCXPROJ x64 | `MSBuild.exe win.slnx /m:4 /restore:false /p:Configuration=Release /p:Platform=x64` + managed P/Invoke | Windows | Passed locally, five DLLs and real C# calls, 2026-08-13 |
| Native ARM64 | both CMake profiles and independent `win.slnx` | Windows | Hosted CI pending; local VS lacks the ARM64 v145 component |
| Linux native | both Clang profiles with clang-tidy, ASan/UBSan, CTest, install, managed P/Invoke, and libFuzzer | WSL Debian | Passed locally; runtime 1/1, shim 4/4, installed P/Invoke 1/1, five fuzzers × 1,000 runs, 2026-08-13 |
| Linux managed | locked restore/build/test with host-isolated output roots | WSL Debian | Passed locally, 0 warnings/errors and 34/34 policy tests, 2026-08-13 |
| Coverage | XPlat collector over Architecture/Repository policy engine | Windows | 95.83% lines, 74.27% branches, 2026-08-13 |
| Desktop Native AOT | locked restore, publish `win-x64`, execute real Avalonia window lifecycle | Windows | Four products passed locally, 2026-08-13 |
| Cloud/Web/Android | live HTTP + SignalR, real Chromium, APK publish, emulator install/launch/UI assertion | hosted matrix | Local Cloud and real Chromium passed; signed APK published; hosted device result pending |
