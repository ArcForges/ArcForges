# Foundation Verification Evidence

This file is updated after local verification and linked from the pull request. GitHub CI run IDs are added
after hosted jobs execute; local results never impersonate hosted CI.

| Check | Command | Environment | Result/evidence |
|---|---|---|---|
| Repository policy | `dotnet test --project tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --no-build --filter-trait Category=Architecture` | Windows | Passed locally, 36/36, 2026-08-24 |
| Locked restore | `dotnet restore ArcForges.slnx --locked-mode` | Windows | Passed locally with no lock-file changes, 2026-08-24 |
| Managed build/tests | Release build followed by the MTP Unit/Integration/Contract/Ui/Architecture solution run | Windows | Passed locally, build 0 warnings/errors and tests 77/77, 2026-08-24 |
| Published Web browser | MTP Browser test against the locally published WASM site in Chromium | Windows | Passed locally, 1/1, 2026-08-24 |
| Android package | `android-arm64` Mono AOT signed APK publish | Windows | Passed locally, 2026-08-13 |
| CMake native x64 | classic vcpkg through `VCPKG_ROOT`; both `windows-msvc-x64-*-*` profiles, build + CTest + install + managed P/Invoke | Windows | Passed locally, runtime 1/1 + shim 4/4 + P/Invoke, 2026-08-13 |
| Independent VCXPROJ x64 | user-wide `vcpkg integrate install`; `MSBuild.exe win.slnx /m:4 /restore:false /p:Configuration=Release /p:Platform=x64` + managed P/Invoke | Windows | Passed locally, five DLLs and real C# calls, 2026-08-13 |
| Application smoke | one real Avalonia window, Cloud HTTP/SignalR, and Web Chromium probe | Linux | Local Cloud and Chromium passed; hosted aggregate pending |
| Deep native/security | C# CodeQL plus Linux clang-tidy, ASan/UBSan and libFuzzer | weekly/manual | Not a pull-request blocker; latest execution is reported by the Deep check workflow |
