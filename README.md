<div align="center">

# ArcForges

**One open-source C# product family for AI work, knowledge, instruments, and media.**

[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-663399.svg)](LICENSE)
[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4.svg)](global.json)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C.svg)](native/CMakeLists.txt)

</div>

ArcForges is a native, local-first family of professional applications backed by an optional cloud companion.
The repository is intentionally initialized as one buildable monorepo: every planned product and boundary has
a real project now, while product behavior arrives through small, reviewable steps.

| Product | Purpose | Primary host |
|---|---|---|
| **ArcChat** | AI conversations, tasks, approvals, local capabilities, and MCP tools | Avalonia desktop, MAUI companion, Web companion |
| **ArcNotes** | Documents, knowledge, canvas, databases, and presentations | Avalonia desktop |
| **ArcScope** | Acquisition, decoding, visualization, analysis, and reports | Avalonia desktop |
| **ArcSlate** | Timeline editing, playback, color, audio, rendering, and export | Avalonia desktop + owned native C ABI |
| **ArcForges Cloud** | Identity, sync, durable agent execution, storage, policy, and operations | ASP.NET Core modular monolith |

There is exactly **one Mobile app** (`ArcChat.Mobile`) and exactly **one Web app**
(`ArcForges.Web.App`). Their other projects are internal libraries and tests, not additional apps or sites.

## Build

Prerequisites are .NET SDK 10.0.400, CMake 4.3+, a C++20 compiler, and the `maui-android`
and `wasm-tools` workloads. Native dependencies use a standard vcpkg installation; install and integration
commands are documented in [deploy/README.md](deploy/README.md).

NuGet uses its standard per-user cache outside the checkout. Keeping dependency sources outside the repository
prevents generated package files from being mistaken for ArcForges-owned source by static analysis.

```powershell
dotnet restore ArcForges.slnx --locked-mode
dotnet build ArcForges.slnx -c Release --no-restore
dotnet test --solution ArcForges.slnx -c Release --no-build

cmake --preset windows-msvc-x64-runtime-shared
cmake --build --preset windows-msvc-x64-runtime-shared-release
ctest --preset windows-msvc-x64-runtime-shared

cmake --preset windows-msvc-x64-shim-static
cmake --build --preset windows-msvc-x64-shim-static-release
ctest --preset windows-msvc-x64-shim-static
```

Windows contributors can run `vcpkg integrate install` once and open `win.slnx`; its native projects are
independent MSBuild `.vcxproj` definitions and do not call CMake. Build `Release|x64` or `Release|ARM64`
directly in Visual Studio.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the full verification flow.

Pull requests check the managed solution, both Windows native build paths, real application/browser smoke tests,
one Android package, dependency review, and secret scanning. CodeQL, clang-tidy, sanitizers, and fuzzing run in
the weekly/manual deep check. These gates do not depend on GitHub's paid Code Quality feature.

## Architecture

- C# 14 / .NET 10 throughout managed product code.
- Native Avalonia desktop applications; no embedded browser runtime.
- Android uses MAUI Mono AOT; iOS architecture is present but build-deferred.
- Web is standalone trimmed Blazor WebAssembly.
- Cloud stays JIT ASP.NET Core.
- C++20 implementations cross into managed code only through owned, versioned C17 ABIs and `[LibraryImport]`.

The repository is licensed under [AGPL-3.0-only](LICENSE). Third-party attribution is tracked in
[NOTICE.md](NOTICE.md).
