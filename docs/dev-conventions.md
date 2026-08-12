# Development Conventions

- Managed product code uses C# 14 and .NET 10. The SDK is pinned by `global.json`.
- Native implementation uses strict C++20; public ABI headers remain C17-compatible.
- Add `SPDX-License-Identifier: AGPL-3.0-only` to new source and configuration files.
- Package versions belong only in `Directory.Packages.props`; commit every generated `packages.lock.json`.
- Four desktop heads publish Native AOT. Cloud remains framework-dependent JIT. Android uses MAUI Mono AOT.
- iOS is architecturally present and excluded unless `EnableIosTarget=true` is explicitly supplied.
- Web is standalone trimmed Blazor WebAssembly with `RunAOTCompilation=false`.
- Use owned C ABIs and source-generated `[LibraryImport]`; never expose third-party C++ ABI or native ownership.
- Work in a Git worktree and keep one focused branch/PR per owned step.

Warnings-as-errors wave 1 covers foundations, contracts, domains, and production-host AOT warnings. Wave 2
becomes repository-wide after the horizontal foundations are implemented and existing warnings are cleared.
