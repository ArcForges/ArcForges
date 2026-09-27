# Existing native ABI package release

> Historical implementation and evidence. Current CI/local execution is governed by
> [AGENTS.md](../AGENTS.md) and P2-017; the runtime and package-consumer gates recorded below are no longer required.

## Current retained publication

GOV.17 retires Media, Colour and Otio from future publication and moves the image producer to native/arcimage-abi under ArcImageNative, keeping arc_image_* exports unchanged. The current allowlist is Build.Policy, Native.Abstractions, Native.Image and Native.Image.Runtime.win-x64. The evidence below describes the original four-family candidate only; it is not rerun or rewritten as evidence for the reduced candidate.

## Historical scope fixed before implementation

Base: DesktopPlatform `7bdbf6c4656721088081cdf85c9f1ec8d78bc848`. The requested delivery is the
complete existing Windows x64 ABI and its actual dependencies, not new media/timeline business APIs.
The four owned libraries currently expose ABI version, dependency build information and thread-local
error queries. Metal remains macOS-only and is outside this Windows package admission.

The package identities follow the Design package registry: `ArcForges.Native.Abstractions`, managed
`ArcForges.Native.Media`, `.Colour`, `.Image`, `.Otio`, and their matching `.Runtime.win-x64` packages.
`ArcForges.Build.Policy` remains in the same verified release. Shared product placeholders remain excluded.

## Findings and repair plan

1. Main publication and native validation were independent workflows. In runs 34675014058/34675014032,
   upload completed at 05:15:11 UTC while native validation completed at 05:16:10 UTC. Route PRs and main
   releases through one reusable gate: native compilation/tests and source checks precede packing;
   package consumers and the aggregate gate precede publication. Keep each main run independent.
2. Native outputs were only copied into a producer test directory. Export immutable staged artifacts
   with commit, RID, hashes, imports and exports. Packing must consume that artifact from the same run;
   missing, changed or mismatched native assets must fail before upload.
   Validation also exposed global installed vcpkg libraries with older Vulkan-Headers/OpenEXR/OpenJPH
   versions than the pinned checkout. Use an isolated Windows installed tree shared by CMake and MSBuild;
   verify installed recipe and release-library hashes instead of inferring provenance from vcpkg HEAD.
3. The current managed interop project is a test probe. Add per-capability public bindings for all
   existing entry points, sharing fixed-width status/layout/error handling in Native.Abstractions.
   Use generated LibraryImport and explicit application-directory loading without PATH/CWD fallback.
4. Admit real RID packages containing the owned DLL, complete non-system DLL closure, C headers and
   import library. Record static and shared upstream dependencies, preserve licences and pinned source
   records, include corresponding FFmpeg/libusb sources and build recipes, and distinguish Windows
   system API dependencies from redistributed Visual C++ runtime files.
5. Prove the delivered bytes in an external consumer with an empty NuGet cache and no producer source
   references. Exercise each package independently and together, publish/run Windows x64 Native AOT,
   verify deployed native hashes, and reject missing/tampered libraries and incompatible RID/version
   pairs. Retain portable Build.Policy consumer checks on Windows and Linux.

## Closure evidence

Validated implementation commit: `a0d52c508c598b0bd7929baddafe78fa7fbbb49d`.

- Locked managed restore/build, four architecture checks, dotnet format, actionlint 1.7.12 and
  pre-commit passed. Local tools were .NET SDK 10.0.400, CMake 4.4.3 and MSVC 19.51.36256.
- A fresh isolated vcpkg installation completed at the pinned commit. Both CMake profiles were
  configured with `--fresh`, rebuilt and staged; all 1 + 3 CTests passed. The independent
  `win.slnx Release|x64` pre-push gate and its app-local C# ABI test also passed.
- Native staging verified installed recipe versions/hashes, release-library hashes, DLL import/export
  closure, LGPL configuration and corresponding source archives. Media contains 12 DLLs and 15
  upstream records; Colour 4/12; Image 4/21; Otio 3/5. These counts include CRT and build dependencies,
  and do not imply every build dependency has a separate shipped DLL.
- The final local ten-package set `1.0.0-ci.native.6` passed all twelve package guards and independent
  JIT/Native AOT execution for each capability and all four together. The C17 consumer used only
  packaged headers/import libraries. Missing owned/transitive DLLs, tampering and wrong RID were
  rejected, including attempted working-directory fallback. Projects, locks and the success report
  are retained under `artifacts/native-consumer-evidence`.

[Hosted PR run 34677477555](https://github.com/ArcForges/DesktopPlatform/actions/runs/34677477555)
passed every gate with CI's pinned CMake 4.3.3. It built PR merge source
`105be7ea21d63addf57e0f259a4d57d8a29b7f6c`, packed version `1.0.0-ci.34677477555.1` on Linux,
and consumed the same archives on Windows and Linux. Windows ran all five JIT/AOT cases, C17 and
the failure fixtures. The downloaded candidate was independently re-verified against that merge SHA.

| Gate | Started (UTC, 2026-09-12) | Finished |
|---|---|---|
| Native build, tests, provenance and artifact | 06:11:25 | 06:15:20 |
| Managed build, packing and package guards | 06:15:22 | 06:16:54 |
| Windows package consumers, Native AOT and C17 | 06:16:56 | 06:19:41 |
| Aggregate success | 06:19:51 | 06:19:59 |

The retained candidate contains ten actual NuGets. Runtime archive sizes in that hosted run were
approximately Media 26.9 MiB, Colour 0.93 MiB, Image 4.67 MiB and Otio 176 KiB; Build.Policy remains
about 16.5 KiB. Runtime archives include the DLLs, headers/import libraries, manifests, notices,
recipes and relevant source archives. Sizes vary with the compiler and dependency release.

The main publication job depends on the entire reusable gate and rechecks the candidate before OIDC
authentication. PR runs do not upload to nuget.org. Public upload/indexing of the newly admitted native
packages remains a main-merge release outcome; the earlier Build.Policy upload does not prove that
new package IDs are publicly available. No other native RID, decode/encode, image processing, timeline
editing, hostile-content sandbox, GPU, application or commercial-operation acceptance is claimed.
