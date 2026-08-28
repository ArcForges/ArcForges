# Third-party License Register

The authoritative managed versions are in `Directory.Packages.props`; reviewed native packages and vcpkg
revision are in `deploy/README.md`. Managed restore is locked. Pull requests run dependency review and
vulnerability checks, and releases emit the resolved transitive graph as SPDX JSON.

This register is the Third-Party-License-Register manifest of Step 00.04. First-batch rows below harvest the
frozen baseline from `implementation-repository-layout.md` §4.1; a later NuGet skeleton back-fills exact
`nupkgSha256`/`repositoryCommit`/`licenseFileSha256`/copyright per `license-and-reuse-matrix.md` §3.2 in Step
01.01. Every direct managed + native dependency row must be present; prohibited families must stay absent.

| Dependency family | Version/source | SPDX/license | Compatibility/use | Owner |
|---|---|---|---|---|
| Avalonia | 12.1.1 | MIT | Native desktop UI | Step 01/06 |
| SkiaSharp and native assets | 4.151.1 | MIT | Cross-platform Avalonia rendering backend | Step 01/06 |
| .NET / ASP.NET Core / MAUI | 10.0.x | MIT | Managed hosts | Step 01 |
| xUnit v3 and Microsoft.NET.Test.Sdk | 4.0.0 / 18.9.0 | Apache-2.0 / MIT | Tests only; drift from layout §12 recorded in `docs/deviations.md` and `docs/adr/0001-dependency-version-drift.md` | Step 01 |
| OpenTimelineIO | 0.18.1#2, locked overlay | Apache-2.0 | Static inside owned shim | Step 24 |
| mdflib | 2.3.0, locked overlay | MIT | Static inside owned shim | Step 22 |
| FFmpeg | builtin **9.0.1** (frozen 2026-08-15) | LGPL-2.1-or-later configuration | Shared behind ArcMediaNative | Step 07 |
| libusb / miniaudio | 1.0.30 / 0.11.25 | LGPL-2.1-or-later / Unlicense OR MIT-0 | Shared runtime graph | Step 08 |
| OpenColorIO / OpenEXR / Imath | 2.5.2 / 3.4.13 / 3.2.2 | BSD-3-Clause | Static inside owned shims | Step 10/25 |
| OpenImageIO | 3.1.14.0#1 | Apache-2.0 | Static inside owned image shim | Step 25 |
| minizip-ng / zlib | 4.1.0 / 1.3.2#1 | Zlib | Minimal static transitive closure | Step 10/25 |
| libjpeg-turbo / libpng / TIFF | 3.2.0 / 1.6.58 / 4.7.2 | BSD-3-Clause / libpng-2.0 / libtiff | Minimal static image closure | Step 25 |
| fmt / rapidjson / robin-map / yaml-cpp | reviewed vcpkg checkout | MIT | Static implementation dependencies | Step 10/24/25 |
| expat | reviewed vcpkg checkout | MIT | Static MDF parser dependency | Step 22 |
| vcpkg-cmake / vcpkg-cmake-config | reviewed vcpkg checkout | MIT | Build-time port helpers only | Step 01 |
| Vulkan headers / AMF / oneVPL / nv-codec headers | reviewed vcpkg checkout | Apache-2.0 OR MIT / MIT / MIT / upstream header license | Hardware capability headers/loaders | Step 07 |
| glslang / SPIRV-Cross | reviewed vcpkg checkout | BSD-3-Clause / Apache-2.0 | Build-time shader host tools only | Step 01/25 |
| Selenium.WebDriver / Selenium.Support | 4.46.0 | Apache-2.0 | Real-browser tests only; Selenium Manager resolves the driver, no Node toolchain | Step 01/29 |
| coverlet.collector | 10.0.1 | MIT | Coverage collection only | Foundation closure |

## Step 00.04 seeded frozen baseline (authority: `implementation-repository-layout.md` §4.1)

Field set: `Dependency | Version | License (SPDX) | Source | Copyright | Notice | AGPLCompatibility | Owner`.

### Managed (central locked / test) stack

| Dependency | Version | License (SPDX) | Source | Copyright | Notice | AGPLCompatibility | Owner |
|---|---|---|---|---|---|---|---|
| Avalonia (family) | 12.1.1 | MIT | nuget.org | Avalonia Contributors | keep package LICENSE | yes | Step 01/06 |
| Silk.NET (Vulkan/KHR/EXT) | 2.23.0 | MIT | Silk.NET repo | Silk.NET contributors | keep NOTICE | yes (confined to `ArcForges.Desktop.Graphics.Vulkan`) | Step 07/21 |
| Silk.NET (Direct3D11/DXGI, Windows-only) | 2.23.0 | MIT | Silk.NET repo | Silk.NET contributors | keep NOTICE | yes | Step 07/21 |
| DocumentFormat.OpenXml | 3.5.1 | MIT | nuget.org | Microsoft | keep LICENSE | yes (ContentSandbox only) | Step 09/22 |
| SkiaSharp (+ native assets) | 4.151.1 | MIT | nuget.org | mono/SkiaSharp | keep LICENSE | yes | Step 01/06 |
| CSharpMath.SkiaSharp | 0.5.1 | MIT | CSharpMath repo | CSharpMath contributors | keep LICENSE | yes (Math rich-content only) | Step 09/15 |
| TextMateSharp | 2.0.4 | MIT | textmate-sharp | textmate-sharp authors | keep LICENSE | yes (tokenization only) | Step 09/27 |
| Markdig | 1.3.2 | BSD-2-Clause | nuget.org | Alexandre Mutel et al. | keep LICENSE | yes (Markdown) | Step 09 |
| AngleSharp | 1.7.1 | MIT | nuget.org | AngleSharp contributors | keep LICENSE | yes (ContentSandbox SafeHtml only) | Step 09/22 |
| xUnit v3 / Test SDK | 4.0.0 / 18.9.0 | Apache-2.0 / MIT | nuget.org | .NET foundation | keep LICENSE | yes (tests only) | Step 01 |
| Selenium.WebDriver / Selenium.Support | 4.46.0 | Apache-2.0 | nuget.org | Selenium contributors | keep LICENSE | yes (tests only) | Step 01/29 |
| bunit / coverlet | 2.9.0 / 10.0.1 | MIT / MIT | nuget.org | bUnit contributors / Microsoft | keep LICENSE | yes (tests only) | Step 01/29 |
| Microsoft.AspNetCore.SignalR.Client | 10.0.10 | MIT | nuget.org | Microsoft | keep LICENSE | yes (`*.CloudClient`/Mobile realtime only) | Step 03/12 |
| Microsoft.CodeAnalysis.NetAnalyzers | 10.0.400 | MIT | nuget.org | Microsoft | keep LICENSE | yes (build analyzers) | Step 01 |
| Microsoft.Maui.Controls | 10.0.100 | MIT | nuget.org | Microsoft | keep LICENSE | yes (MAUI head/shared presentation) | Step 01/18 |

### Native supply chain (vcpkg checkout `36677bbd0b3bf11da7376e62e14bffcc54d2eaeb`)

| Dependency | Version | License (SPDX) | Source | Copyright | Notice | AGPLCompatibility | Owner |
|---|---|---|---|---|---|---|---|
| FFmpeg | builtin 9.0.1 (shared) | LGPL-2.1-or-later configuration | pinned vcpkg checkout builtin | FFmpeg project | exact config/license string to evidence | yes (inside `ArcMediaNative`, no `AV*` egress) | `arcmedia_ffmpeg_abi` (ArcMediaNative) / Step 07 |
| miniaudio | 0.11.25 (header-only) | Unlicense OR MIT-0 | pinned vcpkg checkout builtin | David Reid et al. | keep declarations | yes (only WASAPI/CoreAudio/ALSA) | `arcmedia_ffmpeg_abi` / Step 07 |
| libusb | 1.0.30 | LGPL-2.1-or-later shared | pinned vcpkg checkout builtin (`libusb[core]`, no udev) | libusb project | relink/Corresponding Source | yes (controlled binding) | ArcScope native / Step 08/21 |
| hidapi | ReferenceOnly | source LGPL3/BSD/original | source repo only | hidapi authors | not distributed | n/a (not built) | ArcScope platform HID adapter |
| OpenTimelineIO | 0.18.1#2 overlay | Apache-2.0 | `eng/native/vcpkg/ports/` overlay | Academy Software Foundation | keep NOTICE/source offer | yes (static in owned shim) | `arcslate_otio_abi` / Step 24 |
| mdflib | v2.3.0 overlay | MIT | `eng/native/vcpkg/ports/` overlay | Ingemar Hedvall | keep LICENSE-3RD-PARTY | yes (static in owned shim) | `arcscope_mdf_abi` / Step 22 |
| OpenColorIO | 2.5.2 | BSD-3-Clause | pinned vcpkg builtin | OCIO project | keep NOTICE | yes (static in owned shim) | `arcslate_color_abi` / Step 25 |
| OpenImageIO | 3.1.14.0#1 | Apache-2.0 | pinned vcpkg builtin | OIIO project | keep NOTICE/source offer | yes (static in owned shim) | `arcslate_image_abi` / Step 25 |
| OpenEXR / Imath | 3.4.13 / 3.2.2 | BSD-3-Clause | pinned vcpkg builtin | OpenEXR project | keep NOTICE | yes (OIIO/OCIO closure) | image/color shims / Steps 10/25 |
| ZLIB | 1.3.2#1 | Zlib | pinned vcpkg builtin | zlib authors | keep notice | yes (static in owned shims) | mdflib/OIIO closure |
| EXPAT | 2.8.2 | MIT | pinned vcpkg builtin | expat project | keep NOTICE | yes (static MDF parser dep) | `arcscope_mdf_abi` / Step 22 |
| PDFium (non-V8) | 152.0.7961.0 per-RID hash | PDFium BSD-style + notices | immutable `chromium/7961` binary release | PDFium authors | third-party notices in release | yes (ContentSandbox, non-V8 only) | `ArcForges.ContentSandbox` / Step 09 |
| glslang / SPIRV-Cross | 16.4.0 / 1.4.350.1 | BSD-3-Clause / Apache-2.0 | pinned vcpkg builtin (`host-tools`) | Khronos | keep notices | build-time only (not staged) | shader pipeline / Steps 01/25 |

## Constraints (must stay absent from the dependency graph)

- **Prohibited managed families**: Silk.NET.OpenGL, AvaloniaEdit, ClosedXML, CSharpMath.Avalonia, NAudio, and any managed-layer direct FFmpeg binding (hosted binding/header generator). Blocked via locked `Directory.Packages.props` + restore/build/publish/SBOM negative scans.
- **Prohibited control/AGP stack**: Nerdbank.MessagePack, Fory, TypeScript/Node packages (including Node-driver browser automation such as `Microsoft.Playwright`; real-browser tests use Selenium .NET per `implementation-repository-layout.md` §8/§12), SqlSugar, Dapper, and any local model runtime.
- **Native**: single vendored root is the frozen vcpkg checkout; no vcpkg manifest/configuration, custom triplet, or repository-local installed tree; FFmpeg only from the pinned checkout's builtin port; OpenTimelineIO/mdflib only from `eng/native/vcpkg/ports/` overlay; CMake consumes `$env:VCPKG_ROOT` toolchain + standard triplet, Windows `.slnx` consumes one-time `vcpkg integrate install`.
- **Replaced/Dropped sources**: QuaZip → `System.IO.Compression`; Serial-Studio OpenSSL → .NET/OS TLS; KissFFT → source-coverage/math Oracle only (V1 uses locked MathNet.Numerics); all three must show zero build/link/distribute hits.
- **FFmpeg GPU feature matrix** frozen: win-x64 = `vulkan,qsv,nvcodec,amf`; win-arm64 = `vulkan`; linux-x64 = `vulkan,vaapi,qsv,nvcodec`; macOS both RID core only with portfile VideoToolbox; `all/all-gpl/all-nonfree/gpl/nonfree/x264/x265/fdk-aac/opencl/opengl/avdevice` permanently disabled. `ArcMediaNative` accepts only caller-owned byte/seek/write callbacks + validated handles — no URL/scheme/socket/network entry.
- libusb on Linux uses `libusb[core]` (udev-less netlink); hidapi ReferenceOnly; OS/driver deps closed in `NativeSystemDependencyRegistryV1` and equal to the final dependency scan.
