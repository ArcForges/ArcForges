# Third-Party License Register

> Frozen first-entry skeleton per Step 00.04. Managed versions/License are the authoritative
> `implementation-repository-layout.md` §12 `Directory.Packages.props` baseline (written verbatim, never
> re-chosen by an implementer); native versions/licenses are `license-and-reuse-matrix.md` §3.3 / layout §9.1
> (single vcpkg builtin baseline `40f3c709db80acf154ac4b17a1f83c564ebd022e`). Machine-readable double in
> `third-party-license-register.json`. `Owner` = introducing step.
>
> **Forbidden set (zero-entry, must not enter the dependency graph):** Silk.NET.OpenGL / EGL-direct,
> AvaloniaEdit, ClosedXML, CSharpMath.Avalonia, NAudio, any managed direct FFmpeg binding
> (e.g. FFmpeg.AutoGen — ReferenceOnly only), Nerdbank.MessagePack, Fory, SqlSugar, Dapper, TypeScript/Node
> packages, local model runtime. A second `vcpkg.json`/`ArcForges.db`/fourth vcpkg manifest root is also
> forbidden.

## Fields

`Dependency | Version | License(SPDX) | Source(仓库/源) | Copyright | Notice | AGPLCompatibility | Owner(引入步骤)`

## Managed baseline (layout §12)

| Dependency | Version | License(SPDX) | Source | Copyright | Notice | AGPLCompatibility | Owner |
|---|---|---|---|---|---|---|---|
| Avalonia family (`Avalonia`, `.Desktop`, `.Themes.Fluent`, `.Skia`, `.Headless`, `.Headless.XUnit`) | `12.1.1` | MIT | nuget.org | Avalonia contributors | package NOTICE | yes | 01/06 |
| CommunityToolkit.Mvvm | `8.4.2` | MIT | nuget.org | .NET Foundation | - | yes | 01/06 |
| StreamJsonRpc | `2.25.29` | MIT | nuget.org | Microsoft | - | yes | 01/02/03 |
| PolyType | `1.4.1` | MIT | nuget.org | Microsoft | - | yes | 02 |
| Refit / Refit.HttpClientFactory | `15.0.0` | MIT | nuget.org | ReactiveUI | - | yes | 02 |
| Microsoft.AspNetCore.SignalR.Client | `10.0.10` | MIT | nuget.org | Microsoft | - | yes | 02/03/12 |
| Microsoft.AspNetCore.OpenApi | `10.0.10` | MIT | nuget.org | Microsoft | - | yes | 02/12 |
| Microsoft.Extensions.ApiDescription.Server | `10.0.10` | MIT | nuget.org | Microsoft | - | yes | 02/12 |
| Microsoft.Extensions.Hosting(+Abstractions) | `10.0.10` | MIT | nuget.org | Microsoft | - | yes | 01/06 |
| Microsoft.Extensions.DependencyInjection.Abstractions | `10.0.10` | MIT | nuget.org | Microsoft | - | yes | 01 |
| Microsoft.Extensions.Logging.Abstractions | `10.0.10` | MIT | nuget.org | Microsoft | - | yes | 01 |
| Microsoft.Extensions.Options.* (+DataAnnotations) | `10.0.10` | MIT | nuget.org | Microsoft | - | yes | 01 |
| Microsoft.Extensions.Validation | `10.0.10` | MIT | nuget.org | Microsoft | - | yes | 12 |
| Microsoft.Extensions.Http.Resilience | `10.8.0` | MIT | nuget.org | Microsoft | - | yes | 12 |
| Microsoft.Data.Sqlite.Core | `10.0.10` | MIT | nuget.org | Microsoft | - | yes | 01/04 |
| SQLitePCLRaw.bundle_e_sqlite3 | `3.0.5` | Apache-2.0 | nuget.org | ericsink | - | yes | 04 |
| Npgsql / Npgsql.OpenTelemetry | `10.0.3` | PostgreSQL License | nuget.org | Npgsql contributors | - | yes | 12 |
| Microsoft.Extensions.AI | `10.8.3` | MIT | nuget.org | Microsoft | - | yes | 13 |
| Microsoft.Agents.AI | `1.17.0` | MIT | nuget.org | Microsoft | - | yes | 13 |
| ModelContextProtocol.Core | `2.1.0` | Apache-2.0 | nuget.org | .NET Foundation / ModelContextProtocol | - | yes | 09 |
| Fido2 | `4.0.1` | MIT | nuget.org | fido2-net-lib | - | yes | 12/26 |
| Konscious.Security.Cryptography.Argon2 | `1.3.1` | MIT | nuget.org | Konscious | - | yes | 12/26 |
| Cronos | `0.13.0` | MIT | nuget.org | piotrmazurek | - | yes | 12/13 |
| AWSSDK.S3 | `4.0.102` | Apache-2.0 | nuget.org | Amazon | - | yes | 12/26 |
| Azure.Identity / Azure.Security.KeyVault.Keys / .Secrets | `1.21.0` / `4.10.0` / `4.11.0` | MIT | nuget.org | Microsoft | - | yes | 12/26 |
| OpenTelemetry (+Extensions.Hosting, +Exporter.OpenTelemetryProtocol) | `1.17.0` | Apache-2.0 | nuget.org | .NET Foundation | - | yes | 01/06 |
| Aspire.Hosting (+AppHost, +Testing) | `13.4.6` | MIT | nuget.org | .NET Foundation | - | yes | 12 |
| Microsoft.Maui.Controls | `10.0.90` | MIT | nuget.org | .NET Foundation | - | yes | 18 |
| Microsoft.AspNetCore.Components.WebAssembly(+DevServer) | `10.0.10` | MIT | nuget.org | Microsoft | - | yes | 29 |
| bunit | `2.9.0` | MIT | nuget.org | bUnit | - | yes | 29 |
| Selenium.WebDriver / Selenium.Support | `4.46.0` | Apache-2.0 | nuget.org | Selenium | - | yes | 29 |
| System.IO.Ports | `10.0.10` | MIT | nuget.org | Microsoft | - | yes | 21 |
| MQTTnet | `5.2.0.1603` | MIT | nuget.org | chkr | - | yes | 21 |
| NModbus / NModbus.Serial | `3.0.83` | MIT (Serial nupkg license-metadata incomplete; back-filled by source/hash) | nuget.org + upstream | NModbus | - | yes | 21 |
| MathNet.Numerics | `5.0.0` | MIT | nuget.org | Math.NET | - | yes | 21/22 |
| Dock.Avalonia | `12.1.0` | MIT | nuget.org | Dock.Avalonia | - | yes | 21 |
| Silk.NET.Vulkan/KHR/EXT, .Direct3D11/.DXGI | `2.23.0` | MIT | nuget.org | Silk.NET | - | yes | 07/21/24 |
| Markdig | `1.3.2` | BSD-2-Clause | nuget.org | lunet | - | yes | 09 |
| AngleSharp | `1.7.1` | MIT | nuget.org | AngleSharp | - | yes | 09 (ContentSandbox only) |
| DocumentFormat.OpenXml | `3.5.1` | MIT | nuget.org | .NET Foundation | - | yes | 09 (ContentSandbox) |
| TextMateSharp / TextMateSharp.Grammars | `2.0.4` | MIT | nuget.org | avaloniaui/textmate | - | yes | 09/21 |
| SkiaSharp | `4.151.1` | MIT | nuget.org | mono | native closure SBOM | yes | 01/06 |
| CSharpMath.SkiaSharp | `0.5.1` | MIT | nuget.org | CSharpMath | - | yes | 10 |
| Velopack | `1.2.0` | MIT | nuget.org | Velopack | - | yes | 24/31 |
| Microsoft.CodeAnalysis.NetAnalyzers | `10.0.302` | MIT | nuget.org | Microsoft | - | yes (build-time) | 01 |
| xunit.v3 / xunit.runner.visualstudio | `3.2.2` / `3.1.5` | Apache-2.0 | nuget.org | xunit | - | yes (test) | 01 |
| Microsoft.NET.Test.Sdk | `18.8.1` | MIT | nuget.org | Microsoft | - | yes (test) | 01 |
| coverlet.collector | `10.0.1` | MIT | nuget.org | coverlet | - | yes (test) | 01 |
| BenchmarkDotNet | `0.15.8` | MIT | nuget.org | BenchmarkDotNet | - | yes (bench only) | 21/24 |
| Microsoft.Extensions.TimeProvider.Testing | `10.8.0` | MIT | nuget.org | Microsoft | - | yes (test) | 01 |
| NSubstitute | `6.1.0` | BSD-3-Clause | nuget.org | NSubstitute | - | yes (test) | 01 |
| Testcontainers / Testcontainers.PostgreSql | `4.13.0` | MIT | nuget.org | Testcontainers | - | yes (test) | 12 |
| Microsoft.AspNetCore.Mvc.Testing | `10.0.10` | MIT | nuget.org | Microsoft | - | yes (test) | 12 |
| NetArchTest.Rules | `1.3.2` | MIT (nupkg license-metadata incomplete; source/hash back-fill) | nuget.org + upstream | NetArchTest | - | yes (test) | 01 |

## Native baseline (single vcpkg builtin `40f3c709db80acf154ac4b17a1f83c564ebd022e`)

| Dependency | Version | License(SPDX) | Source | Copyright | Notice | AGPLCompatibility | Owner |
|---|---|---|---|---|---|---|---|
| FFmpeg | `8.1.2#3` | LGPL-2.1-or-later configuration | vcpkg builtin port (`runtime-shared`) | FFmpeg developers | FFmpeg NOTICE; Corresponding Source | yes (LGPL) | 07/24 |
| miniaudio | `0.11.25` | Unlicense OR MIT-0 | vcpkg builtin (header-only into ArcMediaNative) | miniaudio | - | yes | 07/24 |
| libusb | `1.0.30` | LGPL-2.1-or-later | vcpkg builtin (`runtime-shared`; `default-features=false`) | libusb | - | yes | 21/08 |
| OpenTimelineIO | `0.18.1#2` | Apache-2.0 | overlay port (`shim-static`) | OTIO | - | yes | 24 |
| OpenColorIO | `2.5.2` | BSD-3-Clause | vcpkg builtin (`shim-static`) | OCIO | - | yes | 24 |
| OpenImageIO | `3.1.14.0#1` | Apache-2.0 | vcpkg builtin (`shim-static`) | OIIO | - | yes | 25 |
| OpenEXR / Imath | `3.4.13` / `3.2.2` | BSD-3-Clause | vcpkg builtin (`shim-static`) | OpenEXR/Imath | - | yes | 25 |
| mdflib | `v2.3.0` | MIT | overlay port (`shim-static`) | Ingemar Hedvall | LICENSE-3RD-PARTY.md | yes | 22 |
| zlib / expat | `1.3.2#1` / `2.8.2` | Zlib / MIT | vcpkg builtin (`shim-static`) | - | - | yes | 24/22 |
| rapidjson / fmt / robin-map / yaml-cpp / sse2neon | `2025-02-26` / `12.2.0#1` / `1.4.1` / `0.9.0#1` / `1.9.1` | MIT (robin-map MIT, yaml-cpp MIT, sse2neon MIT) | vcpkg builtin (`shim-static`) | - | - | yes | 24/25 |
| libjpeg-turbo | `3.2.0` | BSD-3-Clause | vcpkg builtin (`shim-static`) | - | - | yes | 25 |
| libpng | `1.6.58` | libpng-2.0 | vcpkg builtin | - | - | yes | 25 |
| tiff / libdeflate / openjph | `4.7.2` / `1.25` / `0.30.1` | libtiff / MIT / BSD-2-Clause | vcpkg builtin | - | - | yes | 25 |
| minizip-ng / pystring | `4.1.0` / `1.2.0` | Zlib / BSD-3-Clause | vcpkg builtin | - | - | yes | 24 |
| glslang / SPIRV-Cross | `16.4.0` / `1.4.350.1` | BSD-3-Clause / Apache-2.0 | vcpkg builtin (`host-tools`, build-time only) | - | build SBOM/NOTICE | yes | 01/25 |
| PDFium (non-V8) | `152.0.7961.0` | BSD-style (+ third-party notices; wrapper MIT) | external per-RID binary registry exception | PDFium | NOTICE | yes | 09 (ContentSandbox) |

## Forbidden / ReferenceOnly — zero-entry (must NOT enter the dependency graph)

| Item | Disposition | Owner |
|---|---|---|
| Silk.NET.OpenGL / EGL-direct / self-built GL renderer | forbidden | all |
| AvaloniaEdit | forbidden (TextMateSharp token-only) | 01/09/21 |
| ClosedXML | forbidden (DocumentFormat.OpenXml only) | 09 |
| CSharpMath.Avalonia | forbidden (SkiaSharp adapter only) | 10 |
| NAudio | forbidden (ArcMediaNative + miniaudio single owner) | all |
| FFmpeg.AutoGen (managed FFmpeg binding) | ReferenceOnly surface oracle; zero in restore/build/publish | 07 |
| Nerdbank.MessagePack / Fory | forbidden (JSON only) | all |
| SqlSugar / Dapper | forbidden (explicit SQL) | all |
| TypeScript / Node / npm / .esproj / React | forbidden | all |
| local model runtime / Ollama / Whisper / embedding | forbidden | all |
| hidapi / KissFFT / QuaZip / OpenSSL / tweetnacl / SimpleCrypt | ReferenceOnly / Replace / Drop per license matrix §3; not built/staged | 07/21/22 |