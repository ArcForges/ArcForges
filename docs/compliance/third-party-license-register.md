# Third-party License Register

The authoritative direct versions are in `Directory.Packages.props` and the three native vcpkg manifests.
Every restore is locked. Pull requests run dependency review and vulnerability checks; pull requests and releases
emit the resolved transitive graph as SPDX JSON rather than maintaining a second hand-written version list.

| Dependency family | Version/source | SPDX/license | Compatibility/use | Owner |
|---|---|---|---|---|
| Avalonia | 12.1.1 | MIT | Native desktop UI | Step 01/06 |
| SkiaSharp and native assets | 4.151.1 | MIT | Cross-platform Avalonia rendering backend | Step 01/06 |
| .NET / ASP.NET Core / MAUI | 10.0.x | MIT | Managed hosts | Step 01 |
| xUnit v3 and Microsoft.NET.Test.Sdk | 3.2.2 / 18.8.1 | Apache-2.0 / MIT | Tests only | Step 01 |
| OpenTimelineIO | 0.18.1#2, locked overlay | Apache-2.0 | Static inside owned shim | Step 24 |
| mdflib | 2.3.0, locked overlay | MIT | Static inside owned shim | Step 22 |
| FFmpeg | builtin 8.1.2#3 | LGPL-2.1-or-later configuration | Shared behind ArcMediaNative | Step 07 |
| libusb / miniaudio | 1.0.30 / 0.11.25 | LGPL-2.1-or-later / Unlicense OR MIT-0 | Shared runtime graph | Step 08 |
| OpenColorIO / OpenEXR / Imath | 2.5.2 / 3.4.13 / 3.2.2 | BSD-3-Clause | Static inside owned shims | Step 10/25 |
| OpenImageIO | 3.1.14.0#1 | Apache-2.0 | Static inside owned image shim | Step 25 |
| minizip-ng / zlib | 4.1.0 / 1.3.2#1 | Zlib | Minimal static transitive closure | Step 10/25 |
| libjpeg-turbo / libpng / TIFF | 3.2.0 / 1.6.58 / 4.7.2 | BSD-3-Clause / libpng-2.0 / libtiff | Minimal static image closure | Step 25 |
| fmt / rapidjson / robin-map / yaml-cpp | locked vcpkg baseline | MIT | Static implementation dependencies | Step 10/24/25 |
| expat | locked vcpkg baseline | MIT | Static MDF parser dependency | Step 22 |
| vcpkg-cmake / vcpkg-cmake-config | locked vcpkg baseline | MIT | Build-time port helpers only | Step 01 |
| Vulkan headers / AMF / oneVPL / nv-codec headers | locked vcpkg baseline | Apache-2.0 OR MIT / MIT / MIT / upstream header license | Hardware capability headers/loaders | Step 07 |
| glslang / SPIRV-Cross | locked vcpkg baseline | BSD-3-Clause / Apache-2.0 | Build-time shader host tools only | Step 01/25 |
| Microsoft.Playwright | 1.61.0 | Apache-2.0 | Browser smoke tests only | Foundation closure |
| coverlet.collector | 10.0.1 | MIT | Coverage collection only | Foundation closure |
