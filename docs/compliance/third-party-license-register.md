# Third-party License Register

The authoritative dependency versions are in `Directory.Packages.props` and the three native vcpkg manifests.
This foundation register is intentionally concise; release closure expands it to the resolved transitive graph.

| Dependency family | Version/source | SPDX/license | Compatibility/use | Owner |
|---|---|---|---|---|
| Avalonia | 12.1.1 | MIT | Native desktop UI | Step 01/06 |
| .NET / ASP.NET Core / MAUI | 10.0.x | MIT | Managed hosts | Step 01 |
| xUnit v3 and Microsoft.NET.Test.Sdk | 3.2.2 / 18.8.1 | Apache-2.0 / MIT | Tests only | Step 01 |
| OpenTimelineIO | 0.18.1#2, locked overlay | Apache-2.0 | Static inside owned shim | Step 24 |
| mdflib | 2.3.0, locked overlay | MIT | Static inside owned shim | Step 22 |
| FFmpeg | builtin 8.1.2#3 | LGPL-2.1-or-later configuration | Shared behind ArcMediaNative | Step 07 |
