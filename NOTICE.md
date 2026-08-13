# ArcForges Notices

ArcForges is licensed under AGPL-3.0-only. Corresponding Source is published at
<https://github.com/ArcForges/ArcForges>.

Third-party code and assets must be recorded here and in `docs/compliance/` before distribution.

| Component | Version/source | License | Use | Notice/source offer |
|---|---|---|---|---|
| .NET, ASP.NET Core, and MAUI | 10 | MIT | Managed runtime, Cloud, Web, and Mobile hosts | Microsoft notices ship with published runtimes |
| Avalonia | 12.1.1 | MIT | Native desktop UI | Upstream license included in release notices |
| FFmpeg | 8.1.2#3 | LGPL-2.1-or-later | Shared runtime libraries behind `ArcMediaNative` | Dynamic linking and corresponding upstream source/version are preserved |
| libusb | 1.0.30 | LGPL-2.1-or-later | Shared device-access runtime | Dynamic linking and upstream notice preserved |
| miniaudio | 0.11.25 | Unlicense OR MIT-0 | Audio abstraction | Upstream notice preserved |
| OpenTimelineIO | 0.18.1#2 | Apache-2.0 | Statically linked into owned OTIO shim | License and NOTICE are copied from the locked source |
| OpenColorIO / OpenEXR / Imath | 2.5.2 / 3.4.13 / 3.2.2 | BSD-3-Clause | Statically linked color and image shims | Upstream notices preserved |
| OpenImageIO | 3.1.14.0#1 | Apache-2.0 | Statically linked image shim | Upstream notice preserved |
| mdflib | 2.3.0 | MIT | Statically linked MDF shim | License and third-party notice are copied from the locked source |

The resolved transitive inventory and license texts are emitted as SPDX JSON by the release workflow. Exact
managed versions are locked in `packages.lock.json`; reviewed native versions and install features are recorded
in `deploy/README.md`, with the two custom ports retained under `eng/native/vcpkg/ports`.
