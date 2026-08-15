# StartArcForges Packaged Oracle — Static Evidence

| Field | Value |
|---|---|
| Status | **NotExecuted** |
| Root | `C:\MyFile\ArcForges\StartArcForges` |
| Capture date | 2026-08-15 |
| Execution boundary | File-system metadata, version resources, Authenticode metadata, package metadata, launch-wrapper text, and dependency/package closure names only; no executable, service, installer, updater, or child process was launched. |
| Full-tree records | 11,297 files |
| Full-tree bytes | 4,172,582,286 |
| Manifest hash | `0e16e92490e1986b71f2b0186ee0a0fe4212119e5eade4b0b3d7f35cd95b143d` |

## Reproducible manifest

The manifest is the UTF-8/LF SHA-256 of the sorted records `product-relative-path|file-length`, with one final LF. The record set covers every regular file under the six product directories; the hash is an evidence identity, not a runtime or compatibility result.

| Product directory | Files | Bytes |
|---|---:|---:|
| `AFFiNE` | 48 | 668,249,469 |
| `AionUi` | 9,794 | 2,194,699,158 |
| `ArcVideo` | 56 | 112,901,021 |
| `ArcVideoFoundation` | 22 | 2,451,306 |
| `Serial-Studio` | 180 | 389,141,902 |
| `siyuan` | 1,197 | 805,139,430 |

## Static artifact observations

| Product | Artifact | Bytes | Version resource | Signature |
|---|---|---:|---|---|
| AFFiNE | `AFFiNE/AFFiNE.exe` | 210,950,552 | File/Product `0.27.2`; company `toeverything` | Valid; TOEVERYTHING PTE. LTD. |
| AFFiNE | `AFFiNE/affine-0.27.2-stable-windows-x64.nsis.exe` | 164,556,648 | File/Product `0.27.2` | Valid; TOEVERYTHING PTE. LTD. |
| AionUi | `AionUi/AionUi.exe` | 204,521,984 | File/Product `37.10.3`; company `GitHub, Inc.` | NotSigned |
| AionUi | `AionUi/AionUi-2.1.35-win-x64.exe` | 459,829,069 | File/Product `2.1.35`; company `AionUi` | NotSigned |
| ArcVideo | `ArcVideo/arcvideo-editor.exe` | 12,359,680 | File `1.0.0.0`, Product `1.0`; company `Olive Team` | NotSigned |
| Serial-Studio | `Serial-Studio/bin/Serial-Studio-GPL3.exe` | 22,913,024 | no version resource | NotSigned |
| siyuan | `siyuan/SiYuan.exe` | 232,703,488 | File `3.7.3`, Product `3.7.3.0` | NotSigned |
| siyuan | `siyuan/siyuan-3.7.3-win.exe` | 218,459,309 | File/Product `3.7.3` | NotSigned |

Additional static package anchors include `AFFiNE/resources/app.asar` (118,441,181 bytes), `AionUi/resources/app.asar` (384,895,467 bytes), `AionUi/resources/bundled-aioncore/win32-x64/aioncore.exe` (77,713,408 bytes), `ArcVideoFoundation/lib/arcvideo-foundation.lib` (2,051,380 bytes), and `siyuan/resources/pandoc.zip` (38,138,476 bytes).

The observed closure is recorded as file/layout evidence only: AFFiNE Chromium/Qt/Vulkan/FFmpeg files; AionUi Electron/Chromium/FFmpeg/Vulkan, bundled AionCore, Node/ACP resources, `app-update.yml`, PWA manifest and service worker; ArcVideo Qt/FFmpeg/OpenColorIO/OpenImageIO/OpenEXR/PortAudio; Serial-Studio Qt/QML/WebEngine; and siyuan Electron/Chromium/FFmpeg/Vulkan, kernel and Pandoc resources. `run.cmd`/`qt.conf` wrapper text was read but never invoked.

This oracle is not source coverage, a build result, a signature-release result, a runtime compatibility result, or a performance result.
