# Replacement-Backlog（替换台账）

> Structure per `license-and-reuse-matrix.md` §6.4；first entries per Step 00.04。Consistent with §6.4: V1 does
> **not** introduce a temporary/to-be-replaced port — every listed item is a **direct, permanent replacement**
> decision (`TemporarySource = none`, never ported to production). Machine-readable double in
> `replacement-backlog.json`.

## Fields

`ItemId | What | Why | TemporarySource | ReplacementDesign | ReplacementStage(owning step) | ExitCriteria | Status`

## First entries

### RPL-0001 — QuaZip → System.IO.Compression
| Field | Value |
|---|---|
| ItemId | `RPL-0001` |
| What | Replace Serial-Studio vendored `QuaZip` (LGPL-2.1 + static-link exception) |
| Why | .NET built-in ZIP; no second archiver/OOXML dependency |
| TemporarySource | none（直接采用，永不先移植 QuaZip） |
| ReplacementDesign | `System.IO.Compression`（.NET 内置） |
| ReplacementStage | 07（native closure 零 QuaZip）/ 21–22 ArcScope |
| ExitCriteria | no QuaZip in restore/build/staged/NOTICE/SBOM（负扫描） |
| Status | Decided |

### RPL-0002 — QSimpleUpdater → locked Velopack
| Field | Value |
|---|---|
| ItemId | `RPL-0002` |
| What | Replace `QSimpleUpdater` (MIT) update signal |
| Why | Desktop update path is Velopack 1.2.0 |
| TemporarySource | none |
| ReplacementDesign | 锁版 Velopack `1.2.0` adapter |
| ReplacementStage | 24（ArcChat update）/ 31 |
| ExitCriteria | no QSimpleUpdater; update via Velopack signed feed |
| Status | Decided |

### RPL-0003 — QCodeEditor → ArcScope JsonProjectEditorControl
| Field | Value |
|---|---|
| ItemId | `RPL-0003` |
| What | Replace `QCodeEditor` (MIT) Qt editing widget |
| Why | Avalonia-only; no AvaloniaEdit in dependency graph |
| TemporarySource | none |
| ReplacementDesign | `ArcScope.Desktop.ProjectEditor.JsonProjectEditorControl`（自有 Avalonia 12.1.1 控件）；TextMateSharp 只负责锁版 JSON grammar tokenization，不引入 AvaloniaEdit |
| ReplacementStage | 21–22（ArcScope project editor） |
| ExitCriteria | no AvaloniaEdit / QCodeEditor in graph; JSON editor via own control |
| Status | Decided |

### RPL-0004 — OpenSSL (Serial-Studio build path) → .NET / OS TLS
| Field | Value |
|---|---|
| ItemId | `RPL-0004` |
| What | Replace non-vendored `OpenSSL` build path |
| Why | Managed/OS TLS via SChannel / .NET Linux `libssl.so.3` OS-system entries |
| TemporarySource | none |
| ReplacementDesign | .NET 内置 TLS（Windows SChannel / macOS security framework / Linux OS libssl+libcrypto as closed system deps） |
| ReplacementStage | 12（Cloud）/ 21 / 31 |
| ExitCriteria | no vendored/app-local OpenSSL; OS TLS only in `NativeSystemDependencyRegistryV1` |
| Status | Decided |

### RPL-0005 — mdflib C++ API → owned narrow C ABI
| Field | Value |
|---|---|
| ItemId | `RPL-0005` |
| What | Replace direct mdflib C++ (MIT) access |
| Why | Never cross C++ ABI; C# 只能 `[LibraryImport]` 稳定 C ABI |
| TemporarySource | none |
| ReplacementDesign | `arcscope-mdf-abi` owned narrow C ABI（mdflib overlay `v2.3.0` 静态封入 shim-static） |
| ReplacementStage | 22（ArcScope MDF4 export）；native associate Step 07 |
| ExitCriteria | MDF4 只经 `arcscope_mdf_abi`；无跨 C++ ABI（若锁定版本另有经审计稳定 C API 必须先更新 native register，禁止临场切换） |
| Status | Decided |