# Replacement Backlog (替换台账)

> First-batch structure + entries (authority: `license-and-reuse-matrix.md` §6.4, Step 00.04). V1 does **not**
> allow temporary-port-then-replace; each row below is a pre-declared **replacement decision** — the vendored
> source is never introduced into the target in its source form — and must satisfy its `ExitCriteria` before it
> is considered closed. QuaZip/OpenSSL/KissFFT additionally require a zero build/link/distribute negative scan.

Field set: `ItemId | What | Why | TemporarySource | ReplacementDesign | ReplacementStage | ExitCriteria | Status`.

| ItemId | What | Why | TemporarySource | ReplacementDesign | ReplacementStage | ExitCriteria | Status |
|---|---|---|---|---|---|---|---|---|
| RB-0001 | QuaZip | 静态链接例外 LGPL-2.1 许可与目标不匹配；.NET 原生可用 | 不引入（无临时源） | `System.IO.Compression`（ZipArchive） | Step 21–22 | 提取/备份/压缩引用全部经 System.IO.Compression；target link map 对 QuaZip 零命中 | Planned |
| RB-0002 | QSimpleUpdater | 来源更新器许可/生命周期与 Velopack 冲突 | 不引入 | 锁版 Velopack（发布/更新/回滚） | Step 31 / eng-release | Velopack feed 更新闭环；无 QSimpleUpdater 编译/链接/分发 | Planned |
| RB-0003 | QCodeEditor | 来源编辑器行为只取 Oracle；目标自研编辑控件 | 不引入 | `ArcScope.Desktop.ProjectEditor.JsonProjectEditorControl` 自有 Avalonia `12.1.1` 控件（TextMateSharp 仅做锁版 JSON grammar tokenization，不引 AvaloniaEdit） | Step 22 | 自有 Avalonia editor 通过 ArcScope ProjectEditor 门禁；AvaloniaEdit 零命中 | Planned |
| RB-0004 | OpenSSL（来源构建路径） | 不引入 vcpkg/vendored/app-local OpenSSL；.NET 原生 TLS 优先 | 不引入 | .NET 内置 TLS（Windows SChannel / macOS 安全框架 / Linux `libssl.so.3`+`libcrypto.so.3` OS TLS） | Step 08/21 | TLS 非托管 OpenSSL 零 build/link/stage；OS TLS 登记 NativeSystemDependencyRegistryV1 | Planned |
| RB-0005 | mdflib C++ API | 无成熟、许可兼容、AOT 满足的 C# binding | 不引入（只经 owned C ABI） | owned narrow C ABI shim `arcscope_mdf_abi`（如锁定版本另有经审计稳定 C API 必须先更新 native register，禁实施时临场切换） | Step 22 | 唯有 owned narrow C ABI 直绑；ABI manifest/source parity 通过 | Planned |