# Copied-Code Manifest（移植代码清单）

> Structure defined by `license-and-reuse-matrix.md` §6.1; first entries per Step 00.04. Each row is also emitted
> as machine-readable JSON (`copied-code.json`). Fields verbatim. `ManifestId` unique and stable; entries are
> added (never removed) as steps 02+ port code. `CurrentPlanningStatus` is planning-stage (not a build claim);
> `TargetPath` for planned modules is the target project, final file path filled at implementation with an
> owning step.

## Fields

`ManifestId | SourcePath | SourceRepository | SourceCommit | OriginalLicense | FileLevelLicense | TargetProduct |
TargetProject | TargetPath | ReuseType(Copy/Rewrite 语义移植) | Purpose | TemporaryOrPermanent | ReplacementRequired |
ReplacementStage | ReplacementDesign | ValidationMethod(Oracle + owning test project) | Attribution(NOTICE 行文本) |
ReleaseRestriction | CurrentPlanningStatus | Evidence(FeatureId 列表) | Notes`

## First entries

### CCM-0001 — AionUi ipcBridge contract surface
| Field | Value |
|---|---|
| ManifestId | `CCM-0001` |
| SourcePath | `AionUi/packages/desktop/src/common/adapter/ipcBridge.ts` |
| SourceRepository | `C:\MyFile\ArcForges\AionUi` |
| SourceCommit | `29c9271a59484e4696778cb80164f705245a6186` |
| OriginalLicense | Apache-2.0 |
| FileLevelLicense | Apache-2.0 (`aionui.com` SPDX header) |
| TargetProduct | ArcChat |
| TargetProject | `ArcForges.Contracts.LocalRpc` + `ArcChat.*`（合同 → LocalRpc；行为 → Domain/Application） |
| TargetPath | `src/Contracts/LocalRpc`（实施填充） |
| ReuseType | Copy（合同语义移植）/ Rewrite（UI 不在此 Manifest） |
| Purpose | ArcChat 合同面（REST op + WS 事件 + Electron 桥三组装订为 C# 强类型）权威枚举 |
| TemporaryOrPermanent | Permanent |
| ReplacementRequired | no |
| ReplacementStage | — |
| ReplacementDesign | — |
| ValidationMethod | Oracle O1/O2；`tests/ContractCompatibilityTests` + `ArcChat.Tests.*`；Step 02/09 |
| Attribution | `NOTICE.md`: "This product includes material derived from AionUi (Apache-2.0)." |
| ReleaseRestriction | 保留 Apache-2.0 头与 NOTICE；派生文件不标做纯原创 AGPL |
| CurrentPlanningStatus | Planned（Step 02/09） |
| Evidence | `AF-F-AIONUI-0001..0180`, `AF-F-AIONUI-0197..0202` |
| Notes | 传输降级/升级（本地 Domain vs LocalRpc/PublicApi/Realtime）是 ArcChat 核心合同变换；UD-LIC-2（获授权来源逻辑允许 C#/Avalonia 移植并保留归属） |

### CCM-0002 — AionUi chatLib message model / merge rules
| Field | Value |
|---|---|
| ManifestId | `CCM-0002` |
| SourcePath | `AionUi/packages/desktop/src/common/chat/chatLib.ts` |
| SourceRepository | `C:\MyFile\ArcForges\AionUi` |
| SourceCommit | `29c9271a59484e4696778cb80164f705245a6186` |
| OriginalLicense | Apache-2.0 |
| FileLevelLicense | Apache-2.0 |
| TargetProduct | ArcChat |
| TargetProject | `ArcChat.Domain` + `ArcChat.Application` |
| TargetPath | `src/ArcChat/Domain/Conversations` + `src/ArcChat/Application/Conversations`（实施填充） |
| ReuseType | Copy（每个合并规则独立行） |
| Purpose | `TMessage` oneof、`IResponseMessage`、`IConfirmation`、`composeMessage`/`transformMessage`、各 `merge*`（text append/replace、tool_group by-call_id、tool_call·acp_tool_call by-id、plan by-session、thinking contiguous-chunk） |
| TemporaryOrPermanent | Permanent |
| ReplacementRequired | no |
| ReplacementStage | — |
| ReplacementDesign | — |
| ValidationMethod | Oracle O1；Step 09；合并规则金样（00.05 条目 1） |
| Attribution | 同上 NOTICE 行 |
| ReleaseRestriction | 保留 Apache-2.0 归属 |
| CurrentPlanningStatus | Planned（Step 09） |
| Evidence | `AF-F-AIONUI-0197..0202`（chat 合并族） |
| Notes | 每个 merge 规则一行 |

### CCM-0003 — AionUi mobile messageAdapter / grouping / JWT
| Field | Value |
|---|---|
| ManifestId | `CCM-0003` |
| SourcePath | `AionUi/mobile/src/{services/*,context/*,hooks/*}` |
| SourceRepository | `C:\MyFile\ArcForges\AionUi` |
| SourceCommit | `29c9271a59484e4696778cb80164f705245a6186` |
| OriginalLicense | Apache-2.0 |
| FileLevelLicense | Apache-2.0（`agentModes.ts:1-5` SPDX） |
| TargetProduct | ArcChat.Mobile |
| TargetProject | `ArcChat.Mobile.*`（ShShared/Android） |
| TargetPath | `src/Mobile/…`（实施填充） |
| ReuseType | Copy（移植语义）+ 补齐缺口 |
| Purpose | WS 协议层、`messageAdapter`、分组逻辑、JWT 生命周期、主题 token |
| TemporaryOrPermanent | Permanent |
| ReplacementRequired | no |
| ReplacementStage | — |
| ReplacementDesign | — |
| ValidationMethod | Oracle O1/O4；Step 18/19；mobile WS reconnect/JWT/golden（00.05 条目 3） |
| Attribution | 同上 NOTICE 行 |
| ReleaseRestriction | 保留 Apache-2.0 归属；删除硬编码发布凭据（Replace 行）；`wss://`+证书校验 |
| CurrentPlanningStatus | Planned（Step 18/19） |
| Evidence | `AF-F-AIONUI-M-*` |
| Notes | RN→MAUI UI 为 Rewrite，此处只抄语义/协议 |

### CCM-0004 — AFFiNE blocksuite data model / geometry / type system / snapshot
| Field | Value |
|---|---|
| ManifestId | `CCM-0004` |
| SourcePath | `AFFiNE/blocksuite/**` |
| SourceRepository | `C:\MyFile\ArcForges\AFFiNE` |
| SourceCommit | `81df4751a367f2795bc0d165586650dbe8db73d6` |
| OriginalLicense | MIT |
| FileLevelLicense | MIT（各 `package.json` `"license":"MIT"`） |
| TargetProduct | ArcNotes |
| TargetProject | `ArcNotes.Domain` / `ArcNotes.Edgeless` / `ArcNotes.Database` / `ArcNotes.Slides` |
| TargetPath | `src/ArcNotes/…`（实施填充） |
| ReuseType | Copy / Rewrite |
| Purpose | Block 模型/几何/类型系统/快照格式（快照只为 C# 独立重实现依据；Yjs/CRDT Drop） |
| TemporaryOrPermanent | Permanent |
| ReplacementRequired | no |
| ReplacementStage | — |
| ReplacementDesign | — |
| ValidationMethod | Oracle O2/O5；Step 10/15/16/17；`ArcNotes.Tests.*` + snapshot golden（00.05 条目 4） |
| Attribution | `NOTICE.md`: "Includes material from AFFiNE blocksuite (MIT)." |
| ReleaseRestriction | 保留 MIT 归属；不保留 CRDT 兼容字段 |
| CurrentPlanningStatus | Planned（Step 10/15/16/17） |
| Evidence | `AF-F-BLOCKSUITE-*` |
| Notes | Snapshot 仅结构 Oracle；不生成 Yjs/awareness 兼容金样 |

### CCM-0005 — Serial-Studio GPL core algorithms
| Field | Value |
|---|---|
| ManifestId | `CCM-0005` |
| SourcePath | `Serial-Studio/app/src/IO/{FrameReader,CircularBuffer,FrameBuilder,FrameConfig}` + `app/src/DataModel/FrameConsumer` |
| SourceRepository | `C:\MyFile\ArcForges\Serial-Studio` |
| SourceCommit | `639daafb2fe7d324c3b2d5583d2514c8c470676f` |
| OriginalLicense | `GPL-3.0-only OR LicenseRef-SerialStudio-Commercial`（取 GPL-3.0 分支） |
| FileLevelLicense | GPL-3.0-only |
| TargetProduct | ArcScope |
| TargetProject | `ArcScope.Infrastructure`（采集管线） |
| TargetPath | `src/ArcScope/Infrastructure/…`（实施填充） |
| ReuseType | Copy（语义移植） |
| Purpose | ring buffer/SPSC、FrameReader/FrameBuilder、JSON Frame Format、降采样 |
| TemporaryOrPermanent | Permanent |
| ReplacementRequired | no |
| ReplacementStage | — |
| ReplacementDesign | — |
| ValidationMethod | Oracle O1/O5；Step 07/21；`ArcScope.Tests.*` + golden（00.05 条目 5） |
| Attribution | `NOTICE.md`: "Derived from Serial Studio GPL core (GPL-3.0-only)." |
| ReleaseRestriction | 保留 GPL-3.0 覆盖/SPDX/版权/来源 commit；AGPL 兼容（AGPL §13） |
| CurrentPlanningStatus | Planned（Step 21–22） |
| Evidence | `AF-F-SS-CORE-*`（core 行） |
| Notes | 取 GPL 分支；Pro 模块绝不进入本 Manifest（见 Independent-Reimplementation） |

### CCM-0006 — ArcVideo / ArcVideoFoundation media runtime behavior
| Field | Value |
|---|---|
| ManifestId | `CCM-0006` |
| SourcePath | `ArcVideo/app/**` + `ArcVideoFoundation/{include/**src/**}` |
| SourceRepository | `C:\MyFile\ArcForges\ArcVideo` / `C:\MyFile\ArcForges\ArcVideoFoundation` |
| SourceCommit | `caf56513278703adec0c2933ec235bb864d72e31` / `139eecaaa79dbad743a146f174a9c89a66ed594b` |
| OriginalLicense | GPL-3.0 |
| FileLevelLicense | GPL-3.0（两 LICENSE 全文） |
| TargetProduct | ArcSlate |
| TargetProject | `ArcSlate.Domain` / `ArcSlate.Infrastructure`（媒体运行时）+ `ArcMediaNative`（ABI） |
| TargetPath | `src/ArcSlate/…` + `native/arcmedia-ffmpeg-abi`（实施填充） |
| ReuseType | Copy（产品模型/时间线/媒体运行时行为） |
| Purpose | Project/Timeline/Track/Block、compose、renderer、codec、rational/time/timecode/color 值类型 |
| TemporaryOrPermanent | Permanent |
| ReplacementRequired | no（媒体经 owned C ABI `ArcMediaNative`） |
| ReplacementStage | — |
| ReplacementDesign | — |
| ValidationMethod | Oracle O1/O5；Step 07/23–25；`ArcSlate.Tests.*` + rational/timecode golden（00.05 条目 6） |
| Attribution | `NOTICE.md`: "Includes material derived from ArcVideo/ArcVideoFoundation (GPL-3.0), an Olive-family editor." |
| ReleaseRestriction | 保留 GPL-3.0 覆盖/SPDX；AGPL 兼容 |
| CurrentPlanningStatus | Planned（Step 23–25） |
| Evidence | `AF-F-ARCV-*`, `AF-F-ARCVF-*` |
| Notes | FFmpeg 经 `ArcMediaNative` only；值类型纯 C#；C++ 仅经 owned C ABI |