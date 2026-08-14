# Source Subsystem Feature Inventory

> **Subsystem-level functional inventory across the six frozen source repositories, merged with and
> consistent with `feature-inventory-and-mapping.md`.** The detailed per-feature `AF-F-*` rows live in
> `feature-inventory-and-mapping.md` (the canonical denominator; `source-coverage-register.md` §5.1: 833 rows,
> `CrossChecked=624 / Mapped=204 / NeedsRecheck=5`); this file is the per-subsystem aggregate with the unified
> row mode. Every `FeatureId` here is a range/group pointer into that denominator — no feature is "generalized
> away". Source baselines are the frozen commits in `source-baseline.md` §1.
>
> Invariants (00.02):
> - No feature is dropped by aggregation: every `ipcBridge` export member, UI surface, blocksuite package,
>   siyuan kernel API group, Serial-Studio driver/parser/widget, ArcVideo/ArcVideoFoundation top-level module
>   and native dependency has an independent inventory row and an explicit owning step in 00–31.
> - Every row carries a single `DecisionClass` (Keep/Copy/Rewrite/Replace/Merge/Drop/Defer/ReferenceOnly) and
>   an `OracleClass` (O1–O7); no `TBD`/`待定`.
> - Restricted sources (siyuan AGPL, AFFiNE EE backend, Serial-Studio Pro) record only behavior-spec paths and
>   independent-implementation constraints; their golden samples are input/output pairs, never source excerpts.
> - Feature IDs are globally unique and stable (`AF-F-<Source>-<NNNN>`), never reused after renumbering.

**Unified row mode** applied below:
`FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject |
TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes`.

---

## 1. AionUi desktop (`AF-F-AIONUI-*`)

Base: `AionUi@29c9271a59484e4696778cb80164f705245a6186`, Apache-2.0 (`AionUi/LICENSE`; 519/733 TS/TSX carry
`SPDX-License-Identifier: Apache-2.0`). Decision body Copy/Rewrite, `AttributionRequired=yes`. Detailed rows
`AF-F-AIONUI-0001..0282` (contract/UI/process) plus `..0283..0289` (tests/build/resource closures).

| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AF-F-AIONUI-0001..0005 | AionUi@`29c9271a…` | `packages/desktop/src/common/adapter/ipcBridge.ts:140-151` | `shell` 打开外部资源/定位/探测（openFile/showItemInFolder/openExternal/checkToolInstalled/openFolderWith） | Rewrite（Electron→Avalonia 平台层） | ArcChat | `ArcChat.Desktop`/Platform + `ArcChat.Application` | 目标 Native 平台互操作 + 环境探测 Domain 服务 | 09 | O1 | `AionUi/LICENSE` | yes | 目录布局并入 Step 04 |
| AF-F-AIONUI-0006..0012 | AionUi@`29c9271a…` | `ipcBridge.ts:155-173` | `assistants` CRUD/import（AgentProfile 面） | Merge（Cloud 唯一权威 Profile） | ArcChat + Cloud | `ArcForges.Cloud.Modules.Agent` + `ArcChat.CloudClient` | `GET/POST/PUT/DELETE /api/v1/agent-profiles` | 09,12 | O1/O7 | `AionUi/LICENSE` | yes | 本地仅 draft/outbox |
| AF-F-AIONUI-0013..0043 | AionUi@`29c9271a…` | `ipcBridge.ts:180-368` | `conversation` 主合同（REST op + `message.stream`/`conversation.*`/`confirmation.*`/`approval.*` WS）+ runtime | Merge（本地转 Domain/Application；Remote 升 Cloud Chat/Agent） | ArcChat + Cloud | `ArcChat.Application` + `ArcForges.Cloud.Modules.Chat/Agent` | Conversation/Message/Task 合同 + `clientMessageId` 幂等 | 09,12,13 | O1/O6/O7 | `AionUi/LICENSE` | yes | ACP/team/assistant override Drop；runtime 状态机并入 Task Lifecycle |
| AF-F-AIONUI-0044 | AionUi@`29c9271a…` | `ipcBridge.ts:371` | `runtime.statusChanged`（Node/ACP/custom runtime 状态） | Merge | ArcChat | `ArcChat.Application` | 只归一为按需 MCP tool/package 安装连接校验状态 | 14,27 | O1 | `AionUi/LICENSE` | yes | Node/ACP/custom-agent runtime 与下载器 Drop |
| AF-F-AIONUI-0045..0056 | AionUi@`29c9271a…` | `ipcBridge.ts:465-504` | `application.*` Electron 原生面（restart/devtools/systemInfo/getPath/gpu/zoom/log/startOnBoot） | Rewrite（Avalonia）+ Drop（DevTools/CDP） | ArcChat | `ArcChat.Desktop`/Platform + `ArcForges.Observability` | 原生平台互操作 + 结构化日志 | 06,09,24 | O1/O6 | `AionUi/LICENSE` | yes | Chromium DevTools/CDP 专用项 Drop |
| AF-F-AIONUI-0057..0063 | AionUi@`29c9271a…` | `ipcBridge.ts:510-560` | `update`/`autoUpdate`（electron-updater → Velopack） | Replace | ArcChat | `ArcChat.Desktop`/Platform | 锁版 Velopack 安装/签名/回滚门禁 | 24,31 | O1/O6 | `AionUi/LICENSE` | yes | electron-updater→Velopack |
| AF-F-AIONUI-0064 | AionUi@`29c9271a…` | `ipcBridge.ts:563-572` | `dialog.showOpen` 原生文件选择 | Rewrite | ArcChat | `ArcChat.Desktop` | Avalonia `StorageProvider` | 06,09 | O1 | `AionUi/LICENSE` | yes | |
| AF-F-AIONUI-0065..0087 | AionUi@`29c9271a…` | `ipcBridge.ts:575-720` | `fs.*`/Skills（目录/读写真临/打包/metadata/技能 CRUD·导入·市场） | Copy（移植语义） | ArcChat | `ArcChat.Application`/Infra | 本机 FS/Workspace/Skills 服务；Cloud Skill tombstone | 09,27 | O1/O6/O7 | `AionUi/LICENSE` | yes | 技能市场→签名 Arc Package/Connector 目录 |
| AF-F-AIONUI-0088..0092 | AionUi@`29c9271a…` | `ipcBridge.ts:722-780` | `fileWatch`/`workspaceOfficeWatch`/`fileStream` | Rewrite/Copy | ArcChat | `ArcChat.Infrastructure` + `ArcChat.Application` | FileSystemWatcher 封装 + WS 事件投影 | 09 | O1/O6 | `AionUi/LICENSE` | yes | |
| AF-F-AIONUI-0093..0099 | AionUi@`29c9271a…` | `ipcBridge.ts:782-850` | `fileSnapshot`（快照/比较/暂存/分支，git-like） | Copy | ArcChat | `ArcChat.Application`/Infra | snapshot/stage/discard 语义 | 09 | O1 | `AionUi/LICENSE` | yes | |
| AF-F-AIONUI-0100..0102 | AionUi@`29c9271a…` | `ipcBridge.ts:855-880` | `googleAuth`/`google`/`bedrock` provider 专连 | Drop/Copy | ArcChat | `ArcChat.Infrastructure` | Provider 客户端/连通测试 | 09 | O1 | `AionUi/LICENSE` | yes | googleAuth stub Drop |
| AF-F-AIONUI-0103..0107 | AionUi@`29c9271a…` | `ipcBridge.ts:884-940` | `mode.*` Provider 管理 + fetchModels/detectProtocol | Copy | ArcChat | `ArcChat.Application`/Infra | Provider CRUD（Secret 仅 SecretRef）、模型探测 | 09 | O1/O7 | `AionUi/LICENSE` | yes | |
| AF-F-AIONUI-0108..0112 | AionUi@`29c9271a…` | `ipcBridge.ts:944-1010` | `acpConversation`/managed agent（ACP 别名；本地 Agent） | Merge/Drop | ArcChat + Cloud | `ArcForges.Cloud.AgentRuntime` | 只留 canonical Chat/Task；ACP route/type Drop | 09,13,00 | O7 | `AionUi/LICENSE` | yes | 本机 Agent/CLI/ACP 全部 Drop；单 Agent |
| AF-F-AIONUI-0113..0119 | AionUi@`29c9271a…` | `ipcBridge.ts:1014-1090` | `mcpService.*`（MCP 服务器 CRUD/import/toggle/test/OAuth） | Copy | ArcChat | `ArcChat.Application`/Infra | MCP 服务器管理 + OAuth 生命周期 | 09,14,27 | O1/O2/O6 | `AionUi/LICENSE` | yes | 旧式独立 HTTP+SSE 拒绝 |
| AF-F-AIONUI-0120..0121 | AionUi@`29c9271a…` | `ipcBridge.ts:1094-1130` | `openclawConversation`（来源网关后端） | Merge/Drop | ArcChat | `ArcChat.Application` | 只保留消息/stream UX | 09,13,00 | O7 | `AionUi/LICENSE` | yes | OpenClaw runtime 不保留 |
| AF-F-AIONUI-0122..0125 | AionUi@`29c9271a…` | `ipcBridge.ts:1135-1200` | `remoteAgent`（来源远程 Agent → Device + ToolRequest） | Merge/Rewrite/Drop | ArcChat + Cloud | `ArcForges.Cloud.Modules.Identity/Agent` + ArcChat client | Device trust/presence/tool catalog；正式 ToolRequest | 12,14,00 | O1/O7 | `AionUi/LICENSE` | yes | 不创建 RemoteAgent 实体；`allow_insecure`/任意 URL Drop |
| AF-F-AIONUI-0126..0129 | AionUi@`29c9271a…` | `ipcBridge.ts:1205-1250` | `database.*`（会话/消息/搜索游标分页） | Copy | ArcChat | `ArcChat.Application`/Infra | 双向游标分页 + 锚点；消息 FTS | 09,11 | O2 | `AionUi/LICENSE` | yes | 本地查询 |
| AF-F-AIONUI-0130..0135 | AionUi@`29c9271a…` | `ipcBridge.ts:1254-1330` + `process/services/office*` | `previewHistory`/`preview`/`document`/Office 预览（word/excel/ppt） | Rewrite（NativePreview） | ArcChat | `ArcChat.Application.NativePreview` + `ArcForges.Desktop.Preview/RichContent/Text` + `ArcForges.ContentSandbox` | closed `NativePreviewDescriptorV1` + `FlowDocumentV1/WorkbookViewV1/SlideDeckViewV1` + `PreviewFidelityReport` | 09 | O1 | `AionUi/LICENSE` | yes | DOCX/XLSX/PPTX=`DocumentFormat.OpenXml 3.5.1`；ContentSandbox 只解析；无 Office/Node 子进程 |
| AF-F-AIONUI-0136..0143 | AionUi@`29c9271a…` | `ipcBridge.ts:1334-1390` | `deepLink`/`windowControls`/`theme`/`notification`（Electron 原生面） | Rewrite | ArcChat | `ArcChat.Desktop`/Platform + Design System | `arcforges://` 深链、原生窗口/主题/通知（五 Surface） | 06 | O1/O6 | `AionUi/LICENSE` | yes | |
| AF-F-AIONUI-0144..0154 | AionUi@`29c9271a…` | `ipcBridge.ts:1394-1500` | `systemSettings.*`（tray/notification/language/keepAwake/gpu/pet）+ `ensureNodeRuntime`/`ensureManagedAcpTool` | Copy/Rewrite/Drop | ArcChat | `ArcChat.Application`/Desktop + `ArcForges.Desktop.Experience` | Settings 六 Scope；`arcchat.pet.*` 四个 DeviceLocal 键 | 06,09,30 | O1/O6 | `AionUi/LICENSE` | yes | Node/ACP runtime 安装器 Drop；负扫 node/npm/bun |
| AF-F-AIONUI-0155 | AionUi@`29c9271a…` | `ipcBridge.ts:1504` | `task.*`（stub：stopAll/getRunningCount） | Merge | ArcChat + Cloud | Cloud Agent + ArcChat client | 统一 Task/Run 模型取代 stub | 09 | O1 | `AionUi/LICENSE` | yes | 来源即 stub |
| AF-F-AIONUI-0156..0161 | AionUi@`29c9271a…` | `ipcBridge.ts:1510-1580` | `webui.*`（本机 LAN Web 服务器 + QR） | Drop/Merge | ArcChat + Cloud + Web | `ArcForges.Web.Infrastructure` + Identity/Device | standalone WASM + Cloud pairing；无本机 LAN WebUI | 09,12,29,00 | O6/O7 | `AionUi/LICENSE` | yes | 本机 Web server 全 Drop |
| AF-F-AIONUI-0162..0166 | AionUi@`29c9271a…` | `ipcBridge.ts:1584-1660` | `cron.*`（定时任务） | Merge | ArcChat + Cloud | `ArcForges.Cloud.Modules.Agent` + ArcChat client | Automation（`/api/v1/automations`）取代本地 cron | 09,12,13 | O1/O7 | `AionUi/LICENSE` | yes | Cloud durable scheduler 权威 |
| AF-F-AIONUI-0167..0176 | AionUi@`29c9271a…` | `ipcBridge.ts:1664-1740` | `extensions.*`（主题/扩展/权限/风险/i18n/启停） | Merge/Rewrite/Drop | ArcForges | `ArcForges.Extensions.*` | 声明式 contribution/Arc Package trust；禁 CSS/脚本注入 | 27 | O1/O6/O7 | `AionUi/LICENSE` | yes | 第三方代码/UI host Drop |
| AF-F-AIONUI-0177..0180 | AionUi@`29c9271a…` | `ipcBridge.ts:1744-1810` | `channel.*`（Bot 平台通道） | Merge | ArcChat | ArcChat client + Integrations | Connector package（Telegram/Lark/…）非本地 Agent | 09,27 | O1/O7 | `AionUi/LICENSE` | yes | 不扩展私有 SignalR 方法名 |
| AF-F-AIONUI-0181..0196 | AionUi@`29c9271a…` | `ipcBridge.ts:1814-1900` | `hub.*`（扩展市场） | Merge | ArcChat + Cloud | Cloud Catalog + ArcChat client | 签名 Arc Package Catalog | 27 | O1/O7 | `AionUi/LICENSE` | yes | |
| AF-F-AIONUI-0197..0282 | AionUi@`29c9271a…` | `common/chat/chatLib.ts`（1015 行）、`common/config/storage.ts`、`renderer/pages/*`、`renderer/components/*`、`process/{bridge,services,pet,resources}/*` | 消息模型/流式合并规则（TMessage oneof、`composeMessage`、`transformMessage`、各 `merge*`）；SQLite 13 表 schema；UI surface；process 桥接/服务；i18n 13 语言 | Copy（消息 accumulate）→ `ArcChat.Domain`/`ArcChat.Application` `AF-F-AIONUI-0197..0202`；Rewrite（UI）→ Avalonia `../../UI`；Copy（DB，O2）→ 13 表；Copy（i18n，O6/Copied-Asset） | ArcChat | `ArcChat.Domain`/`ArcChat.Application`/`ArcChat.LocalRpc`/`ArcChat.Desktop`/`ArcChat.LocalHub`/`ArcChat.LocalTools`/`ArcChat.McpClient`/`ArcChat.CloudClient` | TMessage 每 oneof 变体、`IResponseMessage`、`IConfirmation`、`composeMessage`/`transformMessage`、`merge*`（text append vs replace / tool_group by-call_id / tool_call·acp_tool_call by-id / plan by-session / thinking contiguous-chunk）；13 表；每 renderer page/component + process bridge/service 一行 | 09（各 UI）+ 04/09（表） | O1/O2/O6 | `AionUi/LICENSE` | yes | 每个合并规则独立行；UI 一律 React→Avalonia Rewrite；i18n 键名不变 Copied-Asset |
| AF-F-AIONUI-0283..0289 | AionUi@`29c9271a…` | `tests/**`,`examples/**`, root config, `.github/**`,`scripts/**`, homebrew, docs, web-host/cli | 测试/fixture/构建/发布/资源/Web host 边界 | ReferenceOnly/Rewrite/Replace/Drop | 共享 | `tests/*`, `eng/release`, Step29 Web | provenance/oracle fixtures；Node/aioncore/localhost launcher Drop | 00,30,31 | O1/O2/O5/O6/O7 | `AionUi/LICENSE` | yes | `AF-F-AIONUI-0283`/`0285` NeedsRecheck（dirty test/build files） |

---

## 2. AionUi mobile (`AF-F-AIONUI-M-*`)

Base `AionUi@29c9271a…`, Apache-2.0, `mobile/src/constants/agentModes.ts:1-5` carries SPDX header. Detailed rows
`AF-F-AIONUI-M-*` (Source coverage SC-AION-02). Copy + 补齐缺口；RN→MAUI 重写 UI。

| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AF-F-AIONUI-M-xxxx | AionUi@`29c9271a…` | `mobile/src/services/*`,`context/*`,`hooks/*`,`components/*`,`i18n/*`,`constants/*`（76 文件） | WS 协议层/`messageAdapter`/分组逻辑/JWT 生命周期/远程控制面/主题 token/i18n | Copy（移植语义）+ Rewrite（RN→MAUI） | ArcChat.Mobile | `ArcChat.Mobile.{Domain,Application,Contracts,CloudClient,Realtime,Persistence,Presentation}` | 共享 MAUI 架构；Refit + 可选 SignalR + 本地缓存 | 18,19 | O1 | `mobile/src/constants/agentModes.ts:1-5` + `AionUi/LICENSE` | yes | 不复制 RN runtime；iOS 只留架构；删除硬编码发布凭据（Replace 行）；`wss://`+证书校验（安全行） |
| AF-F-AIONUI-M-gap-push | —（来源无、目标必补） | （缺口） | push 通知 | Copy+补齐 | ArcChat.Mobile | `ArcChat.Mobile/Platforms/Android` + Identity/Operations | FCM/APNs token 绑定/轮换/解绑/失效；push 只唤醒 | 12,19,20 | O4 | — | — | 登记 Replacement/Independent 缺口 |
| AF-F-AIONUI-M-gap-deeplink | — | （缺口） | 深链（HTTPS canonical App Link） | Copy+补齐 | ArcChat.Mobile | `ArcChat.Mobile/Platforms/*` | verified App Link | 19,20 | O4 | — | — | |
| AF-F-AIONUI-M-gap-offline | — | （缺口） | 离线缓存 | Copy+补齐 | ArcChat.Mobile | `ArcChat.Mobile.Application` | bounded cache/outbox/recovery | 18 | O4 | — | — | |
| AF-F-AIONUI-M-gap-pagination | — | （缺口） | 分页 | Copy+补齐 | ArcChat.Mobile | `ArcChat.Mobile.Application` | cursor pagination | 18,19 | O4 | — | — | |
| AF-F-AIONUI-M-gap-upload | — | （缺口） | 上传 | Copy+补齐 | ArcChat.Mobile | `ArcChat.Mobile.CloudClient` | `IResourceApi` transfer | 18,19 | O4 | — | — | |
| AF-F-AIONUI-M-gap-bg-recovery | — | （缺口） | 后台恢复 | Copy+补齐 | ArcChat.Mobile | `ArcChat.Mobile.Application`/`Persistence` | process death/weak network/后台恢复 | 19 | O4 | — | — | |
| AF-F-AIONUI-M-gap-weaknet | — | （缺口） | 弱网重试 | Copy+补齐 | ArcChat.Mobile | `ArcChat.Mobile.CloudClient`/`Realtime` | Retry-After/退避 | 18,19 | O4 | — | — | |
| AF-F-AIONUI-M-credentials | AionUi@`29c9271a…` | 删除硬编码个人发布凭据（Apple ID/team） | 清除凭据 | Replace | ArcChat.Mobile | `eng/` release | 无硬编码发布凭据 | 19 | O1 | `AionUi/LICENSE` | yes | 审计零命 |
| AF-F-AIONUI-M-sec | AionUi@`29c9271a…` | `wss://` + 证书校验 | 安全要求行 | Copy | ArcChat.Mobile | `ArcChat.Mobile.CloudClient` | wss + cert pinning 约定 | 18 | O1 | `AionUi/LICENSE` | yes | 禁 LAN 直连/专业 App |

---

## 3. AFFiNE blocksuite (`AF-F-BLOCKSUITE-*`)

Base `AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6`, MIT. Copy/Rewrite, `AttributionRequired=yes` (MIT).
Yjs/awareness/CRDT/state-vector rows are registered **Drop**.

| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AF-F-BLOCKSUITE-xxxx | AFFiNE@`81df4751…` | `blocksuite/framework-core/**` | framework-core | Copy/Rewrite | ArcNotes | `ArcNotes.Domain`/`ArcNotes.Editor` | C# core model | 10 | O2/O5 | `blocksuite` 各 `package.json` `"license":"MIT"` | yes | 只作 C# 独立重实现依据；Yjs Drop |
| AF-F-BLOCKSUITE-xxxx | AFFiNE@`81df4751…` | `blocksuite/framework-store/**` | store（文档存储核） | Copy/Rewrite | ArcNotes | `ArcNotes.Domain`/`ArcNotes.Application` | 文档/Block 模型 | 10 | O2/O5 | MIT | yes | Yjs/CRDT Drop |
| AF-F-BLOCKSUITE-xxxx | AFFiNE@`81df4751…` | `blocksuite/framework/std/**` | std（编辑标准件） | Copy/Rewrite | ArcNotes | `ArcNotes.Editor`/`ArcNotes.Application` | 编辑命令/选择 | 10 | O2 | MIT | yes | |
| AF-F-BLOCKSUITE-xxxx | AFFiNE@`81df4751…` | `blocksuite/blocks/**`,`affine/model` | Block 类型（schema/block-std/flavour） | Copy/Rewrite | ArcNotes | `ArcNotes.Domain`/`ArcNotes.Editor` | 静态注册 Block schema | 10 | O2/O5 | MIT | yes | ≥25 flavours |
| AF-F-BLOCKSUITE-xxxx | AFFiNE@`81df4751…` | `blocksuite/affine/gfx/*`+`surface*`+`edgeless-*` | Edgeless 画布几何/连接/分组 | Copy/Rewrite | ArcNotes | `ArcNotes.Edgeless` | 几何/连接/分组/缩放 | 15 | O2/O5 | MIT | yes | 共享 Block 内容 |
| AF-F-BLOCKSUITE-xxxx | AFFiNE@`81df4751…` | `blocksuite/affine/data-view/*`,`database` | 多视图 Database | Copy/Rewrite | ArcNotes | `ArcNotes.Database` | Typed Property/View | 16 | O2 | MIT | yes | |
| AF-F-BLOCKSUITE-xxxx | AFFiNE@`81df4751…` | `blocksuite/affine/blocks/frame`,`frame-panel` | Slides/Frame 演示 | Copy/Rewrite | ArcNotes | `ArcNotes.Slides` | Frame/演示 | 17 | O2 | MIT | yes | |
| AF-F-BLOCKSUITE-xxxx | AFFiNE@`81df4751…` | `blocksuite/affine/…/adapter` | snapshot/block 几何/连接/分组/Typed Property/视图/presentation 行为 | Copy/Rewrite | ArcNotes | `ArcNotes.Domain`/`ArcNotes.{Edgeless,Database,Slides}` | snapshot 格式/类型系统 | 10,15,16,17 | O2/O5 | MIT | yes | 纯 C# 独立重实现依据 |
| AF-F-BLOCKSUITE-xxxx | AFFiNE@`81df4751…` | blocksuite `yjs`,`awareness`,`CRDT`,`state-vector` | 协作/CRDT | **Drop** | — | — | 不进入目标 schema/wire/golden/开放项 | — | — | MIT | no | 明确 Drop，无兼容字段 |

---

## 4. AFFiNE platform/backend (`AF-F-AFFINE-BE-*`)

Base `AFFiNE@81df4751…`, `packages/backend/**` + `packages/common/native/**` are **ReferenceOnly** (EE, UD-LIC-4).
Pattern rows only: `BehaviorSpecPaths` + `TargetProject=ArcForges.Cloud.Modules.*` + OwningStep 12/26 + Oracle O3 +
明示"不复制 EE 代码，C# 独立实现".

| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior (pattern) | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AF-F-AFFINE-BE-xxxx | AFFiNE@`81df4751…` | `packages/backend/server/schema.prisma` | Prisma 57 表（snapshots/updates/histories 双层、users/workspaces/devices/sessions/permissions/blobs/features/entitlements 等） | ReferenceOnly | Cloud | `ArcForges.Cloud.Modules.*` | 结构参照，不复制 DDL | 12,26 | O3 | `packages/backend/server/LICENSE` (EE) | n/a | UD-LIC-4 |
| AF-F-AFFINE-BE-xxxx | AFFiNE@`81df4751…` | `server/src/core/{doc,sync}/*` | clock-based sync | ReferenceOnly | Cloud | `ArcForges.Cloud.Modules.Sync` | 独立 C# 实现 | 12,26 | O3 | EE | n/a | C# 独立，无 CRDT |
| AF-F-AFFINE-BE-xxxx | AFFiNE@`81df4751…` | `server/src/core/auth/permission/*` | permission evaluator | ReferenceOnly | Cloud | `ArcForges.Cloud.Modules.Identity` | 独立 C# | 12,26 | O3 | EE | n/a | |
| AF-F-AFFINE-BE-xxxx | AFFiNE@`81df4751…` | `server/src/core/blob/*` | blob 两阶段 GC | ReferenceOnly | Cloud | `ArcForges.Cloud.Modules.Resource` | 独立 C# | 12,26 | O3 | EE | n/a | |
| AF-F-AFFINE-BE-xxxx | AFFiNE@`81df4751…` | `server/src/…entitlement*` | entitlement→quota 投影 | ReferenceOnly | Cloud | `ArcForges.Cloud.Modules.Entitlement` | 独立 C# | 12,26 | O3 | EE | n/a | |
| AF-F-AFFINE-BE-xxxx | AFFiNE@`81df4751…` | `server/src/core/auth/*` | Passkey/OTP auth | ReferenceOnly | Cloud | `ArcForges.Cloud.Modules.Identity` | 独立 C# | 12,26 | O3 | EE | n/a | |
| AF-F-AFFINE-BE-xxxx | AFFiNE@`81df4751…` | `server/src/core/realtime/*` | socket.io 同步模式 | ReferenceOnly | Cloud | `ArcForges.Cloud.Realtime` | SignalR JSON 独立 | 12,26 | O3 | EE | n/a | socket.io → SignalR |

---

## 5. siyuan (AGPL, ReferenceOnly 行为规格 → 独立 C#) (`AF-F-SIYUAN-*`)

Base `siyuan@eef10568384e2e7cf547adb029ae46a72e43c287`, AGPL-3.0 (`siyuan/LICENSE`). **UD-LIC-3**：只取行为规格，
金样只取输入/输出对，**绝不复制源码**。每行 Notes 标"独立实现，不复制源码，金样只取输入/输出对"。

| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AF-F-SIYUAN-0001..0026 | siyuan@`eef10568…` | `kernel/**`（Go API/model/sql/filesys services） | block CRUD / 引用·反链 / FTS 搜索 / 导入导出（.sy/.md）/ history / conf / sync / asset / template / snippet | ReferenceOnly | ArcNotes | `ArcNotes.Domain`/`ArcNotes.Application`/`ArcNotes.Search`/`ArcNotes.ImportExport` | 行为规格 → 独立 C# 实现 | 10–15 | O3 | `siyuan/LICENSE` (AGPL) | n/a | 独立实现，不复制源码；AV/search/ref/history/import/export/assets/sync/template/plugin/flashcard/publish/crypto 各组独立行 |
| AF-F-SIYUAN-0027..0062 | siyuan@`eef10568…` | `app/src/**`（editor/shell/AV/search/settings/import/export UI） | 文档树 / 大纲 / 块菜单 / 闪卡 / 关系图 / 数据库属性视图 | ReferenceOnly | ArcNotes | `ArcNotes.Editor`/`ArcNotes.Edgeless`/`ArcNotes.Search` + Avalonia UI | 行为规格 → 独立 UI | 10–15 | O3 | `siyuan/LICENSE` | n/a | 不得逐行翻译 |
| AF-F-SIYUAN-0063..0067 | siyuan@`eef10568…` | `app/electron/**`,`app/appx/**`,`app/nsis/**`,`app/scripts/**`, root scripts/Docker/CI | build/release/platform 与 Electron 窗口/localhost kernel shell | ReferenceOnly | 共享（eng/release） | `eng/release`, Step31 + Avalonia lifecycle | 目标 .NET publish/sign/update | 00,30,31 | O3 | AGPL | n/a | Electron/Chromium/HTML/JS/loopback UI 不进入 Desktop |
| AF-F-SIYUAN-0068..0075 | siyuan@`eef10568…` | `app/appearance/**`,`app/guide/**`,`app/stage/**`,`screenshots/**` | 外观/本地化/引导/发布静态资源与 stage 浏览器渲染家族 | ReferenceOnly/Replace/Drop | ArcNotes | ArcNotes 原生 Avalonia/Skia renderer + ImportExport | 逐家族映射原生 typed renderer/fallback | 00,10-15,30 | O3 | AGPL + 逐资产 | n/a | 所有 stage JS/WebView runtime 显式 Drop |

---

## 6. Serial-Studio (`AF-F-SS-CORE-*` / `AF-F-SS-PRO-*` / `AF-F-SS-LIB-*`)

Base `Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f`. GPL core (`GPL-3.0-only OR LicenseRef-SerialStudio-Commercial`,
取 GPL 分支, AGPL 兼容) → Copy；Pro（182 商业文件，`BUILD_COMMERCIAL` 门控）→ **Replace**（独立 C#，公开协议，Oracle O4）。
Pro 边界以 `CMakeLists.txt` `BUILD_COMMERCIAL` 为准。

| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AF-F-SS-CORE-xxxx | Serial-Studio@`639daafb…` | `app/src/IO/Drivers/*`（UART/Network TCP·UDP/BLE） | 串口/网络/BLE 驱动 | Copy（GPL 分支） | ArcScope | `ArcScope.Infrastructure`（Source Adapter） | `DataSource/Device` | 21 | O1/O5 | SPI(Dual) + GPL 分支 | yes（AGPL 兼容） | UD-LIC-2 合法 |
| AF-F-SS-CORE-xxxx | Serial-Studio@`639daafb…` | `app/src/IO/{FrameReader,CircularBuffer,FrameConfig}` + `DataModel/FrameConsumer` | FrameReader/FrameBuilder、环形缓冲/SPSC、JSON Frame Format、降采样 | Copy | ArcScope | `ArcScope.Infrastructure`（采集管线） | ring buffer/SPSC/帧解析/降采样 | 07,21 | O1/O5 | GPL 分支 | yes | 首批金样 |
| AF-F-SS-CORE-xxxx | Serial-Studio@`639daafb…` | `app/src/DataModel/*` | DataModel（Dataset/Group/Action） | Copy（行为） | ArcScope | `ArcScope.Domain` | Channel/Signal/Event | 21 | O1/O5 | GPL 分支 | yes | |
| AF-F-SS-CORE-xxxx | Serial-Studio@`639daafb…` | `app/src/UI/Widgets/{Plot,Gauge,FFT,Bar}*` | Plot/Gauge/FFT/Bar 核心 widget | Copy + Rewrite（Qt→Avalonia） | ArcScope | `ArcScope.Desktop`（Rendering） | 可视化模型/降采样显示 | 22 | O1/O5 | GPL 分支 | yes | |
| AF-F-SS-PRO-xxxx | Serial-Studio@`639daafb…` | `app/src/IO/Drivers/{MQTT,Modbus,CAN,HID,USB,Audio,Process}*` | MQTT/Modbus/CAN/HID/USB/Audio/Process 驱动（Pro，基于公开协议） | **Replace**（独立 C#） | ArcScope | `ArcScope.Infrastructure`（独立实现） | 公开协议 conformance | 21 | **O4** | Commercial-only | n/a | UD-LIC-5；反克隆条款 |
| AF-F-SS-PRO-xxxx | Serial-Studio@`639daafb…` | `app/src/Sessions/*` | Sessions 数据库 | **Replace** | ArcScope | `ArcScope.Infrastructure`/`Domain` | Session/Capture | 21 | **O4** | Commercial-only | n/a | |
| AF-F-SS-PRO-xxxx | Serial-Studio@`639daafb…` | `app/src/UI/Widgets/{XY,Plot3D,Waterfall,ImageView,Output}*` | XY/3D/Waterfall/ImageView/Output | **Replace** | ArcScope | `ArcScope.Desktop`（独立实现） | 可视化行为对等 | 22 | **O4** | Commercial-only | n/a | 品牌重绘 |
| AF-F-SS-PRO-xxxx | Serial-Studio@`639daafb…` | `app/src/MDF4/*` | MDF4 Export | **Replace** | ArcScope | `ArcScope.Application`/`Infrastructure` + `arcscope-mdf-abi` | MDF4 C ABI 导出 | 22 | **O4** | Commercial-only | n/a | |
| AF-F-SS-PRO-xxxx | Serial-Studio@`639daafb…` | `app/src/Import/*`(DBC/ModbusMap) | DBC/ModbusMap 导入 | **Replace** | ArcScope | `ArcScope.Infrastructure` | 公开格式解析 | 21 | **O4** | Commercial-only | n/a | |
| AF-F-SS-PRO-xxxx | Serial-Studio@`639daafb…` | `app/src/{AI,Licensing}/**` | AI / Licensing | **Replace** | ArcScope | `ArcScope.Application`/Entitlement | 独立实现 | 21,22 | **O4** | Commercial-only | n/a | 不复制激活体系 |
| AF-F-SS-LIB-xxxx | Serial-Studio@`639daafb…` | `lib/**`（hidapi/KissFFT/mdflib/QCodeEditor/QSimpleUpdater/QuaZip/lua/OpenSSL/readerwriterqueue/fast_float/miniaudio/tweetnacl/ed25519_verify/SimpleCrypt） | vendored 依赖逐库 | Copy/ReferenceOnly/Replace/Drop 逐库（见 `license-and-reuse-matrix.md` §3） | ArcScope/native | `ArcScope.Infrastructure`/`ArcForges.NativeInterop` | hidapi ReferenceOnly；miniaudio→锁版 0.11.25 编入 ArcMediaNative；QuaZip→System.IO.Compression；KissFFT→MathNet；OpenSSL→.NET TLS | 07,21,22 | O4/O5 | 逐库 upstream license | 逐库 | 不构建不分发 hidapi/KissFFT/OpenSSL/QuaZip；miniaudio 仅 ArcMediaNative |

---

## 7. ArcVideo (`AF-F-ARCV-*`)

Base `ArcVideo@caf56513278703adec0c2933ec235bb864d72e31`, GPL-3.0 (`ArcVideo/LICENSE`), AGPL 兼容。Copy（Olive 系行为参考，
C# 全面重写）。每个顶层模块独立行。

| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AF-F-ARCV-0001..0066 | ArcVideo@`caf56513…` | `app/{project,node,param,keyframe,timeline}/**` + `app/node.h,project.h` | Project/Sequence/Track/Block(Clip/Gap/Transition/Subtitle)/Footage/节点 | Copy | ArcSlate | `ArcSlate.Domain`/`ArcSlate.Timeline` | Project/Timeline/Track/Block 建模 | 23 | O1/O5 | `ArcVideo/LICENSE` (GPL-3.0) | yes | 49 个 `NodeFactory::InternalID` 封闭 registry；Olive 系参考 |
| AF-F-ARCV-xxxx | ArcVideo@`caf56513…` | `app/codec/*` | 解码/编码（FFmpeg/OIIO 行为 Oracle） | Copy | ArcSlate | `ArcSlate.Infrastructure.Media` + `ArcMediaNative` | SoftwareFrameLease/HardwareFrameLease | 07,24,25 | O1/O5 | GPL-3.0 | yes | 来源仅软件 decode+CPU 上传 = L4 baseline |
| AF-F-ARCV-xxxx | ArcVideo@`caf56513…` | `app/render/*` | Render/Cache/Disk | Copy | ArcSlate | `ArcSlate.Rendering`/`ArcSlate.Infrastructure.Rendering.PlatformGpu` | render/cache/proxy；Vulkan/Metal | 07,24,25 | O1/O5 | GPL-3.0 | yes | |
| AF-F-ARCV-xxxx | ArcVideo@`caf56513…` | `app/audio/*` + `app/render/preview*` | 播放/音视频同步（PortAudio 行为 Oracle；目标 miniaudio 设备层） | Copy | ArcSlate | `ArcSlate.Infrastructure.Audio` + 共享 `ArcMediaNative` | 单 device owner（WASAPI/CoreAudio/ALSA） | 24,25 | O1/O5 | GPL-3.0 | yes | PortAudio 目标零依赖 |
| AF-F-ARCV-xxxx | ArcVideo@`caf56513…` | `app/render/colorprocessor*`,`ocioconf/*`,`node/color/*` | 色彩管理/OpenColorIO | Copy | ArcSlate | `ArcSlate.Native`/`Infrastructure.Color` | OCIO config/transform | 24,25 | O1/O5 | GPL-3.0 | yes | via `arcslate-color-abi` |
| AF-F-ARCV-xxxx | ArcVideo@`caf56513…` | `app/shaders/*.frag/*.vert`（35 着色器） | Shaders | Copy（许可时） | ArcSlate | `ArcSlate.Rendering` + native shader-build | SPIR-V/Metal | 07,24,25 | O5 | 逐 asset | yes | |
| AF-F-ARCV-xxxx | ArcVideo@`caf56513…` | `app/node/project.cpp`(序列化)+`serializeddata` | Serializer 版本链/项目格式 | Copy | ArcSlate | `ArcSlate.Domain`/`ImportExport` | 项目格式/版本链 | 23,25 | O1/O5 | GPL-3.0 | yes | |
| AF-F-ARCV-xxxx | ArcVideo@`caf56513…` | `app/task/*`,`crashhandler/*`,`undo/*` | 任务/恢复/Undo | Copy | ArcSlate | `ArcSlate.Domain`/`Infrastructure.Persistence` | undo/复合命令/recovery | 23 | O1 | GPL-3.0 | yes | |
| AF-F-ARCV-xxxx | ArcVideo@`caf56513…` | `app/{panel,widget,window,dialog,tool,ui}/*` | UI 面板/工具/窗口 | Rewrite（Qt→Avalonia） | ArcSlate | `ArcSlate.Presentation`/`ArcSlate.Desktop` | Avalonia 面板 | 23,25 | O1/O6 | GPL-3.0 | yes | 品牌图形重绘 |
| AF-F-ARCV-xxxx | ArcVideo@`caf56513…` | `tests/**` | 行为 Oracle | ReferenceOnly/Rewrite | ArcSlate | `ArcSlate.Tests.*`/root native tests | 不伪称已执行 | 07,23-25 | O1/O5 | GPL-3.0 | yes | |
| AF-F-ARCV-0067..0072 | ArcVideo@`caf56513…` | `app/ui/**`,`app/shaders/**`,`app/packaging/**`,`cmake/**`,`docker/**`, root config | UI style/cursor/shader/brand + build/package/release/docs | Copy/Replace | ArcSlate | `ArcSlate.Desktop`/eng | 品牌图形重绘；CMake 权威 | 23,25,30,31 | O5/O1 | GPL-3.0 + 逐资产 | yes | `AF-F-ARCV-0065`/`0069` NeedsRecheck（dirty otioutils.h/CMakeLists） |

---

## 8. ArcVideoFoundation (`AF-F-ARCVF-*`)

Base `ArcVideoFoundation@139eecaaa79dbad743a146f174a9c89a66ed594b`, GPL-3.0 (`ArcVideoFoundation/LICENSE`)，AGPL 兼容。
值类型纯 C#；稳定 C 库直绑；C++ 仅经 owned C ABI。

| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AF-F-ARCVF-0001..0010 | ArcVideoFoundation@`139eecaa…` | `include/**`+`src/**`（rational/time range/timecode/color/bezier/sample buffer/SIMD/log/string） | `rational`/`TimeRange`/`Timecode`/Color/Bezier/SampleBuffer(SIMD) | Copy（值类型纯 C#；稳定 C API 直绑；owned C ABI） | ArcSlate | `ArcSlate.Domain`（值类型）+ `ArcSlate.Native`（ABI） | AVRational/time/timecode/color/sample buffer | 07,23,24 | O5 | `ArcVideoFoundation/LICENSE` (GPL-3.0) | yes | 逐类型 PureCSharp/StableCAPI/OwnedCABI 决策；不复用二进制 |
| AF-F-ARCVF-0011 | ArcVideoFoundation@`139eecaa…` | root CMake/presets/CI/docs/config | build/docs/license/config | ReferenceOnly/Rewrite | 共享（native/eng） | `eng/native`,`eng/release` | 同 baseline C ABI | 30,31 | O5 | GPL-3.0 | yes | **NeedsRecheck**（dirty CMakeLists.txt） |

---

## 9. Merge consistency with `feature-inventory-and-mapping.md`

- The per-feature rows in `feature-inventory-and-mapping.md` (833 unique `AF-F-*` at 2026-08-09; renumbering may
  adjust counts) are the denominator. This file's subsystem rows reference those ranges; `docs/tools/check-inventory.ps1`
  validates: (a) every feature row has non-empty `DecisionClass/OracleClass/OwningStep`; (b) no orphan SourcePath
  bidirectionally; (c) per-source completeness (see script for each source's closure test).
- A `SourcePath` appearing in two rows must be merged or annotated as divergence and written back to the relevant
  source section; inventory paths must exist at the frozen baseline commit (`Test-Path` sampling).
- Disabled/deprecated numbers are never reused for a re-mapped row.