# Traceability Matrix（追踪矩阵）— Step 00.06 种子

> **权威来源**：本文件是 ArcForges「来源功能 → 产品需求 → 架构落点 → 步骤 → 测试 → 门禁」的追踪矩阵种子（00.06 产出）。Markdown 大表只保存**稳定 `TR-*` requirement 摘要**，**不代替** Feature/Coverage 外键；闭合状态只由 trace-bridge 生成器（实施阶段以 test/CI gate 落实）生成的 `feature-trace-bridge.json` 判定，不靠人工复制 Feature 数量行。
> 当前状态诚实为 **`BridgeGenerationRequired`**：实现/发布阶段由生成器把每个 Feature 连接到唯一 primary requirement owner、拥有步骤、测试与 Gate。`NeedsRecheck` / `Missing*` 保持阻断，不能因生成成功自动改 `Closed`。

---

## TR-ID 规则与领域

格式 `TR-<领域码>-<两位序号>`（领域：ARC 架构/共享、IPC 本机 IPC、PERSIST 持久化/恢复、SEC 安全/权限、QUAL 质量/可观测、CHAT ArcChat、NOTE ArcNotes、SCOPE ArcScope、SLATE ArcSlate、CLOUD ArcForges Cloud、MOB Mobile/MAUI）。

## 种子 requirement 摘要行

为每个非 Drop 的 Feature 提供唯一 primary requirement owner 并把 Feature 关联到一个拥有步骤。Step 00.06 只种子 requirement 摘要；`Test` 与 `FG` 列指向权威测试项目与 `final-production-gate.md` 门禁项，实施阶段回填精确测试名。

| TR | Requirement 摘要 | OwningStep | Test | FG |
|---|---|---|---|---|
| TR-ARC-01 | 稳定序列化 ID/Revision/Sequence/Error/ResourceRef/ArtifactRef 单一落点 `ArcForges.Contracts.Foundation`；身份与版本原语透明序列化为裸标量，枚举为冻结小写字符串，未知值在边界拒绝；双源生成上下文（严格/入站）覆盖全部公共线类型 | 02.00 | `tests/ContractCompatibilityTests`（golden round-trip、源生成覆盖、演进与校验）/ `tests/ContractSchemaTests`（golden 文档形状） | FG.2 |
| TR-ARC-02 | 七个合同项目引用图与 closed tagged unions（Layout §3）；合同内部可见性授予 Step 02 的四个测试程序集 | 01/02 | `RepositoryPolicyTests.ContractProjectsMatchTheFixedReferenceGraph` / `ContractAssembliesGrantInternalsToTheContractTestProjects` | FG.2 |
| TR-IPC-01 | 产品间 StreamJsonRpc + Named Pipe/UDS JSON 本机通信 | 03 | `tests/ArchitectureTests` / `LocalRpcAotTests` | FG.2 |
| TR-PERSIST-01 | 每产品独立 SQLite + WAL/journal/snapshot/崩溃恢复 | 04 | `tests/PersistenceRecoveryTests` | FG.3 |
| TR-PERSIST-02 | PostgreSQL modular-monolith schema-per-module + migration Expand/Migrate/Contract | 04/12/26 | `ArcForges.Cloud.Tests` / `PersistenceRecoveryTests` | FG.3 |
| TR-SEC-01 | 授权链 + Security Reason Codes + R0–R4 风险 + Approval/Step-up | 05/09/13 | `ArcChat.Tests.*` / `ArcForges.Cloud.Tests` | FG.9 |
| TR-QUAL-01 | Localization 禁硬编码 + WCAG 2.2 AA + 伪本地化与 culture 测试 | 06/09 | `<Product>.Tests.Ui` | FG.9 |
| TR-CHAT-01 | ipcBridge 合同面 → ArcChat RPC/Realtime contract + merge 规则 | 08/09 | `ArcChat.Tests.{Unit,Integration}` + O1 golden | FG.2 |
| TR-CHAT-02 | 本地 Hub / MCP Client / Tool bridge / Approval，无本地 Agent 进程 | 08/09 | `tests/ArchitectureTests` / `EndToEndTests` | FG.1 |
| TR-CHAT-03 | 本地 SQLite 历史/设置（13 表重设计，Cloud Task 权威不迁移） | 09 | `ArcChat.Tests.Integration` + O2 golden | FG.3 |
| TR-NOTE-01 | Block 文档模型 + `.arcnote` 导入导出（`arcnotes.db + Managed Asset Store` 唯一权威） | 10 | `ArcNotes.Tests.*` | FG.6 |
| TR-NOTE-02 | 本地关键词/元数据检索 + 授权远端 AI Evidence | 11 | `ArcNotes.Tests.*` | FG.6 |
| TR-NOTE-03 | 无 CRDT 同步 + revision/change feed/conflict copy/显式解决 | 12/14 | `ArcForges.Cloud.Tests` / `PersistenceRecoveryTests` | FG.2/FG.3 |
| TR-NOTE-04 | Edgeless 几何/连接/分组 | 15 | `ArcNotes.Tests.*` | FG.6 |
| TR-NOTE-05 | Typed Database 多视图 | 16 | `ArcNotes.Tests.*` | FG.6 |
| TR-NOTE-06 | Slides/演示模式 | 17 | `ArcNotes.Tests.*` | FG.6 |
| TR-SCOPE-01 | Serial-Studio GPL core 移植（采集/解码/DataModel/widget） | 21–22 | `ArcScope.Tests.{Unit,Integration,Ui}` | FG.6 |
| TR-SCOPE-02 | Pro 模块独立实现（UD-LIC-5，O4 公开协议标准） | 21–22 | `ArcScope.Tests.*` / ContractCompatibilityTests | FG.6 |
| TR-SLATE-01 | Project/Timeline/Node/Media 运行时（ArcVideo real-time 参考，GPL） | 23–25 | `ArcSlate.Tests.{Unit,Integration,Ui}` | FG.6 |
| TR-SLATE-02 | OTIO `.otio` canonical round-trip + owned narrow C ABI（Step 07 探针预验证） | 07/24 | `NativeAbiTests` / `ArcSlate.Tests.*` | FG.6/FG.8 |
| TR-CLOUD-01 | Identity/Auth/Device + JIT modular-monolith（无 EE 代码移植，UD-LIC-4） | 12/26 | `ArcForges.Cloud.Tests` | FG.4 |
| TR-CLOUD-02 | 持久 ToolRequest/ToolResult + SignalR wakeup + HTTP 权威面 | 13/14 | `ArcForges.Cloud.Tests` / `EndToEndTests` | FG.2/FG.4 |
| TR-MOB-01 | MAUI shared 网络/持久化 + Android Remote Chat/Task/Approval | 18/19 | `ArcChat.Mobile.Tests` / `ArcChat.Mobile.UiTests` | FG.5 |
| TR-MOB-02 | iOS 架构完整（Planned/Build Deferred） | 20 | `ArcChat.Mobile.Tests`（架构） | FG.5 |
| TR-QUAL-02 | Locked restore：每项目提交 `packages.lock.json`，CI 以 `--locked-mode` 还原，篡改/散落版本/预览包三种违规各有可复现失败证据 | 01 | `tests/ArchitectureTests`（`RepositoryPolicyTests`）+ `pr-gate` locked restore 步骤 | FG.8 |
| TR-QUAL-03 | ArchitectureTests ARC-001..ARC-013 机器强制 layout §11 引用禁止矩阵；引用方向规则跑在声明依赖图的**传递闭包**上（间接违规边同样变红并报出整条路径），类型规则跑在已加载的 `src` 程序集上；每条规则配通过 fixture 与失败 fixture，失败信息含规则 ID 与违反路径 | 01 | `tests/ArchitectureTests`（`ARC0XX*Tests`、`ProjectGraph`、`FixtureCompiler`） | FG.1/FG.9 |
| TR-QUAL-04 | 分层 AOT/JIT/WASM 属性文件只被声明宿主 import；Desktop/ContentSandbox Native AOT、Cloud JIT、Web `RunAOTCompilation=false` 互不串线 | 01 | `RepositoryPolicyTests.LayeredBuildPropertyFilesAreImportedByExactlyTheirDeclaredHosts` | FG.5/FG.7 |
| TR-QUAL-05 | 发布验证矩阵：四 Desktop × 5 RID Native AOT publish + `--smoke`，Cloud framework-dependent JIT publish 与 Server/Workstation GC 基线 | 01/07/31 | `docs/coverage/aot-baseline.md` / `docs/coverage/runtime-baseline.md` + `release-train` | FG.5/FG.8 |
| TR-QUAL-06 | AGPL-3.0-only 根 LICENSE 与源文件 SPDX 头由 CI 强制；Third-Party-License-Register 覆盖每个直接依赖 | 01/30/31 | `RepositoryPolicyTests.FirstPartySourceFilesDeclareSpdx` / `RootLicenseMatchesCanonicalAgplText` | FG.0/FG.8 |
| TR-QUAL-07 | Desktop composition root 是唯一注册面；长期运行工作只能经 `DesktopHostedServiceRegistry` 进入进程 | 01/08/10/21/23 | `<Product>.Tests.Ui`（`DesktopCompositionRootTests`） | FG.1/FG.5 |

> 上面 requirement 摘要行不构成闭合声明：Feature/Coverage 外键、测试、门禁证据都必须由 trace-bridge 生成器（实施阶段以 test/CI gate 落实）生成的 `feature-trace-bridge.json` 在实施阶段补齐并判真。

---

## Feature/Coverage bridge schema

每个 record 固定：

`{traceId, featureIds[], coverageIds[], arcForgesRequirementId?, requirementId, targetProduct, targetProjects[], targetTypes[], contractIds[], dataIds[], uiSurfaceIds[], owningSteps[], testIds[], gateIds[], sourceBaselines[], closureStatus, missingFields[], evidenceHash}`。

`closureStatus` 只允许 `Closed`（全部外键存在 + 非 NeedsRecheck + 测试/门禁证据）、`NeedsRecheck`、`MissingFeatureBridge|MissingTarget|MissingContractOrData|MissingUiOrReason|MissingTest|MissingGate`、`Dropped`。当前状态 `BridgeGenerationRequired`。生成器在实施阶段把每个 Feature 连接到唯一 primary requirement owner、拥有步骤、测试与 Gate。