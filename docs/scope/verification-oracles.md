# Verification Methods: Test Oracles & Behavior Golden Samples

> Fixes, **before implementation**, the Oracle class each reused behavior is verified against and the format
> +source rules for the first batch of behavior golden samples (samples are captured during the owning steps,
> never pre-generated). This makes "移植行为可验证" decidable for Copy/ReferenceOnly reuse. Red line holds for
> AGPL/commercial-restricted sources: golden samples are **input/output pairs, never source excerpts**.

---

## 1. Oracle categories

| 类别 | 定义 | 捕获方式 | 拥有测试项目 | 适用 Decision |
|---|---|---|---|---|
| **O1 源行为重放** | 从来源应用捕获的请求/响应/事件增量序列（AionUi `ipcBridge` REST 调用 + `wsEmitter` 事件；mobile WS 帧）→ fixture = 输入时序 + 期望输出 | replay fixtures | `tests/EndToEndTests` / `<Product>.Tests` | Copy |
| **O2 结构对等** | 合同形状/DB schema 字段级对照（AionUi 13 表 → ArcChat schema Step 04/09；AFFiNE Prisma 57 表仅 ReferenceOnly 结构参照，不复制 DDL） | schema/DTD diff | `tests/ContractCompatibilityTests` / `tests/PersistenceRecoveryTests` | Copy/ReferenceOnly |
| **O3 行为规格** | ReferenceOnly 来源的成文行为（siyuan kernel API 语义、AFFiNE EE 同步模式）→ 由规格独立撰写测试用例，不引源码 | spec-derived cases | `ArcNotes.Tests.{Unit,Integration,Ui}` / `ArcForges.Cloud.Tests` | ReferenceOnly→独立实现 |
| **O4 公开协议标准** | MQTT/Modbus/CAN/UART/TCP/UDP/Serial 规范 + 标准一致性测试向量（协议组织公开测试帧） | protocol conformance | `ArcScope.Tests.{Unit,Integration,Ui}`；**ArcScope Pro 一律 O4** | Replace（独立实现） |
| **O5 数学/算法基准值** | FFT 窗函数、降采样（LTTB 等）、几何、Color、rational（`av_reduce`）的公开公式与基准值表；KissFFT（BSD-3-Clause，保留声明）可作交叉验证工具 | numeric baselines | `ArcScope.Tests.*`/`ArcSlate.Tests.*` | Copy/独立实现 |
| **O6 视觉基线** | golden screenshot / UI fixture，逐产品步骤捕获（方法参考 `AionUiReWrite-Kotlin/visual-parity-baseline.md`） | screenshot goldens | 06 共享桌面体验、10/15/16/17 ArcNotes、21–22 ArcScope、23–25 ArcSlate、18–20 Mobile、29 Web | Rewrite（UI） |
| **O7 序列化金样** | 合同往返金样字节/JSON（Step 02 `tests/ContractCompatibilityTests`），旧↔新交叉、additive/unknown-fields/enum/error-codes/resource-refs/revision 全套 | round-trip goldens | `tests/ContractCompatibilityTests` | Copy/迁移 |

---

## 2. Behavior golden-sample first catalog（冻结清单与格式；样本在实施阶段捕获）

Unified per-entry columns: `条目 | 来源@commit | 格式 | 捕获步骤 | Oracle | 拥有测试`。≥8 条。

| # | 条目 | 来源@commit | 格式 | 捕获步骤 | Oracle | 拥有测试 |
|---|---|---|---|---|---|---|
| 1 | AionUi `composeMessage` 合并（append vs replace、merge-by-`call_id`、merge-by-id、merge-by-session、contiguous-chunk） | AionUi@`29c9271a…` | `deltas[]`（按时序流片段 JSON，含 text/tool_group/tool_call/acp_tool_call/plan/thinking 各臂）+ `expected.json`（最终 `TMessage`） | 09 | O1 | `ArcChat.Tests.Unit/Integration` |
| 2 | AionUi conversation CRUD + pin 排序 + 分组历史（今天/昨天/更早，pinned 优先） | AionUi@`29c9271a…` | op 序列 + 期望列表态 | 09 | O1 | `ArcChat.Tests.*` |
| 3 | AionUi mobile WS 重连 / JWT 刷新 / 消息分组 | AionUi@`29c9271a…` | 帧序列 + 期望会话态 | 18/19 | O1 | `ArcChat.Mobile.ContractTests` |
| 4 | blocksuite 文档/Block/Edgeless/Database/Slides 行为样本 | AFFiNE@`81df4751…` | 与 ArcNotes 自有 JSON 文档格式对应的结构和交互 Oracle；**Yjs/CRDT/awareness 明确 Drop，不生成兼容金样** | 10/15/16/17 | O2 | `ArcNotes.Tests.*` |
| 5 | Serial-Studio `FrameReader` 帧解析（帧界/CRC/转义/JSON Frame Format）+ `CircularBuffer` 覆盖写语义 + LTTB 降采样基准 | Serial-Studio@`639daafb…` | 输入字节帧 → 期望帧/输出；覆盖写语义集；数值基准表 | 21–22（探针 07 预验证子集） | O1/O5 | `ArcScope.Tests.*`/`ArcScopePipelineTests` |
| 6 | ArcVideoFoundation `rational`/`TimeRange`/`Timecode`/`av_reduce` 基准值对 | ArcVideoFoundation@`139eecaa…` | 输入→期望输出表 | 23–25（探针 07 预验证） | O5 | `ArcSlate.Tests.*` |
| 7 | siyuan block 引用/反链/搜索/导入导出行为样本（**仅输入/输出对**） | siyuan@`eef10568…` | input→output 对（无源码片段） | 10–15 | O3 | `ArcNotes.Tests.*` |
| 8 | 同步/冲突行为样本（顺序 revision、幂等 change、冲突副本、显式解决、immutable blob、离线重放） | ArcForges 自有（无来源） | revision/change/conflict 序列 | 12/14 | O3 | `SyncConflictTests`/`ArcNotes.Tests.Integration` |

> Catalog has ≥8 entries; each entry carries all five columns (条目/来源/格式/捕获步骤/Oracle/拥有测试).

---

## 3. Golden-sample management rules

- **Storage**: `tests/golden/<area>/<name>.{json,bin}` + per-directory `provenance.json`
  (`SourceRepo@BaselineCommit`、捕获方法、捕获者、日期 UTC、许可证注记).
- **Red lines**:
  - AGPL（siyuan）与商业受限（Serial-Studio Pro、AFFiNE EE）来源的金样**只捕获行为（输入/输出）**；超过"行为描述必要"的源码引用即违规。
  - 金样**不得**含疑涉第三方 IP 资源、真实用户数据、Secret（脱敏规则：token/key/邮箱/绝对路径一律占位符）。
  - 2/3/4/5 类金样（blocksuite Yjs drop、Serial-Studio Frame/LTTB、rational/timecode、siyuan IO 对）不复制来源源码。
- **Update rule**: 金样变更 = 合同级变更 → PR + 兼容 ADR 注记 + 拥有步骤 Completion gate 引用；不做静默覆盖。

---

## 4. Test-pyramid landing

| 层 | Owner 项目 | 落点 |
|---|---|---|
| 单元 | `<Product>.Tests`（`.Unit`） | 算法/合并规则/值类型/协议解析 |
| 合同 | `tests/ContractCompatibilityTests` / `tests/PublicApiContractTests` | JSON Schema/OpenAPI/golden/current↔previous；O7/O2 |
| 集成 | `tests/PersistenceRecoveryTests` / `tests/LocalRpcAotTests` / `tests/RealtimeReconnectTests` / `tests/SyncConflictTests` | 真实 SQLite/PostgreSQL/本地传输/恢复；O1/O3 |
| 跨边界/架构 | `tests/ArchitectureTests` / `tests/NativeAbiTests` | 引用方向/合同唯一性/禁止类型/ABI |
| E2E | `tests/EndToEndTests` | 跨产品用户旅程；O6/O7 |
| **Migration Testing（一级测试类型）** | Persistence/Recovery + Cloud | Round-trip + Failure Injection + Recovery Point + Downgrade 行为（architecture §12；框架 Step 04 起） |

---

## 5. Binding with 00.02

- Every row in `source-subsystems.md`/`feature-inventory-and-mapping.md` has a non-empty `OracleClass` ∈ O1–O7,
  and a landing either in the first catalog (§2) or in its owning step's Testing requirements.
- Decision=Copy/Rewrite/ReferenceOnly rows have **100%** an Oracle landing (no un-verified port).
- Restricted-source goldens (siyuan/Pro/EE) are input/output only — no source-excerpt heuristic hits in the
  planning tree (checked by `docs/tools/check-oracles.ps1`).

---

## 6. Verification

- `docs/tools/check-oracles.ps1` asserts: catalog has ≥8 entries with all five columns; every
  `source-subsystems.md` OracleClass ∈ O1–O7 and non-empty; Decision=Copy/Rewrite/ReferenceOnly rows each
  have an Oracle landing (non-empty OracleClass); golden red-line scan of PlanRoot + TargetDocsRoot marks zero
  source-excerpt hits (≥15 consecutive non-C# source lines heuristic). Reverse evidence: clearing a siyuan row's
  OracleClass → coverage assert fails and names the FeatureId.