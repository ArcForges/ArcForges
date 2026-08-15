# Verification Oracles — 验证方法、测试 Oracle 与行为金样

> **权威来源**：`00-scope-and-source-inventory.md` 00.05。本文件冻结 Oracle 类别 O1–O7、行为金样首批目录、金样管理规则与测试金字塔落点；权威测试/门禁集合以各编号步骤与 `final-production-gate.md` 为准。
> 本步只冻结**清单与格式**；金样本体在实施阶段捕获，不在规划期生成。

---

## 1. Oracle 类别表

| 类别 | 定义 | 捕获方式 | 拥有测试项目 | 适用 Decision |
|---|---|---|---|---|
| **O1 源行为重放** | 从来源应用捕获的请求/响应/事件增量序列（AionUi `ipcBridge` REST 调用 + `wsEmitter` 事件；mobile WS 帧） | fixture = 输入时序 + 期望输出 | `tests/EndToEndTests` / `<Product>.Tests` | Copy |
| **O2 结构对等** | 合同形状/DB schema 字段级对照（AionUi 13 表 → ArcChat schema 行于 Step 04/09；AFFiNE Prisma 57 表仅 ReferenceOnly 结构参照，不复制 DDL） | 合同/表字段 projection 对照 | `tests/ContractCompatibilityTests` / `tests/PersistenceRecoveryTests` | Copy/ReferenceOnly |
| **O3 行为规格** | ReferenceOnly 来源的成文行为（siyuan kernel API 语义、AFFiNE EE 同步模式）→ 由规格**独立撰写**测试用例，不引源码 | 行为规格 → 独立测试用例 | `ArcNotes.Tests.{Unit,Integration,Ui}` / `ArcForges.Cloud.Tests` | ReferenceOnly→独立实现 |
| **O4 公开协议标准** | MQTT/Modbus/CAN/UART/TCP/UDP/Serial 规范 + 标准一致性测试向量（协议组织公开测试帧） | 公开规范测试向量 | `ArcScope.Tests.{Unit,Integration,Ui}` | **ArcScope Pro 行一律 O4** |
| **O5 数学/算法基准值** | FFT 窗函数、降采样（LTTB 等）、几何、Color、rational（`av_reduce`）公开公式与基准值表；KissFFT（BSD-3-Clause 保留声明）可作交叉验证工具 | 公开公式/基准值表 | `ArcScope.Tests.{Unit,Integration,Ui}` / `ArcSlate.Tests.{Unit,Integration,Ui}` | Copy/独立实现 |
| **O6 视觉基线** | golden screenshot / UI fixture，逐产品步骤捕获（方法参考 AionUiReWrite-Kotlin/visual-parity-baseline） | UI fixture | 06 共享桌面体验、10/15/16/17 ArcNotes、21–22 ArcScope、23–25 ArcSlate、18–20 Mobile、29 Web | Rewrite |
| **O7 序列化金样** | 合同往返金样字节/JSON（Step 02 `tests/ContractCompatibilityTests`），旧↔新交叉、additive/unknown-fields/enum/error-codes/resource-refs/revision 全套 | 合同往返金样 bytes/JSON | `tests/ContractCompatibilityTests` | Copy/合同 |

---

## 2. 行为金样首批目录（8 条；本步冻结清单与格式，样本实施期捕获）

每条目五列：`条目 | 来源@commit | 格式 | 捕获步骤 | Oracle | 拥有测试`。

| # | 条目 | 格式 | 捕获步骤 | Oracle | 拥有测试 |
|---|---|---|---|---|---|
| 1 | AionUi `composeMessage` 合并 | `deltas[]`（按时间顺序的流片段 JSON，含 text/tool_group/tool_call/acp_tool_call/plan/thinking 各臂）+ `expected.json`（最终 TMessage）；覆盖 append vs replace、merge-by-call_id、merge-by-id、merge-by-session、contiguous-chunk | Step 09 | O1 | `ArcChat.Tests.Unit` / `tests/EndToEndTests` |
| 2 | AionUi conversation CRUD + pin 排序 + 分组历史（今天/昨天/更早，pinned 优先） | op 序列 + 期望列表态 | Step 09 | O1 | `ArcChat.Tests.Integration` |
| 3 | AionUi mobile WS 重连 / JWT 刷新 / 消息分组 | 帧序列 + 期望会话态 | Step 18/19 | O1 | `ArcChat.Mobile.Tests` |
| 4 | blocksuite 文档/Block/Edgeless/Database/Slides 行为样本 | 只提取与 ArcNotes 自有 JSON 文档格式对应的结构和交互 Oracle；Yjs/CRDT/awareness/state vector 明确 **Drop**，不生成兼容金样 | Step 10/15/16/17 | O2/O5 | `ArcNotes.Tests.*` |
| 5 | Serial-Studio `FrameReader` 帧解析（帧界/CRC/转义/JSON Frame Format 样本）+ `CircularBuffer` 覆盖写语义 + LTTB 降采样数值基准 | 输入帧/字节 → 期望解析 + 数值基准 | Step 21–22（探针 07 预验证子集） | O1/O5 | `ArcScope.Tests.{Unit,Integration,Ui}` |
| 6 | ArcVideoFoundation `rational`/`TimeRange`/`Timecode`/`av_reduce` 基准值对（输入→期望输出表） | 输入→期望输出表 | Step 23–25（探针 07 预验证） | O5 | `ArcSlate.Tests.{Unit,Integration,Ui}` |
| 7 | siyuan block 引用/反链/搜索/导入导出行为样本（**仅输入/输出对**） | 仅行为输入/输出（无源码片段） | Step 10–15 | O3 | `ArcNotes.Tests.{Unit,Integration,Ui}` |
| 8 | 同步/冲突行为样本：顺序 revision、幂等 change、冲突副本、显式解决命令、immutable blob 与离线重放 | 对象版本/change feed 样本；**不得引入 CRDT merge** | Steps 12/14 | O3 | `ArcForges.Cloud.Tests` / `tests/PersistenceRecoveryTests` |

---

## 3. 金样管理规则

- **存放**：`tests/golden/<area>/<name>.{json,bin}` + 每目录 `provenance.json`（`SourceRepo@BaselineCommit`、捕获方法、捕获者、日期 UTC、许可证注记）。
- **红线**：AGPL（siyuan）与商业受限（Serial-Studio Pro、AFFiNE EE）来源的金样只捕获**行为（输入/输出）**，不得含源码片段；超过"行为描述必要"的源码引用即违规。金样不得含疑涉第三方 IP 资源、真实用户数据或 Secret（脱敏规则：token/key/邮箱/绝对路径一律占位符）。
- **更新规则**：金样变更 = 合同级变更，需 PR + 兼容 ADR 注记 + 拥有步骤 Completion gate 引用。

---

## 4. 测试金字塔落点

| 层 | 项目 | 内容 |
|---|---|---|
| 单元 | `<Product>.Tests` | 值类型、合并规则、算法、domain 行为 |
| 合同 | `tests/ContractCompatibilityTests` / `PublicApiContractTests` | O7 序列化金样、schema 兼容、route/event 集合相等 |
| 集成 | `tests/PersistenceRecoveryTests` / `LocalRpcAotTests` / `RealtimeReconnectTests` | DB/恢复、LocalRpc AOT、断线重连 |
| 跨边界/架构 | `tests/ArchitectureTests` / `NativeAbiTests` | 引用方向、native ABI layout/parity |
| E2E | `tests/EndToEndTests` | 跨 App/Cloud 端到端 |
| **Migration Testing（一级测试类型）** | framework（Step 04 起） | Round-trip + Failure Injection + Recovery Point + Downgrade 行为（architecture §12） |

---

## 5. 与 00.02 的绑定

`feature-inventory-and-mapping.md` / `source-subsystems.md` 每行的 `OracleClass` 列取值必须 ∈ O1–O7，且该行在首批目录或拥有步骤测试计划中有落点。`docs/tools/check-verification.ps1` 强制执行：`OracleClass` 无空值；Decision=Copy/Rewrite/ReferenceOnly 的行 100% 有 Oracle 落点；金样红线上限（源码片段启发式 ≥15 行）规划树零命中；首批目录 ≥8 条且五列齐全。