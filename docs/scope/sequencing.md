# Sequencing — 分支/PR 序列与追踪种子

> **权威来源**：分支/worktree/PR 的粒度与生命周期规则唯一权威是顶层执行提示词 `ArcForges/ArchitectureDesign/arcforges.md`；本文件**只给出命名示例**，不复制流程规则。00–31 序列表逐字引用 `README.md` §4；硬约束以下标"约束"。本文件是本步种子，后续每个 PR 以此为准。

---

## 1. 分支命名示例

分支名符合正则 `^feat/af\d{2}(-\d{2})?-[a-z0-9-]+$`（同时接受 whole-step 与 substep 两种格式）。

| 形态 | 示例 |
|---|---|
| whole-step | `feat/af02-contracts-and-code-generation`、`feat/af00-scope-and-source-inventory` |
| substep | `feat/af02-03-localrpc-hub-interfaces`、`feat/af10-05-block-editor-core` |
| lettered substep | `09.16A` → `feat/af09-16-a-native-preview` |

工作树统一置于 `WORKTREE_ROOT`（`ArcForges/.worktree/`）；`PLAN_REPO` 写回使用 `PLAN_WORKTREE_ROOT` 下独立工作树。分支/worktree/PR 的粒度、提交纪律、PR 时点与关闭语义以 `arcforges.md` 为唯一权威。

---

## 2. PR 完成模板字段

以执行提示词的 PR body 模板为唯一权威；本表仅列字段供追踪引用（不在本文件重定义模板）。

- 改动文件清单
- 新增/修改测试
- 命令与结果（restore/build/test/publish 原文）
- 跳过的 GUI/原生/打包项及原因
- 追踪行更新（FeatureId 列表）
- `final-production-gate.md` 影响评估
- 逐功能对等清单（本 PR 涉及的 FeatureId × Oracle × 结果）
- 设计冲突与决定回写

---

## 3. 00–31 序列表（逐字引用 README §4）

| 序 | 说明 | 硬约束 |
|---|---|---|
| 00 | Scope & Source Inventory | 起点 |
| 01 | Solution & Repository Foundation | 前无约束 |
| 02 | Contracts & Code Generation | 依赖 01 |
| 03 / 04 | Local IPC / Persistence & Recovery | 依赖 02 后（03/04 顺序） |
| 05 / 06 | Domain Foundations / Shared Desktop Experience | 依赖 03/04 |
| 07 | High-Risk Technical Probes | 依赖 05/06 |
| 08–12 | ArcChat Hub + core, ArcNotes document core, Knowledge, Cloud vertical slice | 依赖 07 |
| 13 | Cloud Agent Harness Runtime | 依赖 12 |
| 14 | Remote Tool Bridge / Sync | 依赖 13 |
| 15–17 | ArcNotes 扩展（Edgeless / Database / Slides） | 依赖 14 |
| 18 | MAUI shared architecture | 依赖 14 |
| 19 | Android 正式实施 | 依赖 18 |
| 20 | iOS 架构（Build Deferred） | 依赖 18 |
| 21–22 | ArcScope 完整产品 + 分析/UI | 依赖 19 |
| 23–25 | ArcSlate 完整产品 / native·OTIO / renderer·export | 依赖 21–22 |
| 26 | Cloud 完成 | 依赖 23–25 |
| 27–29 | 平台/Web（Extension / Policy / Blazor Web） | 依赖 26 |
| 30 | 独立安全、质量、兼容与失败恢复审计 | 依赖 27–29 |
| 31 | 安装、签名、发布、回滚、运维与最终门禁 | 依赖 30 |

---

## 4. 追踪种子与机读 bridge 合同

- Markdown 大表（`docs/traceability-matrix.md`）保存稳定 `TR-*` requirement 摘要，**不能代替** Feature/Coverage 外键；不靠人工复制 Feature 数量行宣称闭合。
- trace-bridge 生成器（本步以一次性脚本运行生成 bridge JSON；仓库策略 `RepositoryPolicyTests` 禁 tracked helper scripts，生成器脚本不纳入版本控制，bridge 输出记录于 ledger）从 Feature inventory、Coverage register、TR/PS/Contract/Data/Test/Gate registries 生成 `artifacts/evidence/traceability/feature-trace-bridge.json`。每条记录固定 `traceId/featureIds[]/coverageIds[]/requirementId/target*/contractIds[]/dataIds[]/uiSurfaceIds[]/owningSteps[]/testIds[]/gateIds[]/sourceBaselines[]/closureStatus/missingFields[]/evidenceHash`。
- 初始状态诚实为 `BridgeGenerationRequired`；只有外键存在、非适用面有稳定 `NotApplicable(reasonCode)`、Feature/Coverage 非 `NeedsRecheck` 且同 release 测试/门禁证据存在，生成器才写 `Closed`。本轮文档决策完成 **不等于** 实现 evidence 已生成。
- 本步登记冻结决策（见 `00-scope-and-source-inventory.md` 末"冻结决策与实施核验"）与 README §9 恢复入口的更新规则。

---

## 5. 一致性核验

Step 00.06 的 Testing requirements 断言（本步已逐条执行并记录证据）：

1. 追踪完整性：每个 Markdown `TR-*` 有 OwningStep（∈ 00–31）、Test 与 FG；生成 bridge 的 `featureIds` 集合 == `feature-inventory-and-mapping.md` 当前唯一 ID 集合，`coverageIds` 集合 == Coverage register 可展开集合，所有外键双向差集为空；`NeedsRecheck`/`Missing*` 保留为阻断状态，不能因生成成功自动改 `Closed`。
2. 分支命名正则校验：`^feat/af\d{2}(-\d{2})?-[a-z0-9-]+$`（对 sequencing.md 示例与后续分支可用）。