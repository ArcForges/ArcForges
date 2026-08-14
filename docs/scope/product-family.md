# ArcForges Product Family (frozen scope)

> **Product-set freeze for the whole 00–31 implementation sequence.** This file turns the product table in
> `ArcForgesReWrite-AllCsharp - Paddle\README.md` §2 and `product-direction-and-decisions.md` §2/§4 into a
> mechanizable scope sheet. It is the **only** product set for the sequence; any drift (an extra product, a
> missing platform, ArcImage resurrection, Web demoted to an external hand-off) is a failure of this gate.
> Authority for runtime/RID/layout details: `implementation-repository-layout.md` §13/§14 and README §2.

## Change discipline

- `ProductId` values are stable identity strings and must not be edited once assigned.
- Owning-step columns point at numbered step files (`README.md` §4 continuation table); a product may be owned by
  several steps. Priorities and owners below match `README.md` §4.
- No product, project, namespace, or step title may be named `ArcImage`. See the exit table for the single legal
  occurrence context (an "exited" note) of the word.

---

## Table 1 — Product freeze (唯一产品集)

| 产品名 | 稳定身份 ProductId | 定位 | 平台与 RID | 运行时/宿主 | 优先级 | 拥有步骤 |
|---|---|---|---|---|---|---|
| ArcChat Desktop | arcchat | AI Agent Command Center + Chat + Task Center + 本机 Hub + Capability/MCP 工具桥 + 审批/结果应用 + 远程工具桥 | `win-x64`,`win-arm64`,`osx-x64`,`osx-arm64`,`linux-x64`（`linux-arm64` 后续） | Avalonia `12.1.1` + .NET 10 **Native AOT** | 核心 | 08,09（+Hub 协调面 08） |
| ArcNotes Desktop | arcnotes | Local-first 专业知识与文档工作台（文档/Block/知识/Edgeless/Database Views/Slides） | 同五 RID | Avalonia `12.1.1` + Native AOT | 核心 | 10–11,14–17 |
| ArcScope Desktop | arcscope | Local-first 数据采集、观测、遥测分析工作台（解码/可视化/分析/报告） | 同五 RID | Avalonia `12.1.1` + Native AOT + 原生设备互操作 | 核心 | 07,21–22 |
| ArcSlate Desktop | arcslate | Local-first 专业非线性视频编辑（时间线/媒体/渲染/导出）+ owned C ABI | 同五 RID | Avalonia `12.1.1` + Native AOT + FFmpeg/OTIO/图像与音频原生层 | 核心 | 07,23–25 |
| ArcChat Mobile | arcchat-mobile | 远程 Chat、Task、Approval、Steering 控制面 | Android（MAUI Mono AOT，正式交付）；iOS（完整架构、构建延期） | .NET MAUI `10.0.90`；Android Mono + Mono AOT（非 Native AOT） | Companion | 18–20 |
| ArcForges Cloud | arcforges-cloud | JIT ASP.NET Core 模块化单体：Identity/Sync/单 Agent Harness/AI/ToolRequest/商业/运维 | 服务器（linux/container），非桌面 RID | ASP.NET Core 10 JIT + Aspire + PostgreSQL + 对象存储 | 核心 | 12–14,26 |
| ArcForges Web | arcforges-web | standalone Blazor WebAssembly 浏览器 UI（官网/Account Portal/ArcChat Web Companion） | 静态浏览器（trimmed WASM） | standalone Blazor WebAssembly `10.0.10`；`RunAOTCompilation=false` | Companion | 29 |

> ProductId 集合逐字：`arcchat,arcnotes,arcscope,arcslate,arcchat-mobile,arcforges-cloud,arcforges-web`。
> Exactly **one mobile app** and **one web app**; all other mobile/web projects are internal libraries or tests.

---

## Table 2 — 退出与继承

| 条目 | 处置 | 依据/约束 |
|---|---|---|
| **ArcImage** | **退出当前产品基线**——`FutureAllCSharp.md` 的 ArcImage 概念不迁入；ArcScope 是全新产品，不复用 ArcImage 领域概念 | README §2/§3；本文档是 word `ArcImage` 的唯一合法出现语境（"已退出"说明）。目标产品/项目/Namespace/步骤标题零命中。 |
| ArcVideo → ArcSlate | 方向继承：Olive 系行为参考 + GPL-3.0 移植语义 | 拥有步骤 23–25、探针 07 |
| ArcVideoFoundation → ArcSlate | Foundation 纯 C++ 核心（rational/time/timecode/color/bezier/…）作为媒体运行时基础，经 owned narrow C ABI 复用选项 | 拥有步骤 23–25、探针 07 |

---

## Product autonomy invariants（产品自治不变式）

每行冻结 README §2 的自治不变量为可核验行：不变式 | 含义 | 验证方法 | 强制步骤。

| # | 不变式 | 含义 | 验证方法 | 强制步骤 |
|---|---|---|---|---|
| 1 | 每桌面产品是完整自治 OS 应用 | 自己的 Domain、durable state、数据库/文件、事务与恢复、Undo/历史、发布生命周期 | ArchitectureTests（01.06）+ 每产品独立 `*.db`（layout §8）+ 各自 publish 列车（31） | 01,04,31 |
| 2 | 不存在共享可写业务数据库 | 无跨产品共享可写 SQLite/PostgreSQL 业务库；每产品独立 DB | ArchitectureTests 禁跨产品 Infrastructure 直引（01.06）+ Cloud PostgreSQL 逻辑 schema 分模块、禁每模块一库也禁产品共享业务库（layout §6/§11） | 01,04,12 |
| 3 | 不存在本机中央服务或本机 Agent 进程 | ArcChat Desktop 自身承载 Local Hub、MCP Client、远程工具桥、权限和审批；不持有专业产品正文，也不承载模型循环；无 AgentHost/daemon/Worker | 进程拓扑测试、项目引用测试和 OS 进程 E2E（负扫描：无 Node/loopback/ContentSandbox 常驻） | 01,05,07,08,09,30 |
| 4 | 专业 App 核心本地功能不依赖 ArcChat、不依赖 Account/Cloud | ArcNotes/ArcScope/ArcSlate 打开、编辑、保存、恢复、导出本地项目时无需 ArcChat 或 Cloud | 05 Domain 无外部依赖 + 10/18/19 的"无 ArcChat/无 Cloud 启动并可用核心功能"集成测试（引用本表不变式编号） | 05,09,10,21,23 |
| 5 | 跨 App 传语义 Capability/Reference | 跨应用通信用语义 `Capability` 与 `ResourceRef/ArtifactRef`，不远程操作 UI；大资源留所有者一侧，Hub 不代理视频帧/大对象 | Contracts 纯净测试（02）+ 合同无裸字节/帧字段（02.02/02.04 金样） | 02,05,08,09 |
| 6 | 专业 App 可直接参与自己的 Cloud 同步；Cloud Agent 如需本机能力只能创建持久 ToolRequest | Cloud 通过 durable `ToolRequest` 请求本机能力；ArcChat Desktop 拉取、重新授权、执行并幂等回传 `ToolResult`；Cloud 不直连 localhost/Pipe/UDS/stdio | Step 14 的断线、重复、拒绝和恢复 E2E | 12,13,14,26 |
| 7 | Mobile/Web 当前是 ArcChat Companion，不是专业 App 手机版/编辑器 | Mobile/Web 不实现笔记/采集/编辑的移动版；专业对象仅以 `ResourceRef/ArtifactRef/Preview/Summary` 出现 | Mobile 项目清单仅 `ArcChat.Mobile.*`（layout §7）；ArchitectureTests 断言 Mobile 不引用 `ArcNotes.*/ArcScope.*/ArcSlate.*` | 01,18,19,29 |

---

## ArcNotes 分阶段表

| 阶段 | Scope | 拥有步骤 |
|---|---|---|
| V1 文档核心 | 文档/Block/搜索/附件/历史/导入导出 | 10 |
| 知识检索 | Knowledge/Search/Retrieval（FTS + 授权 AI Evidence） | 11 |
| Cloud 同步 | 六类 Sync object、revision/change feed/outbox/inbox/冲突副本/显式解决 | 12,14 |
| Edgeless | Canvas/白板（与文档 Block 共享内容） | 15 |
| 多视图 Database | Typed Property/Database 视图（Table/Board/Calendar/etc.） | 16 |
| Slides | Frame/演示模式 | 17 |

> 同步使用 revision、change feed、冲突副本与显式解决命令，**不实施 CRDT/Yjs/state vector**，也不保留未来 CRDT 兼容字段。

---

## Android / iOS / Web 状态冻结

- **Android 边界规则**（验证：17 合同测试 + 02 PublicApi/Realtime 合同）：完整远程 Chat/Task/Approval/Steering 控制面。**所有远程业务通信全经 ArcForges 服务器**；**禁直连 LAN/Named Pipe/UDS/专业 App**；专业对象仅以 `ResourceRef/ArtifactRef/Preview/Summary` 出现。正式基线 = MAUI **Mono + Mono AOT** Release，不称 Native AOT。
- **iOS**：**完整 MAUI 架构但 Planned / Build Deferred**——当前不编译，但规划中落实：Scene 生命周期、APNs、Universal Link、Keychain、Passkey、Biometrics、Privacy Manifest、Signing/Provisioning、测试策略；真实实现位置 = 唯一 Head `src/Mobile/ArcChat.Mobile/Platforms/iOS/`（layout §7），`EnableIosTarget=false` 时 target 不进入构建图（01.06 创建条件源码/资源骨架）。
- **Web**：standalone Blazor WebAssembly 只是浏览器 UI；静态托管后只调用 Cloud HTTP/JSON 与 SignalR，不使用 Blazor Server circuit、Node/TypeScript/React/TypeSpec/Workers，也不在浏览器运行 Agent。Fixed `PublishTrimmed=true`、`RunAOTCompilation=false`。Step 01 创建骨架，Step 29 完成官网/Account Portal/ArcChat Web Companion/浏览器安全/测试/部署/回滚，并保持 layout §8 的 **9 个 Web 项目**。

---

## 商业模型快照

只登记已确认的产品规则：

- 计费宿主 = ArcForges Cloud（Paddle 托管支付 + Payoneer 卖家结算，`Cloud.Modules.Billing`）。
- **明确 `Drop`（不得作为"未来"范围悄悄保留）**：多人协同、组织/团队成员关系、Team Workspace、邀请、Team Mode、角色、Team Inbox、team task、多 Agent 委派、Agent Team、handoff、BackgroundAgents、CRDT/Yjs/awareness/多人光标。
- ArcForges Cloud 按单用户 `WorkspaceId` 数据/设备/计费/同步/权限边界交付。

---

## 不输出清单

按 README §3.3，本文件（及所有 Step 00 scope 产物的结尾）明确**不输出**：

- 工期、人数、成本估算；
- 甘特图；
- 虚构发布日期。

没有任何结论把 `[ ]` 状态、规划文字或未来测试冒充为已执行的产品、构建、测试或发布证据。