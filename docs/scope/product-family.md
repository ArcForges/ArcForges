# Product Family — 产品组合冻结表与范围

> **权威来源**：本文件是 ArcForges 全产品家族 Step 00.00 的机械可核验范围冻结。产品集合、平台、运行时与拥有步骤以 `ArcForgesReWrite-AllCsharp - Paddle/README.md` §2 / §4 为唯一事实；与本文件冲突时先回写规划，再更新本文件。
> 这是 docs-only 规划证据：Step 00.00 不产出任何 `.slnx`/`.csproj`/C#/XAML/构建脚本/CI 文件。
> 一致性由本步记录的一次性纯文本断言验证（纯文本断言，不触来源仓库；证据见 `docs/execution/step-00-ledger.md`；仓库策略 `RepositoryPolicyTests` 禁 tracked helper scripts，断言脚本不纳入版本控制）。

---

## 1. 产品冻结表

下表是 ArcForges 全产品家族当前基线下的**唯一产品集合**。任何"多一个产品、少一个平台、ArcImage 复活、把 Web 再降级成外部交接"的漂移都会在本表触发失败。

| 产品名 | 稳定身份 ProductId | 定位 | 平台与 RID | 运行时 / 宿主 | 优先级 | 拥有步骤 |
|---|---|---|---|---|---|---|
| **ArcChat** | `arcchat` | AI Agent Command Center + Chat + Task Center + 本机 Hub + 远程控制面 | `win-x64`,`win-arm64`,`osx-x64`,`osx-arm64`,`linux-x64`（`linux-arm64` 后续） | Avalonia `12.1.1` + .NET 10 **Native AOT** | 核心 | 08（+Hub 协调面 08）、09 |
| **ArcNotes** | `arcnotes` | Local-first 专业知识与文档工作台（文档、知识、Edgeless、Typed Database、Slides） | 同五 RID | Avalonia `12.1.1` + Native AOT | 核心 | 10–11、14–17 |
| **ArcScope** | `arcscope` | Local-first 数据采集、解析、观测、遥测分析工作台 | 同五 RID | Avalonia `12.1.1` + Native AOT + 原生设备互操作 | 核心 | 07、21–22 |
| **ArcSlate** | `arcslate` | Local-first 专业非线性视频编辑 | 同五 RID | Avalonia `12.1.1` + Native AOT + FFmpeg/OTIO/图像与音频原生层 | 核心 | 07、23–25 |
| **ArcChat Mobile** | `arcchat-mobile` | 远程 Chat、Task、Approval、Steering 控制面 | Android（MAUI **Mono AOT**，正式交付）与 iOS（完整架构、构建延期） | .NET MAUI | 支撑 | 18–20 |
| **ArcForges Cloud** | `arcforges-cloud` | JIT ASP.NET Core 模块化单体、单 Agent Harness、同步与远程控制 | Aspire + PostgreSQL + 对象存储 | JIT ASP.NET Core | 核心 | 12–14、26 |
| **ArcForges Web** | `arcforges-web` | standalone Blazor WebAssembly 浏览器 UI，调用 Cloud HTTP/JSON 与 SignalR | 静态 Web（WASM `RunAOTCompilation=false`） | standalone Blazor WebAssembly | 支撑 | 29 |

**冻结事实**：

- 桌面四产品 ProductId 集合与 RID 集合一致；`linux-arm64` 不在 V1 正式 RID 集。
- 桌面统一 Avalonia `12.1.1` + Native AOT 发布目标；Cloud 是 JIT 不设 AOT 门禁；Android 是 Mono AOT（不混称 Native AOT）；iOS 是 Planned / Build Deferred；Web 是 standalone trimmed WASM（`RunAOTCompilation=false`）。
- `ArcChat.Mobile` 是唯一 mobile 产品；`ArcForges.Web.App` 是唯一 web 产品。其余 mobile/web 项目均为内部库或测试，不是独立产品。
- 全部拥有步骤经 README §4 连续实施序列核对：ArcChat 08/09、ArcNotes 10–11/14–17、ArcScope 07/21–22、ArcSlate 07/23–25、Mobile 18–20、Cloud 12–14/26、Web 29。

---

## 2. 退出与继承表

| 产品 | 处置 | 说明 / 拥有步骤 |
|---|---|---|
| `ArcImage` | **退出当前产品基线** | `FutureAllCSharp.md` 的 ArcImage 概念**不迁入**；ArcScope 是全新产品，**不复用** ArcImage 领域概念。本行是 grep 白名单中"已退出/不迁入"描述语的**唯一**合法出现语境；ArcImage 不得出现在任何目标产品/项目/Namespace/步骤标题。 |
| `ArcVideo` / `ArcVideoFoundation` | **方向继承 → ArcSlate** | 仅方向继承：Olive 系行为参考 + GPL-3.0 移植语义 + Foundation 纯 C++ 核心 FFI 复用选项。拥有步骤 23–25 / 探针 07。 |

---

## 3. 产品自治不变式

以下 7 条不变式来自 README §2，逐条落为可核验行。任何实施必须在指定的"验证方法 / 强制步骤"内证明，不能靠声明。

| # | 不变式 | 含义 | 验证方法 | 强制步骤 |
|---|---|---|---|---|
| 1 | 每桌面产品是完整自治 OS 应用 | 自己的 Domain、durable state、数据库/文件、事务与恢复、Undo/历史、发布生命周期 | ArchitectureTests（01.06）+ 每产品独立 `*.db`（implementation-repository-layout §8）+ 各自 publish 列车（31） | 01.06、31 / 各产品 08–25 |
| 2 | 不存在共享可写业务数据库 | 无 `ArcForges.db` 大一统；无跨产品直接共享写 | ArchitectureTests 禁跨产品 Infrastructure 直引（01.06）+ Cloud PostgreSQL 逻辑 schema 分模块、禁每模块一库也禁产品共享业务库（layout §6/§11） | 01.06、04、12/26 |
| 3 | 不存在本机中央服务或本机 Agent 进程 | ArcChat Desktop 自身承载 Local Hub、MCP Client、远程工具桥、权限和审批；不持有专业产品正文，不承载模型循环 | 进程拓扑测试、项目引用测试和 OS 进程 E2E | 03、08、09、FG.1 |
| 4 | 专业 App 核心本地功能不依赖 ArcChat、不依赖 Account/Cloud | 专业产品核心功能在 ArcChat/Cloud 不可用时照常工作 | 05 Domain 无外部依赖 + 10/18/19 的"无 ArcChat/无 Cloud 启动并可用核心功能"集成测试（引用本表不变式编号） | 05、10、18、19 |
| 5 | 跨 App 传语义 Capability/Reference | 传 `ResourceRef`/`ArtifactRef`，不远程操作 UI；大资源留所有者一侧，Hub 不代理视频帧/大对象 | Contracts 纯净测试（02）+ 合同无裸字节/帧字段（02.02/02.04 金样） | 02、03 |
| 6 | 专业 App 可直接参与自己的 Cloud 同步 | Cloud Agent 如需本机能力，只能创建持久 `ToolRequest`，由 ArcChat Desktop 拉取、重新授权、执行并回传 | Step 14 的断线、重复、拒绝和恢复 E2E | 12–14 |
| 7 | Mobile/Web 当前是 ArcChat Companion | 不是 ArcNotes/ArcScope/ArcSlate 的手机版/编辑器 | Mobile 项目清单仅 `ArcChat.Mobile.*`（layout §7）；ArchitectureTests 断言 Mobile 不引用 `ArcNotes.*/ArcScope.*/ArcSlate.*` | 18–19、29、01.06 |

---

## 4. ArcNotes 分阶段表

| V1 面向 | 拥有步骤 | 说明 |
|---|---|---|
| 文档核心 | 10 | 运行时权威 `arcnotes.db + Managed Asset Store`；Block/文档 model、`.arcnote` 仅导入导出包。 |
| 知识检索 | 11 | 本地关键词/元数据检索与授权远端 AI Evidence。 |
| Cloud 同步 | 12/14 | revision、change feed、冲突副本与显式解决命令；**不实施 CRDT/Yjs/state vector**，也不保留未来 CRDT 兼容字段。 |
| Edgeless | 15 | | 
| 多视图 Database | 16 | 类型化属性/Typed Database 与多视图。 |
| Slides | 17 | Frame / 演示模式。 |

同步只使用 revision + change feed + conflict copy + explicit resolution；`CRDT / Yjs / awareness / state vector` 全程 Drop。

---

## 5. Android / iOS / Web 状态冻结

### 5.1 Android 边界规则

验证：17 合同测试 + 02 PublicApi/Realtime 合同。

- 完整远程 Chat/Task/Approval/Steering 控制面。
- **所有远程业务通信全经 ArcForges 服务器**。
- **禁直连 LAN / Named Pipe / UDS / 专业 App**。
- 专业对象仅以 `ResourceRef` / `ArtifactRef` / `Preview` / `Summary` 出现。

### 5.2 iOS 状态

- **完整 MAUI 架构但 Planned / Build Deferred**——当前不编译。
- 规划中必须落实：Scene 生命周期、APNs、Universal Link、Keychain、Passkey、Biometrics、Privacy Manifest、Signing/Provisioning、测试策略。
- 真实实现位置 = 唯一 Head `src/Mobile/ArcChat.Mobile/Platforms/iOS/`（layout §7）；01.06 创建条件源码与资源骨架（`EnableIosTarget=false` 时 target 不进入构建图）。

### 5.3 Web 边界

- standalone Blazor WebAssembly 只是浏览器 UI；静态托管后只调用 Cloud HTTP/JSON 与 SignalR。
- **不使用** Blazor Server circuit、Node/TypeScript/React/TypeSpec/Workers；**不在浏览器运行 Agent**。
- 与其余产品同 monorepo（当前 `monorepo` 归属），恰有 layout §8 的 9 个 `ArcForges.Web.*` 项目；Step 29 完成官网、Account Portal、ArcChat Web Companion、浏览器安全、测试、部署与回滚。

---

## 6. 商业模型快照

仅登记**已确认**的产品规则（README §2 与产品方向§/`product-direction-and-decisions.md`）；未确认项不作为"未来"范围悄悄保留。

- 全产品家族 AGPL-3.0-only（UD-LIC-1）。
- 单用户 `WorkspaceId` 作为数据、设备、计费、同步和权限边界。
- **Drop**：多人协同、组织/团队成员关系、Team Mode、多 Agent 委派（均明确排除，不保留为未来范围）。
- Cloud 为 JIT 模块化单体；Billing（Paddle 买家 MoR / Payoneer 卖家结算）按架构事实登记，不在本步铺开。
- 本步不输出：工期 / 人数 / 成本 / 甘特图 / 虚构发布日期。

---

## 7. 一致性核验

Step 00.00 的 Testing requirements 断言（本步已逐条执行并记录证据，见 ledger）：

1. 产品冻结表行数 == README §2 行数且 ProductId 集合逐字相等（`arcchat,arcnotes,arcscope,arcslate,arcchat-mobile,arcforges-cloud,arcforges-web`）。
2. 每个 ProductId 至少 1 个拥有步骤。
3. 规划目录全文 grep `ArcImage`：命中行全部含"退出/不迁入"语境（白名单断言），目标项目/Namespace 命名零命中。
4. ArcNotes `Edgeless`/`Database`/`Slides` 分别命中拥有步骤 15/16/17。
5. 7 条产品自治不变式每行"强制步骤"列非空。