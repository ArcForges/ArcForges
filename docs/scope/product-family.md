# Product Family & Scope Freeze（产品组合冻结）

> 范围：ArcForges Step 00.00 产物。本文件把 `README.md` §1/§2 与
> `implementation-repository-layout.md` §14.1 的产品集冻结成**可机械核验**的范围文件，
> 并给每个产品自治不变式指定“由哪一步强制”。权威仍为 `README.md` §2 与
> `product-direction-and-decisions.md`；本文件是目标仓库侧的证据冻结，不替代规划权威。
>
> 本步只写 docs；不产生任何 `.slnx`/`.csproj`/C#/XAML/构建脚本/CI 文件。当前实现仓库中
> 已存在的 Step 01 骨架不被本步重做或推翻，只在本文件中作为范围事实被引用。

## 1. 产品冻结表

| 产品名 | 稳定身份 ProductId | 定位 | 平台与 RID | 运行时/宿主 | 优先级 | 拥有步骤 |
|---|---|---|---|---|---|---|
| ArcChat | `arcchat` | AI Agent Command Center + Chat + Task Center + 本机 Hub + 远程控制面 | `win-x64`,`win-arm64`,`osx-x64`,`osx-arm64`,`linux-x64`（`linux-arm64` 后续） | Avalonia `12.1.1` + .NET 10 **Native AOT** | 核心 | 08,09（+Hub 协调面 08） |
| ArcNotes | `arcnotes` | Local-first 专业知识与文档工作台 | 同上五 RID | Avalonia `12.1.1` + Native AOT | 核心 | 10–11、14–17 |
| ArcScope | `arcscope` | Local-first 数据采集、观测、遥测分析工作台 | 同上五 RID | Avalonia `12.1.1` + Native AOT + 原生设备互操作 | 核心 | 07、21–22 |
| ArcSlate | `arcslate` | Local-first 专业非线性视频编辑 | 同上五 RID | Avalonia `12.1.1` + Native AOT + FFmpeg/OTIO/图像与音频原生层 | 核心 | 07、23–25 |
| ArcChat Mobile | `arcchat-mobile` | 远程 Chat、Task、Approval、Steering 控制面 | Android（MAUI Mono AOT，正式交付）；iOS（完整架构、构建延期） | .NET MAUI；Android Mono AOT Release，iOS Planned/Build Deferred | 核心 | 18–20 |
| ArcForges Cloud | `arcforges-cloud` | JIT ASP.NET Core 模块化单体、单 Agent Harness、同步与远程控制 | 服务器（OCI 镜像） | Aspire + PostgreSQL + 对象存储；JIT ASP.NET Core | 核心 | 12–14、26 |
| ArcForges Web | `arcforges-web` | standalone Blazor WebAssembly 浏览器 UI，调用 Cloud HTTP/JSON 与 SignalR | 浏览器（静态托管） | standalone Blazor WebAssembly，`PublishTrimmed=true`、`RunAOTCompilation=false` | 核心 | 29 |

ProductId 集合（逐字）：`arcchat, arcnotes, arcscope, arcslate, arcchat-mobile, arcforges-cloud, arcforges-web`。

桌面五 RID 固定为 `win-x64`,`win-arm64`,`osx-x64`,`osx-arm64`,`linux-x64`；`linux-arm64` 为后续扩展，不在 V1 五 RID 之内。Windows executable、Bundle/Application ID 与根 Namespace 见 `implementation-repository-layout.md` §14.1，本文件不重复维护可漂移副本。

## 2. 退出与继承表

| 项 | 处置 | 说明 / 拥有步骤 |
|---|---|---|
| `ArcImage` | **退出当前产品基线** | `FutureAllCSharp.md` 的 ArcImage 概念不迁入；ArcScope 是全新产品，不复用 ArcImage 领域概念。本行同时是 grep 白名单的**唯一**合法出现语境（“已退出”说明）。目标产品/项目/Namespace/步骤标题中零命中。 |
| `ArcVideo` → `ArcSlate` | 方向继承 | Olive 系行为参考 + GPL-3.0 移植语义（AGPL §13 兼容）；方向继承而非二进制复用。拥有步骤 23–25 / 探针 07。 |
| `ArcVideoFoundation` → `ArcSlate` | 方向继承 | `rational`/`TimeRange`/`Timecode`/`Color`/`Bezier`/`SampleBuffer` 行为参考；纯 C# 值类型或 owned 窄 C ABI，绝不跨 C++ ABI。拥有步骤 23–25 / 探针 07。 |

## 3. 产品自治不变式

逐条落为可核验行（README §2）。每行的“强制步骤”列非空。

| # | 不变式 | 含义 | 验证方法 | 强制步骤 |
|---|---|---|---|---|
| 1 | 每桌面产品是完整自治 OS 应用 | 各自拥有 Domain、durable state、数据库/文件、事务与恢复、Undo/历史、发布生命周期 | ArchitectureTests（01.06）+ 每产品独立 `*.db`（layout §14.2）+ 各自 publish 列车（31） | 01.06、04、31 |
| 2 | 不存在共享可写业务数据库 | 跨产品 Infrastructure 直引被禁；Cloud PostgreSQL 逻辑 schema 分模块，禁每模块一库也禁产品共享业务库 | ArchitectureTests 禁跨产品 Infrastructure 直引（01.06）+ Cloud schema 分模块、layout §6/§11 禁共享业务库 | 01.06、12、26 |
| 3 | 不存在本机中央服务或本机 Agent 进程 | ArcChat Desktop 自身承载 Local Hub、MCP Client、远程工具桥、权限和审批；不持有专业产品正文，也不承载模型循环 | 进程拓扑测试、项目引用测试、OS 进程 E2E；安装/进程树无 AgentHost/daemon/service/Worker | 01.06、08、30、31 |
| 4 | 专业 App 核心本地功能不依赖 ArcChat、不依赖 Account/Cloud | 离线可用核心功能；启动不等 ArcChat/Cloud | 05 Domain 无外部依赖 + 10/18/19 的“无 ArcChat/无 Cloud 启动并可用核心功能”集成测试（引用 00.00 不变式编号） | 05、10、18、19 |
| 5 | 跨 App 传语义 Capability/Reference，不远程操作 UI | 传 `ResourceRef`/`ArtifactRef`；大资源留所有者一侧，Hub 不代理视频帧/大对象 | Contracts 纯净测试（02）+ 合同无裸字节/帧字段（02.02/02.04 金样） | 02、08 |
| 6 | 专业 App 可直接参与自己的 Cloud 同步；Cloud Agent 如需本机能力，只能创建持久 `ToolRequest` | 由 ArcChat Desktop 拉取、重新授权、执行并回传；不直连 localhost/Pipe/UDS/stdio | Step 14 的断线、重复、拒绝和恢复 E2E | 14 |
| 7 | Mobile/Web 当前是 ArcChat Companion，不是 ArcNotes/ArcScope/ArcSlate 的手机版/编辑器 | Mobile 项目清单仅 `ArcChat.Mobile.*`（layout §7）；ArchitectureTests 断言 Mobile 不引用 `ArcNotes.*/ArcScope.*/ArcSlate.*` | ArchitectureTests（01.06）+ Mobile 项目清单闭合 | 01.06、18、19 |

## 4. ArcNotes 分阶段表

| 阶段 | 范围 | 拥有步骤 |
|---|---|---|
| V1 文档核心 | 文档/Block 基础 | 10 |
| 知识检索 | 关键词/元数据检索与授权远端 AI Evidence | 11 |
| Cloud 同步 | revision + change feed + 冲突副本 + 显式解决命令 | 12、14 |
| Edgeless | 画布 | 15 |
| 多视图 Database | Typed Property / 视图 | 16 |
| Slides | Frame / 演示模式 | 17 |

ArcNotes 同步使用 revision、change feed、冲突副本与显式解决命令；**不实施 CRDT/Yjs/state vector**，也不保留“未来 CRDT 兼容”字段或空实现。

## 5. Android / iOS / Web 状态冻结

### 5.1 Android

- 正式交付：完整远程 Chat/Task/Approval/Steering 控制面。
- **所有远程业务通信全经 ArcForges 服务器**；**禁直连 LAN/Named Pipe/UDS/专业 App**。
- 专业对象仅以 `ResourceRef`/`ArtifactRef`/Preview/Summary 出现。
- 运行时为 MAUI Mono AOT Release（**不称 CoreCLR Native AOT**）。
- 验证：17 合同测试 + 02 PublicApi/Realtime 合同；Android 22 场景恢复矩阵（`FG.5`）。

### 5.2 iOS

- **完整 MAUI 架构但 Planned / Build Deferred**——当前不编译，不声称已验证。
- 必须在规划中落实：Scene 生命周期、APNs、Universal Link、Keychain、Passkey、Biometrics、Privacy Manifest、Signing/Provisioning、测试策略。
- 真实实现位置 = 唯一 Head `src/Mobile/ArcChat.Mobile/Platforms/iOS/`（layout §7）。
- 01.06 创建条件源码与资源骨架（`EnableIosTarget=false` 时 target 不进入构建图）。
- 验证：只验证架构覆盖与“未编译”负门禁，不制造 build/test 结果。

### 5.3 Web

- standalone Blazor WebAssembly 只是浏览器 UI；静态托管后只调用 Cloud HTTP/JSON 与 SignalR。
- **不使用** Blazor Server circuit、Node/TypeScript/React/TypeSpec/Workers，也不在浏览器运行 Agent。
- 唯一项目集合 = 9 个（layout §8）：`ArcForges.Web.Application`、`ArcForges.Web.Infrastructure`、`ArcForges.Web.Components`、`ArcForges.Web.App`、`ArcForges.Web.SiteGenerator` + `tests/Web` 的 `ArcForges.Web.UnitTests`、`ArcForges.Web.ComponentTests`、`ArcForges.Web.ContractTests`、`ArcForges.Web.BrowserTests`。
- V1 固定 `RunAOTCompilation=false`、`PublishTrimmed=true`、`InvariantGlobalization=false`。
- 验证：FG.7 九项目闭合 + 依赖方向 ArchitectureTests。

## 6. 商业模型快照

只登记已确认的产品规则：

- ArcForges 全产品家族自身采用 **AGPL-3.0-only**（UD-LIC-1）。
- 商业边界以 Paddle 作为买家 Billing Provider（`checkoutKind=web_payment_link` Desktop/Web、`mobile_hosted` Android），Payoneer 仅作 seller-global 结算，不是买家 Provider 或 Entitlement Source。
- Cloud Subscription/CloudPass/Credits/Usage/BYOK Entitlement 由 `ArcForges.Cloud.Modules.Billing/Entitlement` 拥有（layout §6）。
- **明确 Drop（不得作为“未来”范围悄悄保留）**：多人协同、组织/团队成员关系、Team Mode、多 Agent 委派、BackgroundAgents、handoff、Agent Team。

## 7. 不输出清单

本文件不输出、且 Step 00 任何产物不输出：工期、人数、成本、甘特图、虚构发布日期（README §3.3 / `product-direction-and-decisions.md` 禁止）。

## 8. 反向失败证据（Completion Gate 自检）

- 删除任一 Web 项目，或手工插入 ArcImage 作为目标行（违反“ArcImage 不得成为目标”） → `docs/tools/check-scope.ps1` 失败并指认 README/layout 不一致。
- 将 ArcNotes `Edgeless`/`Database`/`Slides` 的拥有步骤改为非 15/16/17 → 脚本失败。
- 将任一不变式“强制步骤”列清空 → 脚本失败。
- ProductId 集合与 README §1 不逐字相等 → 脚本失败。
