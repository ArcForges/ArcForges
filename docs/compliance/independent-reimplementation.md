# Independent-Reimplementation Manifest（独立实现清单）

> Structure per `license-and-reuse-matrix.md` §6.3；first entries per Step 00.04。For AGPL/commercial-restricted
> sources: behavior-spec paths only; **no source copy**; golden samples are input/output pairs, never code
> excerpts. Machine-readable double in `independent-reimplementation.json`.

## Fields

`ItemId | SourceRepo | WhyIndependent(UD-LIC-3/4/5) | BehaviorSpecPaths | TargetProduct | TargetProject |
NoSourceCopyProof | ValidationOracle(O3/O4) | Status`

## First entries

### IRM-0001 — siyuan → ArcNotes (UD-LIC-3)
| Field | Value |
|---|---|
| ItemId | `IRM-0001` |
| SourceRepo | `C:\MyFile\ArcForges\siyuan` @ `eef10568384e2e7cf547adb029ae46a72e43c287` |
| WhyIndependent | UD-LIC-3（AGPL，用户决定独立 C# 实现；不复制源码） |
| BehaviorSpecPaths | siyuan kernel API 组 block/reference/search/import/export/history/sync/asset/template/snippet 行为规格；app 前端/外观行为规格（均非源码摘抄） |
| TargetProduct | ArcNotes |
| TargetProject | `ArcNotes.Domain` / `ArcNotes.Application` / `ArcNotes.Editor` / `ArcNotes.Search` / `ArcNotes.ImportExport` |
| NoSourceCopyProof | 代码审查 + 无源码片段金样（金样只取输入/输出对）+ 独立实现测试套件；Step 30/31 负扫描 |
| ValidationOracle | O3（行为规格独立撰写测试用例，不引源码） |
| Status | Clean-room Planned（Step 10–15） |

### IRM-0002 — Serial-Studio Pro → ArcScope (UD-LIC-5)
| Field | Value |
|---|---|
| ItemId | `IRM-0002` |
| SourceRepo | `C:\MyFile\ArcForges\Serial-Studio` @ `639daafb2fe7d324c3b2d5583d2514c8c470676f` |
| WhyIndependent | UD-LIC-5（纯商业 Pro 非 GPL，只依据公开协议/行为/ArcForges 规格独立设计） |
| BehaviorSpecPaths | MQTT/Modbus/CAN/UART/Serial 公开协议标准、用户文档、ArcForges 产品需求与自建测试（不把 Pro 源文件作为代码 Oracle） |
| TargetProduct | ArcScope |
| TargetProject | `ArcScope.Infrastructure` / `ArcScope.Domain`（独立实现模块） |
| NoSourceCopyProof | 代码审查 + 公开协议 conformance 测试（不复制商业实现表达/资源/品牌/激活） |
| ValidationOracle | O4（公开协议标准一致性） |
| Status | Clean-room Planned（Step 21–22） |

### IRM-0003 — AFFiNE EE backend → ArcForges Cloud (UD-LIC-4)
| Field | Value |
|---|---|
| ItemId | `IRM-0003` |
| SourceRepo | `C:\MyFile\ArcForges\AFFiNE` @ `81df4751a367f2795bc0d165586650dbe8db73d6`（EE 目录） |
| WhyIndependent | UD-LIC-4（EE 商业许可，禁止复制/合并/发布/分发/再许可；只作行为/数据模型参考） |
| BehaviorSpecPaths | Prisma 57 表 pattern、clock-based sync、permission evaluator、blob 两阶段 GC、entitlement→quota 投影、Passkey/OTP、socket.io 同步模式（均非源码） |
| TargetProduct | ArcForges Cloud |
| TargetProject | `ArcForges.Cloud.Modules.*`（ASP.NET Core 独立实现） |
| NoSourceCopyProof | 代码审查 + 无源码片段金样 + Cloud 独立实现测试套件；避免衍生作品风险 |
| ValidationOracle | O3（行为规格独立撰写） |
| Status | Clean-room Planned（Step 12/26） |