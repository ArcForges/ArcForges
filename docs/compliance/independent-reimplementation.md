# Independent-Reimplementation Manifest (独立实现清单)

> First-batch structure + entries (authority: `license-and-reuse-matrix.md` §6.3, Step 00.04). Rows for AGPL / commercial-restricted sources that must be implemented clean-room in C#, with `NoSourceCopyProof` and a `ValidationOracle` (O3/O4). `BehaviorSpecPaths` records the spec/behavior source (not source code snippets).

Field set: `ItemId | SourceRepo | WhyIndependent | BehaviorSpecPaths | TargetProduct | TargetProject | NoSourceCopyProof | ValidationOracle | Status`.

| ItemId | SourceRepo | WhyIndependent | BehaviorSpecPaths | TargetProduct | TargetProject | NoSourceCopyProof | ValidationOracle | Status |
|---|---|---|---|---|---|---|---|---|
| IR-0001 | siyuan | UD-LIC-3（AGPL） | `kernel/**` API 行为组 + `app/**` 前端行为组（文档/引用/搜索/导入导出/历史/同步/资产/模板/闪卡/发布/加密） | ArcNotes | `ArcNotes.Domain` / `ArcNotes.Application` | 代码审查 + 无源码片段金样（仅输入/输出对）+ 独立实现测试套件 | O3 | First batch (planned) |
| IR-0002 | Serial-Studio Pro | UD-LIC-5（LicenseRef-SerialStudio-Commercial + 反克隆条款） | 公开协议标准（MQTT/Modbus/CAN/UART/TCP/UDP/Serial）+ 公开行为 + ArcForges 产品规格 | ArcScope | `ArcScope.Infrastructure` / `ArcScope.Domain` | 基于公开标准/行为从头 C# 实现；不复制 Pro 实现表达/资源/品牌/激活 | O4 | First batch (planned) |
| IR-0003 | AFFiNE (packages/backend) EE | UD-LIC-4（EE 商业许可） | Prisma 57 表模式 / clock-based sync / permission evaluator / blob 两阶段 GC / entitlement→quota 投影 / Passkey·OTP auth / socket.io 同步 模式 | ArcForges Cloud | `ArcForges.Cloud.Modules.*` | ASP.NET Core/Aspire 独立实现；不复制 EE 代码，避免衍生作品风险 | O3 | First batch (planned) |