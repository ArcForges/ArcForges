# License Summary — 许可证与复用矩阵快速参照

> **权威来源**：本文件是 `license-and-reuse-matrix.md` 的快速参照与文件级证据冻结；权威仍为该矩阵与 `source-coverage-register.md`。本文件不引入新许可证结论，不构成法律意见；正式发布前法务审查见 `final-production-gate.md`。
> 所有许可证结论附**文件级证据路径**，可 `Test-Path` 核验；AGPL 兼容性结论引用 AGPL §13。核验脚本：`docs/tools/check-license.ps1`。

---

## 1. UD-LIC 决定卡（用户已锁定）

| ID | 决定文本 | 文件级证据 | 约束清单 | 影响步骤 |
|---|---|---|---|---|
| UD-LIC-1 | ArcForges 全产品家族本身采用 **AGPL-3.0-only** 开源许可（覆盖 ArcChat/ArcNotes/ArcScope/ArcSlate 桌面、ArcChat Mobile、ArcForges Web、ArcForges Cloud Server） | `AionUiReWrite` 无涉；用户明确 + `ArcForges-stages.md` Stage 11 | 全家族根 `LICENSE`=AGPL-3.0-only；每文件 SPDX 头 | 01.00 LICENSE/SPDX 头、12/26 Cloud Source 义务、30/31 NOTICE 与发布门禁 |
| UD-LIC-2 | 除 siyuan 与商业专有部分外，其余获授权来源逻辑原则上可按 C#/Avalonia 移植，保留归属 | AGPL §13 与 GPL-3.0 链接/组合合法 | 移植不删原文件许可证覆盖/SPDX/版权/来源 commit/NOTICE/源码义务；GPL 派生文件不误标纯 AGPL | 全部 Copy 行 |
| UD-LIC-3 | siyuan（AGPL）→ 独立 C# 实现，不复制源码 | `siyuan/LICENSE` GNU AGPL v3 全文 + 用户决定 | 只取行为规格；金样仅输入/输出，无源码片段 | ArcNotes Step 10–15、Independent-Reimplementation-Manifest |
| UD-LIC-4 | AFFiNE 后端 EE（商业）→ 行为/数据模型参考，不移植代码 | `AFFiNE/packages/backend/server/LICENSE` EE 全文（生产需有效 EE 订阅与座位数、禁复制/合并/发布/分发/再许可）；`packages/common/native/LICENSE` 同 EE；blocksuite MIT 除外 | EE 代码不可移植；C# 独立实现；避免衍生作品风险 | Cloud Step 12/26 |
| UD-LIC-5 | ArcScope 全实现；Serial-Studio GPL 核心可移植，纯商业 Pro 从头独立 C# 实现 | 182 纯商业文件 + Serial-Studio `CMakeLists.txt` `BUILD_COMMERCIAL` 门控 + 商业 EULA §4 反克隆条款位置 | Pro 只基于公开标准/行为/ArcForges 规格独立实现；不复制表达/资源/品牌/激活 | ArcScope Step 21–22、发布前法务审查→`final-production-gate.md` |

---

## 2. 文件级证据清单（全部 `Test-Path` 可核验）

| 证据 | 路径 | 说明 |
|---|---|---|
| AionUi Apache-2.0 全文 | `C:\MyFile\ArcForges\AionUi\LICENSE` | 首行 "Apache License Version 2.0, January 2004" |
| AionUi SPDX 头 | 519/733 个 TS/TSX 带 `SPDX-License-Identifier: Apache-2.0` | |
| AionUi mobile SPDX | `mobile/src/constants/agentModes.ts:1-5` | `SPDX-License-Identifier: Apache-2.0`（实测） |
| AFFiNE 根授权 | `AFFiNE/LICENSE`（backend/common-native 之外按 `LICENSE-MIT`）；`AFFiNE/LICENSE-MIT` | |
| AFFiNE blocksuite MIT | blocksuite 68+ 个 `package.json` `"license":"MIT"`（实测≥68；抽样 5 个 `affine/all`、`affine/blocks/{attachment,bookmark,callout,code}/package.json`） | |
| AFFiNE EE ×2 | `packages/backend/server/LICENSE`、`packages/common/native/LICENSE` | EE 全文 |
| siyuan AGPL | `siyuan/LICENSE`（GNU AGPL v3 全文）+ `app/appearance/LICENSE` | |
| Serial-Studio SPDX | SPDX 实测 482 文件：291 双许可 / 182 纯商业 / 9 无标记 audit debt | |
| Serial-Studio BUILD_COMMERCIAL | `Serial-Studio/CMakeLists.txt` `option(BUILD_COMMERCIAL ...)` 门控 | |
| ArcVideo / Foundation GPL-3.0 | `ArcVideo/LICENSE`、`ArcVideoFoundation/LICENSE`（GNU GPL v3 全文 ×2） | |
| Packaged oracle | `C:\MyFile\ArcForges\StartArcForges` | 只读静态发布物/文件布局 Oracle；`NotExecuted`（不启动任何 executable/service/installer/updater/subprocess） |

---

## 3. AGPL 义务 → 拥有步骤表

| 义务 | 含义 / 落点 | 拥有步骤 |
|---|---|---|
| Copyleft | 全产品 AGPL-3.0-only → 01.00 根 `LICENSE` + 每文件 SPDX 头 | 01.00 |
| §13 网络义务 | ArcForges Cloud 主动提供 Corresponding Source：`arcforges.com/open-source` + Account/About → Source Code | 12/26/29 落入口、30/31 门禁 |
| 来源归属 | 每产品 `NOTICE.md` / `THIRD_PARTY_NOTICES` | 30/31 |
| 商标隔离 | Serial-Studio LICENSE §7 禁 fork 用其品牌；AFFiNE/Olive/AionUi 商标不得用于产品名/Logo/营销 | 00.03 黑名单检查 + 30 |
| 资源许可 | 疑涉第三方 IP 主题封面 Replace 重绘、Serial-Studio 图标重绘 | Copied-Asset 排除节 + 30/31 |

---

## 4. 决策类别 ↔ Manifest 映射

| 决策类别 | Manifest 落点 |
|---|---|
| `Copy`（移植语义） | Copied-Code-Manifest / Copied-Asset-Manifest |
| `Rewrite`（UI 框架/平台重写） | Copied-Code（语义移植部分）+ Notes 标 Rewrite |
| `Rewrite`（独立实现） | Independent-Reimplementation-Manifest |
| `Replace` | Replacement-Backlog（.NET 替代 vendored 库）或 Independent-Reimplementation（Pro 模块） |
| `ReferenceOnly` | 不进 Copied Manifest；行为规格路径记入 Independent-Reimplementation-Manifest 的 `BehaviorSpecPaths`（当目标为独立实现时） |
| `Drop` / `Defer` | 清单行 Notes + Defer 拥有步骤 |

---

## 5. 发布合规收口（§8 → `final-production-gate.md` 绑定）

| # | 收口项 | FG / 拥有步骤 |
|---|---|---|
| 1 | Copied-Code / Copied-Asset / Independent-Reimplementation / Third-Party-License-Register 全部完整 | FG.0、FG.8；Steps 02–31 持续 |
| 2 | 每产品 `NOTICE.md` / `THIRD_PARTY_NOTICES` 含全部移植来源归属（Apache-2.0/MIT/GPL-3.0/BSD/公有领域） | FG.10；Steps 30/31 |
| 3 | AGPL §13 网络义务：Cloud 与 Web 网络交互界面提供同版本 Corresponding Source；静态 Web release manifest 绑定源码 commit/archive | FG.10、FG.7；Steps 12/26/29/30/31 |
| 4 | 商标清查：无 Serial-Studio/AFFiNE/Olive/AionUi 商标残留于产品名/Logo/营销 | FG.9；00.03 黑名单 + Steps 30/31 |
| 5 | 可疑资源替换完成（AionUi 第三方 IP 主题封面、Serial-Studio 图标） | FG.9；Copied-Asset 排除节 + Steps 30/31 |
| 6 | Serial-Studio Pro 独立实现确认（无商业源码复制）；建议法务审查反克隆条款 | FG.6/9；UD-LIC-5，Steps 21–22/30/31 |
| 7 | SBOM 完整、漏洞扫描通过、Secret 扫描通过 | FG.8/9；Step 31 |
| 8 | siyuan 独立实现确认（无 AGPL 源码复制进 ArcNotes） | FG.6/9；UD-LIC-3，Steps 10–15 |

---

## 6. 核验（`docs/tools/check-license.ps1`）

1. 每个证据路径 `Test-Path` 为真；AFFiNE 后端 EE LICENSE 与 blocksuite MIT 抽查 5 个 `package.json`。
2. `license-and-reuse-matrix.md` §2 每来源行"确切许可证/复用决策/移植方式/关键约束"四列非空；§3 vendored 表每行决策非空。
3. 商标黑名单检查：对 `implementation-repository-layout.md` §8 命名集与 `product-family.md` 冻结表做正则扫描（`serial.?studio|affine|olive|aionui`）→ 目标命名零命中（仅允许出现在证据/归属说明语境）。
4. Pro/EE 隔离断言：ArcScope Pro 行（`AF-F-SS-PRO-*`）Decision 全 `Replace`；AFFiNE 后端行（`AF-F-AFFINE-BE-*`）Decision 全 `ReferenceOnly`（脚本交叉 `source-subsystems.md`）。

---

## 7. 商标与 Pro/EE 隔离结论

- 目标产品命名（`implementation-repository-layout.md` §8 命名集 + `product-family.md` 冻结表）：`arcchat/arcnotes/arcscope/arcslate/arcchat-mobile/arcforges-cloud/arcforges-web` —— 对 `serial.?studio|affine|olive|aionui` 正则零命中。（本文件 §1–§3 提及 AionUi/AFFiNE/Serial-Studio/Olive 仅在证据/归属语境，不构成目标命名。）
- Pro/EE：ArcScope Pro 全部 `Replace`（UD-LIC-5）；AFFiNE 后端全部 `ReferenceOnly`（UD-LIC-4）；siyuan 全部 `ReferenceOnly`（UD-LIC-3）。`docs/tools/check-source-coverage.ps1` 已交叉验证 source-subsystems.md。