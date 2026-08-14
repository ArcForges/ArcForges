# License & Reuse Matrix — quick reference

> **Quick reference for cross-checking any port/reuse decision.** The authoritative single source of truth is
> `license-and-reuse-matrix.md`; where that file and this summary conflict, `license-and-reuse-matrix.md` wins
> and this summary must be reconciled. No reuse action in any numbered step may contradict the frozen decisions
> below. All evidence paths are `Test-Path`-verifiable at the frozen source baselines (`source-baseline.md` §1).

---

## 1. User-decision cards UD-LIC-1..5

| ID | 决定文本 | 文件级证据 | 约束清单 | 影响步骤 |
|---|---|---|---|---|
| **UD-LIC-1** | ArcForges 全产品家族 **AGPL-3.0-only** | 用户明确告知（来源文档可能未写明）+ ArcForges Stages Stage 11（"ArcForges 自身 = AGPL-3.0-only"）；无来源文件证据（是本产品自身许可，非来源决定） | 全家族 AGPL-3.0-only；所有移植来源派生文件不能错误标成纯原创 AGPL；网络交互义务见 §3 | 01.00 根 `LICENSE` + 每文件 SPDX 头；12/26 Cloud Source 义务；30/31 NOTICE 与发布门禁 |
| **UD-LIC-2** | 除 siyuan 与商业专有部分外，其余获授权来源逻辑原则上可按 C#/Avalonia 移植 | AGPL §13（与 GPL-3.0 链接/组合合法）兼容性结论；各来源 LICENSE 全文 | 移植不删原文件许可证覆盖/SPDX/版权/来源 commit/NOTICE 与源码义务；GPL 覆盖派生文件保留 provenance | 全部 Copy 行；Serial-Studio GPL 核心、ArcVideo/Foundation 移植 |
| **UD-LIC-3** | siyuan（AGPL）= **独立 C# 实现**（例外） | `siyuan/LICENSE` AGPL v3 全文；用户决定（product-direction §12） | 只记行为规格；金样只取输入/输出对；不复制源码片段；独立实现证明交 Step 30/31 | ArcNotes Steps 10–15；Independent-Reimplementation-Manifest |
| **UD-LIC-4** | AFFiNE 后端（EE）= **行为/数据模型参考，不做代码移植** | `AFFiNE/packages/backend/server/LICENSE`（EE 全文：生产需有效 EE 订阅与座位数；禁止复制/合并/发布/分发/再许可）；`packages/common/native/LICENSE` 同 EE；blocksuite MIT 除外正常移植 | 只参考 pattern；C# 独立实现；避免衍生作品风险；blocksuite（MIT）可移植 | Cloud Step 12/26；blocksuite 行（MIT）；AFFINE-BE 行全 ReferenceOnly |
| **UD-LIC-5** | ArcScope 全功能实现；Serial-Studio **GPL 核心可移植，纯商业 Pro 独立 C# 实现** | Serial-Studio Pro 182 纯商业文件（`LicenseRef-SerialStudio-Commercial`）；CMake `BUILD_COMMERCIAL` 门控；商业 EULA/l`LICENSE.md` §7（反克隆 + 品牌重绘条款） | Pro 模块只基于公开协议标准/行为/ArcForges 规格独立设计；不复制实现表达/资源/品牌/激活；发布前法务审查 | ArcScope Steps 21–22；Final-production-gate 合规收口 |

---

## 2. Evidence list（文件级，全部 `Test-Path` 可核验；recomputed 2026-08-14）

| Evidence | Path (frozen baseline) | Observed fact |
|---|---|---|
| AionUi Apache-2.0 全文 | `AionUi/LICENSE` | 首行 "Apache License Version 2.0, January 2004" |
| AionUi SPDX 头统计 | `AionUi/**/*.ts,*.tsx` | recomputed 742/1238 带 `SPDX-License-Identifier: Apache-2.0`（矩阵登记 519/733 为 desktop-src 子集） |
| AionUi mobile SPDX | `AionUi/mobile/src/constants/agentModes.ts:1-5` | `SPDX-License-Identifier: Apache-2.0` |
| AFFiNE 根许可 | `AFFiNE/LICENSE`（+ `LICENSE-MIT`） | 除 EE 目录外为 MIT（"Content outside of the above mentioned directories … available under the "MIT" license as defined in LICENSE-MIT"） |
| AFFiNE backend EE | `AFFiNE/packages/backend/server/LICENSE` | The AFFiNE Enterprise Edition (EE) License |
| AFFiNE native EE | `AFFiNE/packages/common/native/LICENSE` | 同 EE |
| AFFiNE blocksuite MIT | `AFFiNE/blocksuite/**/package.json` | recomputed 大量 `"license":"MIT"`（≥68；抽查 5 文件按 check-license 脚本） |
| siyuan AGPL 全文 | `siyuan/LICENSE` | "GNU AFFERO GENERAL PUBLIC LICENSE Version 3, 19 November 2007" |
| siyuan 外观子许可 | `siyuan/app/appearance/LICENSE` | MIT License |
| Serial-Studio 双许可/License 全文 | `Serial-Studio/LICENSE.md` | "Serial Studio License Agreement"; §7 Trademark & Forking Policy（fork 须完全 rebrand，Pro 排除） |
| Serial-Studio SPDX 统计 | `Serial-Studio/app/src/**` | recomputed 475 文件带 SPDX；473 带 `LicenseRef-SerialStudio-Commercial`（矩阵登记 482：291 dual / 182 纯商业 / 9 无标记 audit debt） |
| Serial-Studio BUILD_COMMERCIAL | `Serial-Studio/CMakeLists.txt` | `option(BUILD_COMMERCIAL …)`，guard 禁 BUILD_COMMERCIAL+BUILD_GPL3 同时；Pro 边界门控 |
| ArcVideo GPL-3.0 全文 | `ArcVideo/LICENSE` | "GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007" |
| ArcVideoFoundation GPL-3.0 全文 | `ArcVideoFoundation/LICENSE` | 同上 |

> `C:\MyFile\ArcForges\StartArcForges` is a static read-only packaged-product Oracle: only file names, sizes,
> version resources, signature, imports/dependency closure are inspected; its evidence is recorded with a hash
> and marked **`NotExecuted`** — nothing is launched, and it is not part of the six-repo Source Coverage
> denominator.

---

## 3. AGPL-3.0 obligations → owning step

| AGPL 义务 | 含义 | 落点/拥有步骤 |
|---|---|---|
| Copyleft | 全产品 AGPL-3.0-only | 01.00 根 `LICENSE` + 每文件 SPDX 头；30/31 |
| §13 网络义务（ArcForges Cloud 主动提供 Corresponding Source） | 经网络服务的修改版须提供源码获得途径（超 AGPL 最低要求，Stage 11） | `arcforges.com/open-source` + Account/About → Source Code：Steps 12/26/29 落入口、30/31 门禁 |
| 来源归属 | 移植来源保留版权/许可文本/NOTICE/修改说明 | 每产品 `NOTICE.md`/`THIRD_PARTY_NOTICES` → 30/31 |
| 商标隔离 | AGPL 不覆盖商标/品牌 | Serial-Studio `LICENSE.md` §7（fork 禁使用品牌）；AFFiNE/Olive/AionUi 商标不得用于产品名/Logo/营销 → 00.03 黑名单检查 + 30/31 |
| 资源许可 | 资源按自身许可；可疑来源资源须替换 | AionUi `hello-kitty.png`/`misaka-mikoto-theme.png` 等第三方 IP 封面 Replace（重绘）；Serial-Studio 图标重绘 → Copied-Asset 排除节 + 30/31 |

---

## 4. DecisionClass ↔ Manifest mapping

| DecisionClass | 落点 | 说明 |
|---|---|---|
| `Copy` | Copied-Code（或 Copied-Asset）Manifest | 语义移植，保留归属/NOTICE |
| `Rewrite`（UI 框架/平台重写） | Copied-Code（语义移植部分）+ Notes 标 Rewrite | React→Avalonia、Qt→Avalonia、RN→MAUI |
| `Rewrite`（独立实现，AGPL/商业受限） | Independent-Reimplementation-Manifest | siyuan、Serial-Studio Pro 等 |
| `Replace` | Replacement-Backlog（.NET 替代 vendored 库）或 Independent-Reimplementation（Pro 模块） | QuaZip→System.IO.Compression 等；Pro 独立实现 |
| `ReferenceOnly`（目标=独立实现时） | 不进 Copied Manifest；行为规格路径记入 Independent-Reimplementation-Manifest 的 `BehaviorSpecPaths` | siyuan、AFFiNE EE 后端、aioncore |
| `Drop`/`Defer` | 清单行 Notes + Defer 拥有步骤 | Yjs/CRDT、Team/Multi-Agent 等 Drop |

---

## 5. Release compliance closure（license-and-reuse-matrix.md §8 → final-production-gate.md）

| # | Compliance item | FG row | Owning steps |
|---|---|---|---|
| 1 | Copied-Code / Copied-Asset / Independent-Reimplementation / Third-Party-License-Register 全部完整 | FG.0, FG.8 | 30,31 |
| 2 | 每产品 NOTICE.md / THIRD_PARTY_NOTICES 含全部移植来源归属（Apache/MIT/GPL/BSD/Public Domain） | FG.8, FG.9 | 30,31 |
| 3 | AGPL §13：Cloud 与 Web 网络界面提供同版本 Corresponding Source 途径；静态 Web release manifest 绑定源码 commit/source archive | FG.7, FG.8 | 12,26,29,30,31 |
| 4 | 商标清查：无 Serial-Studio / AFFiNE / Olive / AionUi 商标残留于产品名/Logo/营销 | FG.8, FG.9 | 00,30,31 |
| 5 | 可疑资源替换完成（AionUi 第三方 IP 主题封面、Serial-Studio 图标） | FG.5, FG.9 | 00,30,31 |
| 6 | Serial-Studio Pro 独立实现确认（无商业源码复制）；建议法务审查反克隆条款处置 | FG.6, FG.9 | 21,22,30,31 |
| 7 | SBOM 完整、漏洞扫描通过、Secret 扫描通过 | FG.8, FG.9 | 30,31 |
| 8 | siyuan 独立实现确认（无 AGPL 源码复制进 ArcNotes） | FG.6, FG.9 | 10–15,30,31 |

---

## 6. Verification

- `docs/tools/check-license.ps1` asserts: every evidence path above `Test-Path` true（AFFiNE EE×2 与 blocksuite MIT 抽查 ≥5 个 `package.json`）；`license-and-reuse-matrix.md` §2 每来源行"确切许可证/复用决策/移植方式/关键约束"四列非空及 §3 vendored 每行决策非空；trademark blacklist regex `serial.?studio|affine|olive|aionui`（不区分大小写）对目标命名集零命中（仅允许出现在证据/归属说明语境）；Pro/EE 隔离（SS-PRO 全 Replace、AFFINE-BE 全 ReferenceOnly）。
- Reverse evidence: marking one `AF-F-SS-PRO-*` as `Copy` fails the Pro-isolation assertion, citing UD-LIC-5.