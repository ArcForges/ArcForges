# Source Baseline — 来源仓库基线核验快照与 Source Coverage 状态机

> **权威来源**：六个来源仓库的基线 commit / tag / dirty 快照以 `source-coverage-register.md` §2 为唯一事实；`WorkspaceState` 不从哪里抄写，逐次复算并与登记簿的 dirty-file/hash 快照相等。本文件只做只读核验（`git rev-parse HEAD` / `git status --porcelain` / `git describe --tags --always` / 只读 diff/hash），不修改任何来源。
> 核验时间：2026-08-15（UTC）。原始命令输出追加于 [baseline-snapshot.txt](baseline-snapshot.txt)。

---

## 1. 基线表

所有 `BaselineCommit` 逐字等于 `source-coverage-register.md` §2 / `license-and-reuse-matrix.md` §1 的冻结值。`WorkspaceState` 为本轮**逐次复算**结果（见 §2 快照）。

| 来源 | 路径 | Branch | BaselineCommit | Tag/Version | WorkspaceState | Submodules |
|---|---|---|---|---|---|---|
| AionUi | `C:\MyFile\ArcForges\AionUi` | `Branch_v2.1.35` | `29c9271a59484e4696778cb80164f705245a6186` | v2.1.35 | **dirty**（`scripts/rebuildNativeModules.js`、`tests/unit/build-scripts/windows-fast-build-script.test.ts`） | none |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `Branch_v0.27.2` | `81df4751a367f2795bc0d165586650dbe8db73d6` | v0.27.2 | clean | none |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `Branch_v3.7.3` | `eef10568384e2e7cf547adb029ae46a72e43c287` | v3.7.3 | clean | none |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `Branch_v4.0.3` | `639daafb2fe7d324c3b2d5583d2514c8c470676f` | v4.0.3 | clean | none |
| ArcVideo | `C:\MyFile\ArcForges\ArcVideo` | `main` | `caf56513278703adec0c2933ec235bb864d72e31` | — | **dirty**（`CMakeLists.txt`、`app/common/otioutils.h`） | none |
| ArcVideoFoundation | `C:\MyFile\ArcForges\ArcVideoFoundation` | `main` | `139eecaaa79dbad743a146f174a9c89a66ed594b` | — | **dirty**（`CMakeLists.txt`） | none |

---

## 2. 核验快照（只读）

对每仓库执行 `git -C <path> rev-parse HEAD`、`git -C <path> status --porcelain`、`git -C <path> describe --tags --always`，原始输出追加到 [baseline-snapshot.txt](baseline-snapshot.txt)（含 UTC 执行时间）。三个 dirty 仓库的 `DiffSha256`（Git 原始 `git diff` UTF-8 文本移除唯一末尾换行后的 SHA-256）本轮复算并与登记簿逐字相等：

- AionUi：`1f87a590859586a4b64831d54b0292117294dabaef93c71a5fe4bcd377525492` ✓
- ArcVideo：`3302eb6c34d252be675ada195461f746c8965d1c2014280df52e0d51a767030c` ✓
- ArcVideoFoundation：`9ccbbea307352499f5ad55ed6f5eb52176f5f0eff7c20df6d3e77969a9f85a96` ✓

六仓 HEAD 逐字等于冻结 commit、tag 匹配、dirty 文件集合与 DiffSha256 完全一致 → **零漂移**。命中的 Coverage/Feature 行保持 `NeedsRecheck`，不因 HEAD 未变而自动恢复为 `CrossChecked`（`source-coverage-register.md` §5 规则）。

---

## 3. Source Coverage 九态状态机

每行为一态，定义进入条件、所需证据与退出方向。任何状态转换必须先满足下一态的进入条件。

| 状态 | 进入条件 | 所需证据 | 退出方向 |
|---|---|---|---|
| `Inventoried` | 顶层目录/模块已枚举 | 目录树快照 + 模块/LOC 统计 | → Classified |
| `Classified` | 每模块已赋复用决策类别（§9.2 八类之一） | 清单行 DecisionClass 列 | → Read |
| `Read` | LICENSE 全文 + 关键入口文件已读 | 许可证证据路径 + SPDX 标注统计 | → DeepAnalyzed |
| `DeepAnalyzed` | 子系统级逐文件深读完成 | 文件范围、入口/类型/函数/测试/资源/协议/构建/许可分析记录 | → Mapped |
| `Mapped` | 全部功能行已进入 `feature-inventory-and-mapping.md` | 清单行 ID 区间 | → CrossChecked |
| `CrossChecked` | 映射 ↔ 代码 ↔ 许可证 三方核对完成 | 交叉核对记录 + 零孤立路径证明 | 终态（除非漂移） |
| `Excluded` | 明确排除（含原因与决定来源） | 排除理由（如 AionCore 不在提供目录内 → ReferenceOnly/Excluded） | 终态 |
| `NeedsRecheck` | 基线漂移或悬而未决问题 | 漂移报告 / 问题清单 | 重读后回原状态 |
| `Superseded` | 被更新基线/决定取代 | 取代指向（新 commit / 新决定 ID） | 终态 |

**当前状态纪律**：不预填"全部 DeepAnalyzed/Mapped/CrossChecked"；`ReviewedFileCount` 必须有对应分析记录，不能只来自文件枚举；`CrossChecked` 还要求功能映射、许可证证据和测试 Oracle 三方一致。生成物 / vendored 依赖 / 二进制 / 资源也必须列行（可标 `Excluded`/`ReferenceOnly` 或"仅许可证/供应链审查"），不能从分母中消失。

---

## 4. 每仓库每子系统现状表

字段固定为 `SourceRepo | RepoPath | BaselineCommit | Subsystem | IncludedGlob | ExcludedGlob | EnumeratedFileCount | ReviewedFileCount | CoverageStatus | LastVerifiedUtc | EvidencePath | RemainingRisk | Notes`。`CoverageStatus ∈` 九态集合；抽样源码路径均经 `Test-Path` 核验存在。

| SourceRepo | RepoPath | BaselineCommit | Subsystem | IncludedGlob | ExcludedGlob | EnumeratedFileCount | ReviewedFileCount | CoverageStatus | LastVerifiedUtc | EvidencePath | RemainingRisk | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AionUi | `C:\MyFile\ArcForges\AionUi` | `29c9271a…` | Desktop first-party (shell/conversation/agent/settings/IPC/DB) | `packages/desktop/src/**` | `.git/**`、`node_modules`、`bin/obj` | 1052 | 逐行映射 282 行证据 | `CrossChecked` | 2026-08-15 | `source-coverage-register.md` SC-AION-01 | none | ipcBridge 全导出成员 + 13 表 + renderer/process 目录映射；目标不保留 Node/local model runtime |
| AionUi | `C:\MyFile\ArcForges\AionUi` | `29c9271a…` | Mobile first-party/platform | `mobile/**` | `.git`、`bin/obj` | 81 | 20 行 `AF-F-AIONUI-M-*` | `CrossChecked` | 2026-08-15 | SC-AION-02 | none | 不复制 RN runtime；iOS 仅架构 |
| AionUi | `C:\MyFile\ArcForges\AionUi` | `29c9271a…` | tests/fixtures/examples | `tests/**`,`examples/**` | none | 463+79 | `AF-F-AIONUI-0283..0284` | `NeedsRecheck` | 2026-08-15 | SC-AION-03 | `tests/unit/build-scripts/windows-fast-build-script.test.ts` dirty 未复核关闭 | 作为 O1..O7 oracle |
| AionUi | `C:\MyFile\ArcForges\AionUi` | `29c9271a…` | resources/i18n/theme/icons | `resources/**`,`public/**` | none | 67+27 | `AF-F-AIONUI-0287..0288` | `CrossChecked` | 2026-08-15 | SC-AION-04 | 逐资产许可 | 品牌/IP 不明资源默认重绘(Replace) |
| AionUi | `C:\MyFile\ArcForges\AionUi` | `29c9271a…` | build/release/docs/config | `packages/shared-scripts/**`,`packages/web-cli/**`,`packages/web-host/**`,`.github/**`,`scripts/**`,`package.json`,`bun.lock`,`docs/**` | none | 3+6+17+23+36+63 | `AF-F-AIONUI-0285..0289` | `NeedsRecheck` | 2026-08-15 | SC-AION-05 | `scripts/rebuildNativeModules.js` dirty 未复核关闭；AF-F-AIONUI-0289 显式 Drop Node/aioncore/localhost launcher | ReferenceOnly/Replace/Drop |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `81df4751…` | blocksuite editor | `blocksuite/**` | `.git`、`bin/obj` | 3108 | 逐行 `AF-F-BLOCKSUITE-*`（本色核对的 `0026,0029,0034,0037,0043,0045..0065` 可 CrossChecked） | `Mapped` | 2026-08-15 | SC-AFF-01 | 其余行保持 Mapped 不得以 tracked 数量宣称 DeepAnalyzed | Yjs/CRDT/awareness 全 Drop |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `81df4751…` | frontend apps/modules | `packages/frontend/**` | none | 4552 | 84 行 `AF-F-AFFINE-FE-*` | `Mapped` | 2026-08-15 | SC-AFF-02 | 目标 Avalonia MVVM，不复制 Web runtime | Rewrite/ReferenceOnly |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `81df4751…` | backend/server (EE reference) | `packages/backend/**` | none | 1100 | `AF-F-AFFINE-BE-*`（仅 `0049` 可 CrossChecked） | `Mapped` | 2026-08-15 | SC-AFF-03 | EE clean-room，不复制 GraphQL/CRDT | ReferenceOnly；多人协作 Drop |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `81df4751…` | common/native + common | `packages/common/native/**`,`packages/common/**` | none | 25+509 | 相关 `AF-F-*` 行 | `Mapped` | 2026-08-15 | SC-AFF-04 | 必要 native 走 C ABI | ReferenceOnly/Rewrite |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `81df4751…` | tests/tools/docs/build | `tests/**`,`tools/**`,`docs/**` | none | 557+68+12 | 相关 frontend/build 行 | `Mapped` | 2026-08-15 | SC-AFF-05 | 28 binary/archive 仅 hash/license/资源处置 | ReferenceOnly/Replace |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `eef10568…` | kernel (Go backend) | `kernel/**` | `.git`、`bin/obj` | 445 | `AF-F-SIYUAN-0001..0026` | `CrossChecked` | 2026-08-15 | SC-SY-01 | 不复制 AGPL 源码，仅 Oracle O3 | ReferenceOnly |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `eef10568…` | app frontend | `app/src/**` | none | 479 | `AF-F-SIYUAN-0027..0062` | `CrossChecked` | 2026-08-15 | SC-SY-02 | 不得逐行翻译 | ReferenceOnly/Rewrite |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `eef10568…` | appearance/stage/generated | `app/appearance/**`,`app/guide/**`,`app/stage/**`,`screenshots/**` | `.git` | 112+426+543+16 | `AF-F-SIYUAN-0064..0066,0068..0075` | `CrossChecked` | 2026-08-15 | SC-SY-03 | 所有 stage JS/WebView runtime 显式 Drop，逐家族映射原生 typed renderer/fallback | ReferenceOnly/Replace/Drop |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `eef10568…` | electron/platform/config | `app/electron/**`,`app/appx/**`,`app/nsis/**`,`app/scripts/**`,`scripts/**`,CI/Docker | none | 对应 groups | `AF-F-SIYUAN-0063,0067` | `CrossChecked` | 2026-08-15 | SC-SY-04 | 目标 .NET publish/sign/update；Electron/Chromium/HTML/JS/loopback UI 不进入 Desktop | ReferenceOnly/Replace |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `eef10568…` | tests/fixtures/docs | repo/app tests、testdata、docs/changelogs | none | 全仓 69 test/testdata + 412 .md | `AF-F-SIYUAN-0063..0066` | `CrossChecked` | 2026-08-15 | SC-SY-05 | 测试行为可重建但不复制源码 | ReferenceOnly |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | app/src core/commercial | `app/src/**` | `.git`、`bin/obj` | 483 | `AF-F-SS-CORE-*`,`AF-F-SS-PRO-*` | `CrossChecked` | 2026-08-15 | SC-SS-01 | Commercial-only Pro 绝不复制 | Copy(GPL)/CleanRoom(Pro) 按 SPDX |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | QML core/Pro UI | `app/qml/**` | none | 160 | 逐文件 SPDX QML rows | `CrossChecked` | 2026-08-15 | SC-SS-02 | 品牌视觉重绘 | GPL core Copy、Pro CleanRoom |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | vendored dependency `lib/` | `lib/**` | `.git` | 1747 | 每库 `AF-F-SS-LIB-*` | `CrossChecked` | 2026-08-15 | SC-SS-03 | 无成熟 C# 绑定时窄 C ABI | 逐库 license（§3 表） |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | tests | `tests/**` | none | 94 | test closure rows | `CrossChecked` | 2026-08-15 | SC-SS-04 | 不伪称已执行 | ReferenceOnly/Rewrite |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | resources/i18n/deploy | `app/rcc/**`,`app/translations/**`,`app/deploy/**`,CMake/CI | none | 899+47+18 | resource/build rows | `CrossChecked` | 2026-08-15 | SC-SS-05 | 字体/图标/品牌逐项处置 | Rewrite/Replace |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | examples/docs | `examples/**`,`doc/**` | none | 117+120 | examples/docs rows | `CrossChecked` | 2026-08-15 | SC-SS-06 | 示例输入保留 provenance | ReferenceOnly |
| ArcVideo | `C:\MyFile\ArcForges\ArcVideo` | `caf56513…` | product source (project/node/timeline/codec/render/audio/color/task/undo) | `app/**`（除 UI/shader/packaging） | `.git`、`bin/obj` | 2362 | `AF-F-ARCV-0001..0066` | `NeedsRecheck` | 2026-08-15 | SC-AV-01 | `app/common/otioutils.h` dirty 未复核关闭（AF-F-ARCV-0065） | Copy/Rewrite；GPL-3.0 |
| ArcVideo | `C:\MyFile\ArcForges\ArcVideo` | `caf56513…` | UI/shader/generated assets | `app/ui/**`,`app/shaders/**` | none | 1472+41 | `AF-F-ARCV-0067..0072` | `CrossChecked` | 2026-08-15 | SC-AV-02 | 品牌图形重绘，生成样式不逐字移植 | Copy shader where licensed / Replace brand |
| ArcVideo | `C:\MyFile\ArcForges\ArcVideo` | `caf56513…` | tests/fixtures | `tests/**` | none | 8 | ArcVideo test rows | `CrossChecked` | 2026-08-15 | SC-AV-03 | 不伪称已执行 | ReferenceOnly/Rewrite |
| ArcVideo | `C:\MyFile\ArcForges\ArcVideo` | `caf56513…` | build/package/release/docs | `app/packaging/**`,`cmake/**`,`docker/**`,root CMake/presets/CI | none | 29+9+19 | `AF-F-ARCV-0067..0072` | `NeedsRecheck` | 2026-08-15 | SC-AV-04 | root `CMakeLists.txt` dirty 未复核关闭（AF-F-ARCV-0069） | ReferenceOnly/Replace |
| ArcVideoFoundation | `C:\MyFile\ArcForges\ArcVideoFoundation` | `139eecaa…` | foundation source | `include/**`,`src/**` | `.git` | 27 | `AF-F-ARCVF-0001..0010` | `CrossChecked` | 2026-08-15 | SC-AVF-01 | 不复用二进制，保留算法 provenance | PureCSharp/StableCAPI/OwnedCABI 逐类型 |
| ArcVideoFoundation | `C:\MyFile\ArcForges\ArcVideoFoundation` | `139eecaa…` | CMake/config/docs/license | CMake/presets/CI/docs/config/license | none | 21 | `AF-F-ARCVF-0011` | `NeedsRecheck` | 2026-08-15 | SC-AVF-02 | root `CMakeLists.txt` dirty 未复核关闭 | ReferenceOnly/Rewrite |

---

## 5. 基线漂移流程

1. **识别变化**：例行重跑基线核验（本步以一次性脚本断言执行，证据见 ledger；仓库策略禁 tracked helper scripts）；任一仓库 `HEAD != 冻结 commit`、`tag` 不匹配、`status --porcelain` 出现未登记新增/删除/修改，或 `DiffSha256` 与快照不一致，即触发。
2. **标记漂移**：受影响子系统/命中路径的 Coverage/Feature 行全部置 `NeedsRecheck`，写漂移报告（新旧 commit diff 摘要 + 受影响清单行 ID 列表）。
3. **找出受影响结论**：定位受影响清单行（`feature-inventory-and-mapping.md`）、许可证证据（`license-and-reuse-matrix.md` §1/§7）与行为金样。
4. **重读**：在 clean frozen checkout 或明确接受的新基线上重新逐项核验。
5. **更新**：回写 `license-and-reuse-matrix.md` §1/§7 与 `feature-inventory-and-mapping.md` 对应行；状态从 `NeedsRecheck` 回到 `Mapped`/`CrossChecked`（`ReviewedFileCount` 必须对应实际分析记录）。
6. **缓释**：漂移未关闭期间，相关步骤引用处标注"以 NeedsRecheck 子系统为输入的部分暂缓"；不得一边宣称全绿一边把未复核承诺成完成。

---

## 6. 一致性核验与 Gate

- 基线核验（本步一次性脚本断言）对 6 仓库给出可判真逐仓结果：`HEAD` == 冻结 commit、tag 匹配、`status --porcelain` 与登记 dirty-file 集合 + 规范化 DiffSha256 完全相等；未登记新增/删除/修改、diff hash 漂移或 commit 漂移均失败并列出受影响 Coverage/Feature，不把"全绿"偷换为"全 clean"。
- 现状表无"未定义状态"单元格：每个子系统的 `CoverageStatus ∈` 九态集合（脚本枚举校验）。
- 完成门禁：`source-baseline.md` + `baseline-snapshot.txt` 存在；6 commit 逐字匹配 §1；workspace clean/dirty 与登记簿当前快照逐仓一致；命中 5 个 dirty file 的 Coverage/Feature 均为 `NeedsRecheck`；九态状态机定义完整；每子系统有且仅有一个当前状态；漂移流程可直接执行。
- **任一 `NeedsRecheck` 未复核关闭前，Step 00 不得宣称整体完整闭合** —— 本步如实登记 5 个 `NeedsRecheck`，保留阻断状态。