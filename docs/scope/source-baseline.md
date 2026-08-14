# Source Baseline & Source Coverage State Machine

> 范围：ArcForges Step 00.01 产物。固定六个只读来源仓库的基线核验快照、Source Coverage 九态状态机、
> 每仓库每子系统当前状态表与基线漂移流程。事实来源为 `source-coverage-register.md`（§2 基线、§3.1 子系统覆盖、
> §5 双向门禁）与 `license-and-reuse-matrix.md` §1。本文件是目标仓库侧证据，不替代规划权威。
>
> **纪律**：`WorkspaceState` 不从历史许可证表抄写，必须逐次复算。下列值已于 2026-08-14T04:05:21Z 由
> `docs/scope/baseline-snapshot.txt` 的只读命令复算，与 `source-coverage-register.md` §2 的 2026-08-11 终验逐字相等——
> 六仓 HEAD、三 clean 仓、三 dirty 仓、五个 tracked 修改文件与三份 `DiffSha256` 均未漂移。
> 既有 dirty worktree **不是本规划可清理的对象**；命中 dirty path 的 Coverage/Feature 保持 `NeedsRecheck`，
> 未复核关闭前 Step 00 Completion Gate 不得闭合。

## 1. 基线表

| 来源 | 路径 | Branch | BaselineCommit | Tag/Version | WorkspaceState | Submodules |
|---|---|---|---|---|---|---|
| AionUi | `C:\MyFile\ArcForges\AionUi` | `Branch_v2.1.35` | `29c9271a59484e4696778cb80164f705245a6186` | v2.1.35 | **dirty**：`scripts/rebuildNativeModules.js`、`tests/unit/build-scripts/windows-fast-build-script.test.ts`；DiffSha256=`1f87a590859586a4b64831d54b0292117294dabaef93c71a5fe4bcd377525492` | none |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `Branch_v0.27.2` | `81df4751a367f2795bc0d165586650dbe8db73d6` | v0.27.2 | clean | none |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `Branch_v3.7.3` | `eef10568384e2e7cf547adb029ae46a72e43c287` | v3.7.3 | clean | none |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `Branch_v4.0.3` | `639daafb2fe7d324c3b2d5583d2514c8c470676f` | v4.0.3 | clean | none |
| ArcVideo | `C:\MyFile\ArcForges\ArcVideo` | `main` | `caf56513278703adec0c2933ec235bb864d72e31` | — | **dirty**：`CMakeLists.txt`、`app/common/otioutils.h`；DiffSha256=`3302eb6c34d252be675ada195461f746c8965d1c2014280df52e0d51a767030c` | none |
| ArcVideoFoundation | `C:\MyFile\ArcForges\ArcVideoFoundation` | `main` | `139eecaaa79dbad743a146f174a9c89a66ed594b` | — | **dirty**：`CMakeLists.txt`；DiffSha256=`9ccbbea307352499f5ad55ed6f5eb52176f5f0eff7c20df6d3e77969a9f85a96` | none |

> 注：`license-and-reuse-matrix.md` §1 历史表曾把六仓一律标 `clean`；以 `source-coverage-register.md` §2 与本步 2026-08-14 复算为准——三仓 dirty。`DiffSha256` 定义为：Git 原始 `git diff` UTF-8 文本移除唯一末尾换行后计算 SHA-256；它只证明本次审计所见 diff，不把 dirty 内容提升为新来源基线。

## 2. 核验快照

完整只读命令输出见 `docs/scope/baseline-snapshot.txt`（含执行时间 UTC `2026-08-14T04:05:21Z`、git `2.55.0.windows.3`）。
对每仓库执行 `git -C <path> rev-parse HEAD`、`git -C <path> branch --show-current`、`git -C <path> describe --tags --always`、
`git -C <path> status --porcelain=v1`、`git -C <path> submodule status`，dirty 仓库额外计算 `DiffSha256`。无任何写操作。

`aggregateIndexSha256`（`git ls-files -s` 原始 stdout bytes 的 SHA-256，证明文件名/mode/blob 集合未变化）逐字承接 `source-coverage-register.md` §2：

| Repository | Tracked | Aggregate index SHA-256 |
|---|---:|---|
| AionUi | 1968 | `93ba619e23883786271d0c8fd785b0f654bd9066fb198460bbe7f83034f3a80f` |
| AFFiNE | 10056 | `78f2c778d8a4b11731c907adf22e4140b697588e93b519d8e05c10ebae6ba313` |
| siyuan | 2538 | `e3ed4807c24dafbdfd6b9ea36d0810d000d2d1ee07ac1b65436cfc4ce72e59b6` |
| Serial-Studio | 3748 | `6a8f6c545304e567dcf46b8c78c7236ab3bca7735ea93de60756889887c38386` |
| ArcVideo | 2436 | `dd99c8a6bd33403828c41d7421327ddfc537039aa2f11ff739d46e39af08528e` |
| ArcVideoFoundation | 48 | `c9166509b4e883a1834c18e3286a3ea4a1ea644f9e22942d100c83a23e1ae8da` |

## 3. Source Coverage 九态状态机

每态一行（进入条件 | 所需证据 | 退出方向）。状态集合 = `{Inventoried, Classified, Read, DeepAnalyzed, Mapped, CrossChecked, Excluded, NeedsRecheck, Superseded}`。

| 状态 | 进入条件 | 所需证据 | 退出方向 |
|---|---|---|---|
| `Inventoried` | 顶层目录/模块已枚举 | 目录树快照 + 模块/LOC 统计 | → Classified |
| `Classified` | 每模块已赋复用决策类别（§5 八类之一） | 清单行 DecisionClass 列 | → Read |
| `Read` | LICENSE 全文 + 关键入口文件已读 | 许可证证据路径 + SPDX 标注统计 | → DeepAnalyzed |
| `DeepAnalyzed` | 子系统级逐文件深读完成 | 文件范围、入口/类型/函数/测试/资源/协议/构建/许可分析记录 | → Mapped |
| `Mapped` | 全部功能行已进入 `feature-inventory-and-mapping.md` | 清单行 ID 区间 | → CrossChecked |
| `CrossChecked` | 映射 ↔ 代码 ↔ 许可证 三方核对完成 | 交叉核对记录 + 零孤立路径证明 | 终态（除非漂移） |
| `Excluded` | 明确排除（含原因与决定来源） | 排除理由（如 AionCore 不在提供目录内 → ReferenceOnly/Excluded） | 终态 |
| `NeedsRecheck` | 基线漂移或悬而未决问题 | 漂移报告 / 问题清单 | 重读后回原状态 |
| `Superseded` | 被更新基线/决定取代 | 取代指向（新 commit / 新决定 ID） | 终态 |

`Inventoried/Classified` 由文件分区证明；`Mapped` 还要求存在 `AF-F-*` 行；`CrossChecked` 还要求路径/符号、目标步骤、许可证和 Oracle 四方一致。二进制只可 `Excluded`，并必须记录资源/许可抽样和遗漏风险。`ReviewedFileCount` 不能只来自文件枚举，必须有对应分析记录。

## 4. 每仓库每子系统现状表

字段固定为：`CoverageId | SourceRepo@BaselineCommit | Subsystem(IncludedGlob;ExcludedGlob) | EnumeratedFileCount | ReviewedFileCount | CoverageStatus | LastVerifiedUtc | EvidencePath | RemainingRisk | Notes`。
`CoverageStatus` ∈ 九态集合。`ReviewedFileCount` 仅在存在逐文件分析记录时等于 `EnumeratedFileCount`，否则记已核对子集。`LastVerifiedUtc` = `source-coverage-register.md` 分析终验 `2026-08-11`（2026-08-14 复算确认零漂移）。

| CoverageId | SourceRepo@Commit | Subsystem / Glob | Enum | Reviewed | CoverageStatus | LastVerifiedUtc | EvidencePath / RemainingRisk / Notes |
|---|---|---|---:|---:|---|---|---|
| SC-AION-01 | AionUi@29c9271a… | `packages/desktop/src/**`（桌面 first-party；TS/TSX/SQL/config） | 1052 | 1052 | CrossChecked | 2026-08-11 | Evidence: `AF-F-AIONUI-0001..0282`；ipcBridge 2039 行、13 表、renderer/process 目录。Risk: none。Notes: 目标不保留 Node/ACP/local model runtime。 |
| SC-AION-02 | AionUi@29c9271a… | `mobile/**`（移动 first-party/平台；TS/TSX/Kotlin/Swift/config） | 81 | 81 | CrossChecked | 2026-08-11 | Evidence: `AF-F-AIONUI-M-*`。Risk: none。Notes: 不复制 RN runtime，iOS 只保留架构。 |
| SC-AION-03 | AionUi@29c9271a… | `tests/**`,`examples/**`（tests/fixtures/examples） | 542 | 542 | **NeedsRecheck** | 2026-08-11 | Evidence: `AF-F-AIONUI-0283..0284`。Risk: dirty `tests/unit/build-scripts/windows-fast-build-script.test.ts`。Notes: AF-F-AIONUI-0283 回退复核，clean frozen checkout 或接受新基线前不得沿用闭包结论。 |
| SC-AION-04 | AionUi@29c9271a… | `resources/**`,`public/**`（assets/i18n/theme/icons） | 94 | 94 | CrossChecked | 2026-08-11 | Evidence: `AF-F-AIONUI-0287..0288`。Risk: none。Notes: Aion/第三方品牌资产默认重绘。 |
| SC-AION-05 | AionUi@29c9271a… | `packages/shared-scripts`,`web-cli`,`web-host`,`.github`,`scripts`,root config（build/release/docs/config） | 145 | 145 | **NeedsRecheck** | 2026-08-11 | Evidence: `AF-F-AIONUI-0285..0289`。Risk: dirty `scripts/rebuildNativeModules.js`。Notes: AF-F-AIONUI-0285 回退复核；AF-F-AIONUI-0289 显式 Drop Node/aioncore/localhost launcher。 |
| SC-AFF-01 | AFFiNE@81df4751… | `blocksuite/**`（editor first-party；TS/TSX/Rust/assets） | 3108 | 624+ | Mapped | 2026-08-11 | Evidence: `AF-F-BLOCKSUITE-*`；本轮实际核对 `0026,0029,0034,0037,0043,0045..0065` 为 CrossChecked，其余 Mapped。Risk: none。Notes: 3108 是分类分母非逐文件深读证据；Yjs/CRDT/awareness 全 Drop。 |
| SC-AFF-02 | AFFiNE@81df4751… | `packages/frontend/**`（frontend apps/modules） | 4552 | 0（分区级） | Mapped | 2026-08-11 | Evidence: `AF-F-AFFINE-FE-0001..0084`。Risk: none。Notes: 4552 仅证明分区与 69-module closure ledger；84 行均 Mapped，目标 Avalonia MVVM，不复制 Web runtime。 |
| SC-AFF-03 | AFFiNE@81df4751… | `packages/backend/**`（含 `server/**`；backend reference） | 1100 | 1（`AF-F-AFFINE-BE-0049`） | Mapped | 2026-08-11 | Evidence: `AF-F-AFFINE-BE-*`。Risk: none。Notes: ReferenceOnly；不复制 EE/GraphQL/CRDT，多人协作 Drop。 |
| SC-AFF-04 | AFFiNE@81df4751… | `packages/common/native/**`,`packages/common/**` | 534 | 0（分区级） | Mapped | 2026-08-11 | Evidence: 相关 AF-F 行已映射。Risk: none。Notes: 不引入 Node/N-API，必要 native 走 C ABI。 |
| SC-AFF-05 | AFFiNE@81df4751… | `tests/**`,`tools/**`,`docs/**`,root Cargo/Yarn/CI/license | 637 | 0（分区级） | Mapped | 2026-08-11 | Evidence: frontend/build rows 已映射。Risk: none。Notes: 28 binary/archive 只做 hash/license/resource 处置。 |
| SC-SY-01 | siyuan@eef10568… | `kernel/**`（backend first-party；Go/SQL/templates） | 445 | 445 | CrossChecked | 2026-08-11 | Evidence: `AF-F-SIYUAN-0001..0026`。Risk: none。Notes: 不复制 AGPL 源码，仅 Oracle O3。 |
| SC-SY-02 | siyuan@eef10568… | `app/src/**`（desktop/mobile frontend；TS/SCSS） | 479 | 479 | CrossChecked | 2026-08-11 | Evidence: `AF-F-SIYUAN-0027..0062`。Risk: none。Notes: 不得逐行翻译。 |
| SC-SY-03 | siyuan@eef10568… | `app/appearance/**`,`app/guide/**`,`app/stage/**`,`screenshots/**` | 1097 | 1097 | CrossChecked | 2026-08-11 | Evidence: `AF-F-SIYUAN-0064..0066,0068..0075`。Risk: none。Notes: 所有 stage JS/WebView runtime 显式 Drop。 |
| SC-SY-04 | siyuan@eef10568… | `app/electron/**`,`app/appx/**`,`app/nsis/**`,`app/scripts/**`,root `scripts/**`,CI/Docker/config | — | — | CrossChecked | 2026-08-11 | Evidence: `AF-F-SIYUAN-0063,0067`。Risk: none。Notes: 目标 .NET publish/sign/update；Electron/Chromium/HTML/JS/loopback UI 不进入 Desktop。 |
| SC-SY-05 | siyuan@eef10568… | repo/app tests/testdata/docs/changelogs | — | — | CrossChecked | 2026-08-11 | Evidence: `AF-F-SIYUAN-0063..0066`。Risk: none。Notes: 测试行为可重建但源码不复制。 |
| SC-SS-01 | Serial-Studio@639daafb… | `app/src/**`（core/commercial mixed；C++/Qt） | 483 | 483 | CrossChecked | 2026-08-11 | Evidence: `AF-F-SS-CORE-*`,`AF-F-SS-PRO-*`。Risk: none。Notes: Commercial-only Pro 绝不复制。 |
| SC-SS-02 | Serial-Studio@639daafb… | `app/qml/**`（QML core/Pro） | 160 | 160 | CrossChecked | 2026-08-11 | Evidence: 按逐文件 SPDX 的 QML rows。Risk: none。Notes: 品牌视觉重绘。 |
| SC-SS-03 | Serial-Studio@639daafb… | `lib/**`（vendored dependency；C/C++/headers/licenses） | 1747 | 1747 | CrossChecked | 2026-08-11 | Evidence: 每库 `AF-F-SS-LIB-*`。Risk: none。Notes: 无成熟 C# 绑定时窄 C ABI。 |
| SC-SS-04 | Serial-Studio@639daafb… | `tests/**`（unit/integration/bench/perf/security/manual/scripts/utils） | 94 | 94 | CrossChecked | 2026-08-11 | Evidence: test closure rows。Risk: none。Notes: 不伪称已执行。 |
| SC-SS-05 | Serial-Studio@639daafb… | `app/rcc/**`,`app/translations/**`,`app/deploy/**`,CMake/CI/scripts | 964 | 964 | CrossChecked | 2026-08-11 | Evidence: resource/build rows。Risk: none。Notes: 字体/图标/品牌逐项处置。 |
| SC-SS-06 | Serial-Studio@639daafb… | `examples/**`,`doc/**` | 237 | 237 | CrossChecked | 2026-08-11 | Evidence: examples/docs rows。Risk: none。Notes: 示例输入保留 provenance。 |
| SC-AV-01 | ArcVideo@caf56513… | `app/{audio,codec,common,node,render,task,timeline,tool,ts,undo,window,widget,panel,dialog}/**`,`app/core.*`,`main.cpp`,`version.*`,`config/**` | 2362 | 2362 | **NeedsRecheck** | 2026-08-11 | Evidence: `AF-F-ARCV-0001..0066`。Risk: dirty `app/common/otioutils.h`。Notes: AF-F-ARCV-0065 回退复核；其余行仍读冻结 commit blob；目标 PortAudio 零依赖不改变来源事实。 |
| SC-AV-02 | ArcVideo@caf56513… | `app/ui/**`,`app/shaders/**`（generated style/assets/shaders） | 1513 | 1513 | CrossChecked | 2026-08-11 | Evidence: `AF-F-ARCV-0067..0072`。Risk: none。Notes: 品牌图形重绘，生成样式不逐字移植。 |
| SC-AV-03 | ArcVideo@caf56513… | `tests/**`（tests/fixtures；C++） | 8 | 8 | CrossChecked | 2026-08-11 | Evidence: ArcVideo test rows。Risk: none。Notes: 不伪称已执行。 |
| SC-AV-04 | ArcVideo@caf56513… | `app/packaging/**`,`cmake/**`,`docker/**`,root CMake/presets/CI/docs/tools | 57 | 57 | **NeedsRecheck** | 2026-08-11 | Evidence: `AF-F-ARCV-0067..0072`。Risk: dirty root `CMakeLists.txt`。Notes: AF-F-ARCV-0069 回退复核；CMake 权威，vcxproj 仅 Windows 开发入口。 |
| SC-AVF-01 | ArcVideoFoundation@139eecaa… | `include/**`,`src/**`（foundation source；C++ headers/source） | 27 | 27 | CrossChecked | 2026-08-11 | Evidence: `AF-F-ARCVF-0001..0010`。Risk: none。Notes: 不复用二进制，保留算法 provenance。 |
| SC-AVF-02 | ArcVideoFoundation@139eecaa… | CMake/presets/CI/docs/config/license | 21 | 21 | **NeedsRecheck** | 2026-08-11 | Evidence: `AF-F-ARCVF-0011`。Risk: dirty root `CMakeLists.txt`。Notes: AF-F-ARCVF-0011 回退复核。 |

### 4.1 现状汇总

- 子系统行数：27（AionUi 5、AFFiNE 5、siyuan 5、Serial-Studio 6、ArcVideo 4、ArcVideoFoundation 2）。
- CoverageStatus 分布：CrossChecked=17、Mapped=5、NeedsRecheck=5。无 `Inventoried/Classified/Read/DeepAnalyzed/Excluded/Superseded` 残留为非终态（`Excluded` 行见 `source-coverage-register.md` §4 二进制/资源处置）。
- 五个 `NeedsRecheck` 子系统（SC-AION-03、SC-AION-05、SC-AV-01、SC-AV-04、SC-AVF-02）对应五个 `NeedsRecheck` Feature 行（`AF-F-AIONUI-0283`、`AF-F-AIONUI-0285`、`AF-F-ARCV-0065`、`AF-F-ARCV-0069`、`AF-F-ARCVF-0011`），与 `source-coverage-register.md` §5.1 逐字一致。未复核关闭前本步 Gate 不闭合。
- Feature 级诚实分布（承接 register §5.1）：833 行唯一 `AF-F-*`，`CrossChecked=624 / Mapped=204 / NeedsRecheck=5`。

## 5. 基线漂移流程

触发条件：例行重跑基线核验脚本（本步 `docs/scope/baseline-snapshot.txt` 的命令），`commit ≠ 快照` 或 `status --porcelain` / `DiffSha256` 与登记值不等即触发。

1. **识别变化**：重跑 `rev-parse HEAD` / `status --porcelain` / `DiffSha256`，与 §1/§2 及 `source-coverage-register.md` §2 比对；commit 漂移或 dirty 文件集合/hash 漂移即记录新旧值。
2. **标记受影响**：命中变更路径的子系统 Coverage 行与对应 Feature 行标 `NeedsRecheck`，写漂移报告（新旧 commit diff 摘要 + 受影响清单行 ID 列表）。
3. **找出受影响结论**：清单行 / 许可证证据 / 金样 / Oracle 落点。
4. **重读**：在 clean frozen checkout 或明确接受的新基线上重新核验；dirty worktree 内容是漂移证据，不是升级 Oracle。
5. **更新**：`license-and-reuse-matrix.md` §1/§7 与 `feature-inventory-and-mapping.md` 对应行；状态回 `Mapped`/`CrossChecked`。
6. **标注**：漂移期间相关步骤引用处标注“以 NeedsRecheck 子系统为输入的部分暂缓”。

本步 2026-08-14 复算结论：**零漂移**——六仓 HEAD、三 clean、三 dirty、五 dirty file、三 `DiffSha256` 与 2026-08-11 终验逐字相等；五个 `NeedsRecheck` 行保持，不新造第二基线。

## 6. 完成门禁自检

- `source-baseline.md` + `baseline-snapshot.txt` 存在；6 仓库 commit 逐字匹配 §1，workspace clean/dirty 与 register 当前快照逐仓一致，命中 5 dirty file 的 Coverage/Feature 均 `NeedsRecheck`。✅
- 九态状态机定义完整；每个子系统有且仅有一个当前状态（§4 枚举校验）。✅
- 漂移流程可直接执行（§5 给出触发条件与更新路径）。✅
- 任一 `NeedsRecheck` 未复核关闭前，Step 00 不得宣称完整闭合。⚠（五个 `NeedsRecheck` 保持，Gate 不闭合——这是诚实阻断，不是失败伪造。）
