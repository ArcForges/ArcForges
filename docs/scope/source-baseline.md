# Source Repo Baselines and Source Coverage State Machine

> Freezes the six read-only source repositories' identity, commit, tag, worktree state and the Source
> Coverage **nine-state** machine that makes "read up to here, mapped to there, who must re-read" decidable.
> Facts here are re-computed each run against `source-coverage-register.md` (the authoritative field and
> drift-process source); the raw command output snapshot is `baseline-snapshot.txt` in this directory.
> Workspace state is never copied from `license-and-reuse-matrix.md` §1 (which records "clean" from authoring
> time); it is recomputed and must equal the `source-coverage-register.md` §2 dirty-file/hash snapshot.

## 1. Baseline table（六来源基线冻结）

Recomputed 2026-08-14 (UTC). Commit/tag values are verbatim from `license-and-reuse-matrix.md` §1; the
`WorkspaceState` / `Submodules` columns are recomputed live and must equal `source-coverage-register.md` §2.

| 来源 | 路径 | Git | Branch | BaselineCommit | Tag/Version | WorkspaceState | Submodules |
|---|---|---|---|---|---|---|---|
| AionUi | `C:\MyFile\ArcForges\AionUi` | yes | `Branch_v2.1.35` | `29c9271a59484e4696778cb80164f705245a6186` | v2.1.35 | **dirty** (2): `scripts/rebuildNativeModules.js`, `tests/unit/build-scripts/windows-fast-build-script.test.ts`; DiffSha256=`1f87a590859586a4b64831d54b0292117294dabaef93c71a5fe4bcd377525492` | none |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | yes | `Branch_v0.27.2` | `81df4751a367f2795bc0d165586650dbe8db73d6` | v0.27.2 | clean | none |
| siyuan | `C:\MyFile\ArcForges\siyuan` | yes | `Branch_v3.7.3` | `eef10568384e2e7cf547adb029ae46a72e43c287` | v3.7.3 | clean | none |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | yes | `Branch_v4.0.3` | `639daafb2fe7d324c3b2d5583d2514c8c470676f` | v4.0.3 | clean | none |
| ArcVideo | `C:\MyFile\ArcForges\ArcVideo` | yes | `main` | `caf56513278703adec0c2933ec235bb864d72e31` | — | **dirty** (2): `CMakeLists.txt`, `app/common/otioutils.h`; DiffSha256=`3302eb6c34d252be675ada195461f746c8965d1c2014280df52e0d51a767030c` | none |
| ArcVideoFoundation | `C:\MyFile\ArcForges\ArcVideoFoundation` | yes | `main` | `139eecaaa79dbad743a146f174a9c89a66ed594b` | — | **dirty** (1): `CMakeLists.txt`; DiffSha256=`9ccbbea307352499f5ad55ed6f5eb52176f5f0eff7c20df6d3e77969a9f85a96` | none |

**Verification snapshot** `docs/scope/baseline-snapshot.txt` records per-repo `rev-parse HEAD`,
`status --porcelain=v1`, `describe --tags --always`, `submodule status`, the index aggregate
(`sha256(git ls-files -s)`) and DiffSha256, all read-only, with the UTC generation timestamp.
None of the six source repositories was fetched, checked out, reset, cleaned or modified in any way.

**Index aggregates** (prove the tracked denominator does not drift; they are not "deep-read" evidence):

| 来源 | Aggregate index SHA-256 (`sha256(git ls-files -s)`) | Worktree drift |
|---|---|---|
| AionUi | `93ba619e23883786271d0c8fd785b0f654bd9066fb198460bbe7f83034f3a80f` | registered dirty 2 |
| AFFiNE | `78f2c778d8a4b11731c907adf22e4140b697588e93b519d8e05c10ebae6ba313` | none |
| siyuan | `e3ed4807c24dafbdfd6b9ea36d0810d000d2d1ee07ac1b65436cfc4ce72e59b6` | none |
| Serial-Studio | `6a8f6c545304e567dcf46b8c78c7236ab3bca7735ea93de60756889887c38386` | none |
| ArcVideo | `dd99c8a6bd33403828c41d7421327ddfc537039aa2f11ff739d46e39af08528e` | registered dirty 2 |
| ArcVideoFoundation | `c9166509b4e883a1834c18e3286a3ea4a1ea644f9e22942d100c83a23e1ae8da` | registered dirty 1 |

Recomputation result (2026-08-14): zero index drift; the three dirty repos' DiffSha256 values equal the
registered values; the mapped Coverage/Feature rows that touch the five dirty paths stay `NeedsRecheck`:
`AF-F-AIONUI-0283`, `AF-F-AIONUI-0285`, `AF-F-ARCV-0065`, `AF-F-ARCV-0069`, `AF-F-ARCVF-0011`. Step 00 does
not claim closure while any of these is open.

---

## 2. Source Coverage nine-state state machine

Each system's current state is a single member of this machine. Entering a later state requires the prior
evidence; nothing is granted on planning prose alone.

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

Rules:
- A dirty worktree is **drift evidence, not an upgraded Oracle**. Feature/Coverage rows hit by a dirty path
  drop to `NeedsRecheck`; the rest still read the frozen-commit blobs but any downstream validation must use a
  clean frozen checkout, never the worktree overlay content.
- Generated artifacts, vendored dependencies, binaries and resources are also listed (see matrix rows); they
  may be `Excluded`/`ReferenceOnly`/`仅许可证或供应链审查` but may never disappear from the denominator.
- `ReviewedFileCount` requires corresponding analysis records; a classed-but-unread group may be `Classified`
  or `Mapped` but never `CrossChecked`.

---

## 3. Per-repo per-subsystem current state

Fixed columns: `SourceRepo | RepoPath | BaselineCommit | Subsystem | IncludedGlob | ExcludedGlob |
EnumeratedFileCount | ReviewedFileCount | CoverageStatus | LastVerifiedUtc | EvidencePath | RemainingRisk | Notes`.
`CoverageStatus` is a single nine-state value (see §2). Counts are the tracked-file denominators recorded in
`source-coverage-register.md` §3; `ReviewedFileCount` equals `EnumeratedFileCount` only where the register
records a `DeepAnalyzed` read + `CrossChecked` closure (per-item analysis), otherwise it is `0` with the
reason in `Notes` (honesty: file count ≠ deep read). LastVerifiedUtc = 2026-08-14 baseline recomputation.

| SourceRepo | RepoPath | BaselineCommit | Subsystem | IncludedGlob | ExcludedGlob | EnumeratedFileCount | ReviewedFileCount | CoverageStatus | LastVerifiedUtc | EvidencePath | RemainingRisk | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AionUi | `C:\MyFile\ArcForges\AionUi` | `29c9271a…` | Desktop first-party | `packages/desktop/src/**` | `.git/**`, `node_modules`, build cache | 1052 | 1052 | CrossChecked | 2026-08-14 | `source-coverage-register.md` SC-AION-01; `baseline-snapshot.txt` | none | ipcBridge 2039 lines、13 表、renderer/process 目录与 `AF-F-AIONUI-0001..0282` |
| AionUi | `C:\MyFile\ArcForges\AionUi` | `29c9271a…` | Mobile first-party/platform | `mobile/**` | … | 81 | 81 | CrossChecked | 2026-08-14 | SC-AION-02 | none | `AF-F-AIONUI-M-*`；RN runtime 不复制，iOS 只留架构 |
| AionUi | `C:\MyFile\ArcForges\AionUi` | `29c9271a…` | Tests/fixtures/examples | `tests/**`,`examples/**` | … | 542 | 542 | **NeedsRecheck** | 2026-08-14 | SC-AION-03 | `tests/unit/build-scripts/windows-fast-build-script.test.ts` dirty | `AF-F-AIONUI-0283..0284`；命中 dirty 行回退复核 |
| AionUi | `C:\MyFile\ArcForges\AionUi` | `29c9271a…` | Assets/i18n/theme/icons | `resources/**`,`public/**` | … | 94 | 94 | CrossChecked | 2026-08-14 | SC-AION-04 | Aion/第三方品牌资产默认重绘 | `AF-F-AIONUI-0287..0288` |
| AionUi | `C:\MyFile\ArcForges\AionUi` | `29c9271a…` | Build/release/docs/config | root config, `.github/**`,`scripts/**`, homebrew, docs | … | 148 | 0 | **NeedsRecheck** | 2026-08-14 | SC-AION-05 | `scripts/rebuildNativeModules.js` dirty | `AF-F-AIONUI-0285..0289`；ReviewedFileCount=0（Read 非 DeepAnalyzed，且 dirty path 命中） |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `81df4751…` | blocksuite（Block/Edgeless/Database/Slides） | `blocksuite/**` | … | 3108 | 0 | Mapped | 2026-08-14 | SC-AFF-01 | 仅 0026,0029,0034,0037,0043,0045..0065 本轮 CrossChecked；其余不因 tracked 数升 DeepAnalyzed | `AF-F-BLOCKSUITE-*`；Yjs/CRDT/awareness 全 Drop |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `81df4751…` | Frontend apps/modules | `packages/frontend/**` | … | 4552 | 0 | Mapped | 2026-08-14 | SC-AFF-02 | 69-module closure ledger；逐行升 CrossChecked 需路径/符号/测试/许可证据 | `AF-F-AFFINE-FE-0001..0084`；Avalonia 重写，不复制 Web runtime |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `81df4751…` | Backend（EE，ReferenceOnly） | `packages/backend/**`,`packages/common/native/**` | … | 1134 | 0 | Mapped | 2026-08-14 | SC-AFF-03 | 仅 `AF-F-AFFINE-BE-0049` 本轮 CrossChecked；EE 不复制 | `AF-F-AFFINE-BE-*`；Prisma 57 表仅 ReferenceOnly；多人协作 Drop |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `81df4751…` | Native/common | `packages/common/**` | … | 534 | 0 | Mapped | 2026-08-14 | SC-AFF-04 | 不引入 Node/N-API；必要 native 走 C ABI | `AF-F-AFFINE-FE-*` native 行 |
| AFFiNE | `C:\MyFile\ArcForges\AFFiNE` | `81df4751…` | Tests/build/docs | `tests/**`,`tools/**`,`docs/**`, root config | 28 binary/archive → Excluded | 637 | 0 | Mapped | 2026-08-14 | SC-AFF-05 | 未执行 source tests 不计 CrossChecked | 28 binary/archive 只 hash/license 处置 |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `eef10568…` | kernel（文档/引用/AV/搜索/历史/导入导出…） | `kernel/**` | … | 445 | 445 | CrossChecked | 2026-08-14 | SC-SY-01 | 不复制 AGPL 源码，仅 Oracle O3 | `AF-F-SIYUAN-0001..0026` |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `eef10568…` | app/src 前端 | `app/src/**` | … | 479 | 479 | CrossChecked | 2026-08-14 | SC-SY-02 | 不得逐行翻译 | `AF-F-SIYUAN-0027..0062` |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `eef10568…` | appearance/guide/stage 资源 | `app/appearance/**`,`app/guide/**`,`app/stage/**` | stage JS 运行时 → Drop | 1097 | 0 | CrossChecked | 2026-08-14 | SC-SY-03 | 全部 stage JS/WebView runtime 显式 Drop | `AF-F-SIYUAN-0064..0066,0068..0075` |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `eef10568…` | electron/构建/发布/平台 | `app/electron/**`,`app/appx/**`,`app/nsis/**`,`app/scripts/**`, root scripts/CI/Docker | … | 0 (grouped) | 0 | CrossChecked | 2026-08-14 | SC-SY-04 | Electron/loopback 不进入 Desktop | `AF-F-SIYUAN-0063,0067` |
| siyuan | `C:\MyFile\ArcForges\siyuan` | `eef10568…` | tests/docs | repo/app tests, testdata/docs | … | 69+406 | 0 | CrossChecked | 2026-08-14 | SC-SY-05 | 测试行为可重建但源码不复制 | `AF-F-SIYUAN-0063..0066` |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | app/src（core + commercial mixed） | `app/src/**` | … | 483 | 483 | CrossChecked | 2026-08-14 | SC-SS-01 | Commercial-only Pro 绝不复制 | `AF-F-SS-CORE-*`,`AF-F-SS-PRO-*` |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | app/qml | `app/qml/**` | … | 160 | 160 | CrossChecked | 2026-08-14 | SC-SS-02 | 品牌视觉重绘 | 逐文件 SPDX 的 QML rows |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | lib（vendored dependency） | `lib/**` | … | 1747 | 0 | CrossChecked | 2026-08-14 | SC-SS-03 | 无成熟 C# 绑定时窄 C ABI | 每库 `AF-F-SS-LIB-*` |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | tests | `tests/**` | … | 94 | 94 | CrossChecked | 2026-08-14 | SC-SS-04 | 不伪称已执行 | test closure rows |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | rcc/translations/deploy/build | `app/rcc/**`,`app/translations/**`,`app/deploy/**`, CMake/CI/scripts | … | 964 | 0 | CrossChecked | 2026-08-14 | SC-SS-05 | 字体/图标/品牌逐项处置 | resource/build rows |
| Serial-Studio | `C:\MyFile\ArcForges\Serial-Studio` | `639daafb…` | examples/docs | `examples/**`,`doc/**` | … | 237 | 0 | CrossChecked | 2026-08-14 | SC-SS-06 | 示例输入保留 provenance | examples/docs rows |
| ArcVideo | `C:\MyFile\ArcForges\ArcVideo` | `caf56513…` | product source（project/node/timeline/codec/render/…） | `app/audio\|codec\|common\|node\|render\|task\|timeline\|tool\|ts\|undo\|window\|widget\|panel\|dialog/**` + `app/core.*,main.cpp,version.*,config/**` | … | 2362 | 0 | **NeedsRecheck** | 2026-08-14 | SC-AV-01 | `app/common/otioutils.h` dirty；其余行仍读冻结 commit blob | `AF-F-ARCV-0001..0066`；目标 PortAudio 零依赖不改变来源事实 |
| ArcVideo | `C:\MyFile\ArcForges\ArcVideo` | `caf56513…` | ui/shaders | `app/ui/**`,`app/shaders/**` | … | 1513 | 0 | CrossChecked | 2026-08-14 | SC-AV-02 | 品牌图形重绘 | `AF-F-ARCV-0067..0072` |
| ArcVideo | `C:\MyFile\ArcForges\ArcVideo` | `caf56513…` | tests | `tests/**` | … | 8 | 8 | CrossChecked | 2026-08-14 | SC-AV-03 | 不伪称已执行 | ArcVideo test rows |
| ArcVideo | `C:\MyFile\ArcForges\ArcVideo` | `caf56513…` | build/package/release/docs | `app/packaging/**`,`cmake/**`,`docker/**`, root CMake/presets/CI/docs/tools | … | 57+ | 0 | **NeedsRecheck** | 2026-08-14 | SC-AV-04 | root `CMakeLists.txt` dirty | `AF-F-ARCV-0067..0072`；CMake 权威、vcxproj 仅 Windows 开发入口 |
| ArcVideoFoundation | `C:\MyFile\ArcForges\ArcVideoFoundation` | `139eecaa…` | foundation source | `include/**`,`src/**` | … | 27 | 27 | CrossChecked | 2026-08-14 | SC-AVF-01 | 逐类型 PureCSharp/StableCAPI/OwnedCABI 决策 | `AF-F-ARCVF-0001..0010`；不复用二进制 |
| ArcVideoFoundation | `C:\MyFile\ArcForges\ArcVideoFoundation` | `139eecaa…` | build/docs/config/license | root CMake/presets/CI/docs/config | … | 21 | 0 | **NeedsRecheck** | 2026-08-14 | SC-AVF-02 | root `CMakeLists.txt` dirty | `AF-F-ARCVF-0011` |

> `ReviewedFileCount` semantics: equals the group's tracked file count only where `source-coverage-register.md`
> records a `DeepAnalyzed` read + `CrossChecked` closure (per-item analysis records exist). Otherwise `0` with
> the honest reason in Notes — a file count alone is never "deep-read" or "CrossChecked" evidence.

---

## 4. Baseline drift process

Authority: `source-coverage-register.md` §2/§5 (this file is the operational summary). Trigger and update path:

1. **Trigger**: a routine rerun of `docs/tools/check-baseline.ps1` (or a `rev-parse HEAD` / `status --porcelain`
   / `ls-files -s` recompute) detects that any repo's `HEAD` != frozen commit, `Tag/Version` mismatch, an
   unregistered add/delete/modify, an index-aggregate (denominator) drift, or a DiffSha256 drift.
2. **Mark drift**: set the affected subsystems' `CoverageStatus` to `NeedsRecheck` and the affected
   Coverage/Feature rows (`AF-F-*`) to `NeedsRecheck`; write a drift report containing the old→new commit diff
   summary and the list of affected Feature IDs.
3. **Find affected conclusions**: the impacted mapping rows, license-evidence rows, and behavior golden samples
   that derived from the changed paths.
4. **Re-read**: on a clean frozen checkout (or an explicitly accepted new baseline) re-read the changed paths;
   do not consume the dirty worktree overlay content as an upgraded Oracle.
5. **Update**: write back the affected rows in `license-and-reuse-matrix.md` §1/§7 and
   `feature-inventory-and-mapping.md`; then return the state to `Mapped`/`CrossChecked`.
6. During drift, any step that consumes a `NeedsRecheck` subsystem as input must be labelled "deferred pending
   recheck" in its own references.

Any un-reconciled `NeedsRecheck` blocks Step 00 closure per the file-level Completion Gate.

---

## 5. Verification

- `docs/tools/check-baseline.ps1` recomputes and asserts per-repo: HEAD == frozen commit, branch/tag match,
  index-aggregate match, worktree `--porcelain` set == registered dirty files (or clean), and (for dirty
  repos) DiffSha256 match. It never rewrites "all green" as "all clean". Result 2026-08-14: **PASS** across
  all six repos; the five `NeedsRecheck` rows remain open and are reported on any failure.
- Every subsystem row in §3 carries a single `CoverageStatus` ∈ the nine-state set; the table above has no
  undefined state cell.