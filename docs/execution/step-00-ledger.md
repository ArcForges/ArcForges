# Step 00 Execution Ledger（canonical）

> ArcForges Step 00 — Scope & Source Inventory。Whole-step mode。
> 本账本是 Step 00 的可恢复操作账本（`arcforges.md` Preflight：Step 00 keeps this file canonical；
> Draft PR body mirrors each checkpoint after every substep commit）。
> 每个检查点记录：completed scope、validation、evidence、risks、branch-tip/commit identity、one exact safe next action。

- Branch（共享，anchored to 00.00）：`feat/af00-00-scope-inventory`
- Worktree：`C:\MyFile\ArcForges\ArcForges\.worktree\step-00-scope`
- Base：`origin/main`（2d4d17d）—— Step 00 无前置编号步骤；origin/main 已含既有 Step 01 骨架，Step 00 为 docs-only 增量，不重做或推翻既有代码。

## Substep 00.00 — 冻结产品组合与范围

- Scope：产出 `docs/scope/product-family.md`（产品冻结表 7 行、退出/继承表、7 条产品自治不变式、ArcNotes 分阶段表、Android/iOS/Web 状态冻结、商业模型快照、不输出清单）+ `docs/tools/check-scope.ps1`（纯文本断言，不触源码）。
- Validation：`pwsh docs/tools/check-scope.ps1` → all assertions green（EXIT=0）。
  断言项：ProductId 集合逐字相等（`arcchat,arcnotes,arcscope,arcslate,arcchat-mobile,arcforges-cloud,arcforges-web`）；每 ProductId 在 README §1 + layout §14.1 有声明；ArcImage 在目标 docs 与 plan 全文仅以退出/不迁入语境出现、目标命名零命中；ArcNotes Edgeless/Database/Slides 拥有步骤 15/16/17；7 条不变式“强制步骤”列非空。
- Evidence：脚本输出 `check-scope.ps1: all assertions green`；反向失败证据——将某 ProductId 改为已退出的 ArcImage 或把 ArcImage 写为目标行（违反“不得成为目标”）→ 脚本 EXIT=1 并指认受影响行。
- Risks：Step 01 骨架（PR #1 `feat/af01-00-repository-foundation` 及后续 fix PR）已先于 Step 00 证据存在于 `main`；本步为 docs-only 范围证据，不重做、不推翻既有实现，仅在 product-family.md 引用为范围事实。该次序偏离记入 `docs/deviations.md`（见下）。
- Branch-tip / commit identity：`feat/af00-00-scope-inventory` tip = this commit（自引用，SHA 记录于 Draft PR body / final report）。
- Exact safe next action：开始 Substep 00.01 — 产出 `docs/scope/source-baseline.md` + `docs/scope/baseline-snapshot.txt`：对 6 仓库执行 `rev-parse HEAD`/`status --porcelain`/`describe --tags` 追加快照，落九态 Source Coverage 状态机与每仓库每子系统现状表，命中 5 dirty file 的 Coverage/Feature 保持 `NeedsRecheck`。

## Substep 00.01 — 待实施

## Substep 00.02 — 待实施

## Substep 00.03 — 待实施

## Substep 00.04 — 待实施

## Substep 00.05 — 待实施

## Substep 00.06 — 待实施

## Step 00 Completion Gate — 待闭合
