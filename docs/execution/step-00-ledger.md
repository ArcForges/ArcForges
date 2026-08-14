# Step 00 Execution Ledger — Scope & Source Inventory

> Canonical ledger for ArcForges Step 00 (`00-scope-and-source-inventory.md`). This is the only
> continuation record for the active scope. It is updated inside each owning-substep commit with the
> completed scope, validation, evidence, risks, branch-tip identity, and one exact safe next action.
>
> Branch: `feat/af00-scope-and-source-inventory`
> Worktree: `C:\MyFile\ArcForges\ArcForges\.worktree\af00-scope-and-source-inventory`
> Base: `origin/main` (2d4d17d2a843cbf202910075ceb3f00e364d5cad)
> Mode: **whole-step** — all owning substeps 00.00–00.06 plus the file-level Completion Gate (00 closure).
> Dead PR #15 (`feat/af00-00-scope-inventory`) must never be reopened or its branch name reused.

## State

| Substep | Deliverable(s) | Status | Commit |
|---|---|---|---|
| 00.00 | `docs/scope/product-family.md`, `docs/tools/check-scope.ps1` | done | 3bf1579 |
| 00.01 | `docs/scope/source-baseline.md`, `docs/scope/baseline-snapshot.txt` | done | 8821c05 |
| 00.02 | `docs/scope/source-subsystems.md` + merge into `feature-inventory-and-mapping.md`, completeness scripts | done | this commit |
| 00.03 | `docs/scope/license-summary.md`, evidence-path checks, trademark blacklist | not started | — |
| 00.04 | `docs/compliance/{copied-code,copied-asset,independent-reimplementation,replacement-backlog,third-party-license-register}.{md,json}` | not started | — |
| 00.05 | `docs/scope/verification-oracles.md` | not started | — |
| 00.06 | `docs/scope/sequencing.md`, traceability seeds, `eng/traceability/generate-feature-trace-bridge` | not started | — |
| Gate | File-level Completion Gate (00 closure) | not started | — |

## Preflight (run start, 2026-08-14)

- TARGET_REPO `C:\MyFile\ArcForges\ArcForges` verified git repo, top-level equals configured path, main clean at
  `2d4d17d2a843cbf202910075ceb3f00e364d5cad`. origin/main == local main after fetch.
- PLAN_REPO `C:\MyFile\ArcForges\ArchitectureDesign` verified git repo, top-level equals configured path,
  clean at `b81a2d526ff70e8616bb814dd02fb4d1be5818d8`. PLAN_ROOT belongs to PLAN_REPO.
- Six source repos HEAD / branch / worktree recomputed (2026-08-14):
  | Repo | Commit | Branch | Worktree |
  |---|---|---|---|
  | AionUi | `29c9271a59484e4696778cb80164f705245a6186` | Branch_v2.1.35 | dirty: `scripts/rebuildNativeModules.js`, `tests/unit/build-scripts/windows-fast-build-script.test.ts` |
  | AFFiNE | `81df4751a367f2795bc0d165586650dbe8db73d6` | Branch_v0.27.2 | clean |
  | siyuan | `eef10568384e2e7cf547adb029ae46a72e43c287` | Branch_v3.7.3 | clean |
  | Serial-Studio | `639daafb2fe7d324c3b2d5583d2514c8c470676f` | Branch_v4.0.3 | clean |
  | ArcVideo | `caf56513278703adec0c2933ec235bb864d72e31` | main | dirty: `CMakeLists.txt`, `app/common/otioutils.h` |
  | ArcVideoFoundation | `139eecaaa79dbad743a146f174a9c89a66ed594b` | main | dirty: `CMakeLists.txt` |
  Three dirty repos / 5 tracked files match source-coverage-register.md §2; DiffSha256 recomputation is in 00.01.
- PR #15 closed-unmerged (dead); not resumed. No existing branch/worktree/ledger on main.

## Run log

### Substep 00.00 — product family & scope (this commit)

- Wrote `docs/scope/product-family.md`: Table 1 product freeze (7 rows, ProductId set
  `arcchat,arcnotes,arcscope,arcslate,arcchat-mobile,arcforges-cloud,arcforges-web`); Table 2 exit/inheritance
  (ArcImage exited, ArcVideo/ArcVideoFoundation→ArcSlate); 7 product autonomy invariants; ArcNotes phased table
  (Edgeless 15 / Database 16 / Slides 17); Android/iOS/Web state freeze; business-model snapshot (multi-collab/
  org/Team/Multi-Agent/CRDT all Drop); explicit no-output list (no timeline/people/cost/gantt/fake dates).
- Wrote `docs/tools/check-scope.ps1` (pure text, touches no source; `pwsh`). All 54 assertions PASS. Reverse
  evidence: injecting an `arcimage` product row fails `ProductId set must equal canonical set` + name/id naming;
  gate restored and re-PASS.
- ArcImage whitelist: matcher uses the plan's own exit-vocabulary (`退出|不迁入|不属于|不得成为目标|不是.*改名|不复用|零.*命中|复活|Out of Scope`) because the authoritative plan docs express the ArcImage exit with several markers; naming-context false-positives removed by scanning only precise target identifiers.
- Validation: `pwsh -NoProfile -File docs/tools/check-scope.ps1 -PlanRoot ... -TargetDocsRoot ...` → exit 0, Result PASS.
- Risk: none outstanding for 00.00.
- Next action: substep 00.01 — recompute 6-repo HEAD/status/DiffSha256, write `docs/scope/source-baseline.md` + `baseline-snapshot.txt`, embed nine-state Coverage state machine.
- Branch tip: 3bf1579 (`feat/af00-scope-and-source-inventory`).

### Substep 00.01 — source baselines & Coverage state machine (this commit)

- Recomputed the six-repo HEAD/branch/describe/submodule + `sha256(git ls-files -s)` index aggregate and, for
  the dirty repos, DiffSha256 (`sha256(git diff)` minus a single trailing LF) — all match
  `source-coverage-register.md` §2: zero index drift; AionUi `1f87a590…`, ArcVideo `3302eb6c…`,
  ArcVideoFoundation `9ccbbea3…` DiffSha256 verbatim.
- `docs/scope/baseline-snapshot.txt`: raw `rev-parse HEAD` / `status --porcelain=v1` / `describe --tags --always`
  / `submodule status` / `INDEX_SH` / `DIFF_SH` per repo + UTC generation timestamp.
- `docs/scope/source-baseline.md`: baseline table, index-aggregate table, nine-state Source Coverage state
  machine (per-state entry/evidence/exit), 27 per-source per-subsystem rows with fixed columns and a single
  nine-state CoverageStatus (5 dirty-path rows stay NeedsRecheck), and the drift process (trigger→mark→find→
  re-read→update; un-reconciled NeedsRecheck blocks Step 00 closure).
- `docs/tools/check-baseline.ps1`: per-repo decidable verdict (HEAD/tag/index-aggregate/worktree-set/DiffSha256)
  + validates every §3 CoverageStatus ∈ nine-state set. PASS 2026-08-14 (six repos + 27 rows).
- Validation: `pwsh -NoProfile -File docs/tools/check-baseline.ps1 -PlanRoot …` → exit 0, PASS.
- Risk: the five NeedsRecheck rows remain open by design (dirty worktree hits registered paths); not a defect,
  but Step 00 cannot claim full closure until reconciled on a clean frozen checkout.
- Next action: substep 00.02 — produce `docs/scope/source-subsystems.md` (subsystem-level functional inventory
  with the unified row mode) and merge/verify against `feature-inventory-and-mapping.md`, incl. completeness
  scripts.
- Branch tip: 8821c05.

### Substep 00.02 — source subsystem feature inventory (this commit)

- `docs/scope/source-subsystems.md`: subsystem-level feature inventory across all six sources with the
  unified row mode (FeatureId|SourceRepo@Baseline|SourcePath|Behavior|DecisionClass|TargetProduct|
  TargetProject|TargetDefinition|OwningStep|OracleClass|LicenseEvidence|AttributionRequired|Notes),
  grouped per source (AionUi desktop `AF-F-AIONUI-*` + mobile `-M-*`, AFFiNE blocksuite + backend ReferenceOnly,
  siyuan ReferenceOnly/独立实现, Serial-Studio CORE/PRO/LIB with Pro→Replace+O4, ArcVideo, ArcVideoFoundation),
  plus the Yjs/CRDT Drop row and merge-consistency § with feature-inventory.
  82 subsystem rows; FeatureId families all present; ranges/placeholders pointer style documented (per-feature
  unique IDs live in `feature-inventory-and-mapping.md` — the 833-row denominator).
- `docs/tools/check-inventory.ps1`: 34 assertions PASS on the merged coverage (82 rows; Decision/Oracle/
  OwningStep non-empty, no TBD; ten source families present; SS-PRO all Replace+O4; AFFINE-BE all ReferenceOnly;
  ipcBridge 35 groups + 299-member extraction + 289 unique desktop rows + renderer/pages dirs; blocksuite/siyuan/
  Serial-Studio lib/ArcVideo modules closure; per-source SourcePath sample present). Reverse evidence verified:
  deleting the `shell` group from the deliverable fails "Every ipcBridge export-member group … missing shell".
- Validation: `pwsh -NoProfile -File docs/tools/check-inventory.ps1 …` → exit 0, PASS.
- Risk: per-feature rows are aggregated at subsystem level in this file (groups/ranges); the authoritative
  per-feature uniqueness is the plan's `feature-inventory-and-mapping.md` denominator (read-only), and the
  merge is asserted consistent by the script (families + ranges present, no genuine orphan path).
- Next action: substep 00.03 — `docs/scope/license-summary.md` evidence paths (`Test-Path`), trademark
  blacklist, AGPL obligations→owning-step table, DecisionClass↔Manifest map.
- Branch tip: this commit.