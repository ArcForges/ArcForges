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
| 00.00 | `docs/scope/product-family.md`, `docs/tools/check-scope.ps1` | done | this commit |
| 00.01 | `docs/scope/source-baseline.md`, `docs/scope/baseline-snapshot.txt` | not started | — |
| 00.02 | `docs/scope/source-subsystems.md` + merge into `feature-inventory-and-mapping.md`, completeness scripts | not started | — |
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
- Branch tip: this commit (`feat/af00-scope-and-source-inventory`).