# Step 00 — Scope & Source Inventory : Execution Ledger

> Canonical continuation ledger for ArcForges Step 00 (docs-only). Rules: one atomic implementation/evidence
> commit per owning substep; a PR only after the whole active scope passes its final review and the 00-closure
> Completion Gate. Remote PRs are history; this file is the only continuation record until a final PR exists.
> Records reflect **actual** commands, exit codes, evidence paths, and branch-tip identity — never fabricated.

- Active step: `00-scope-and-source-inventory.md`（whole-step mode）
- Active branch: `feat/af00-scope-source-inventory-reboot`（fresh; prior PR #16 & #15 closed-unmerged, their branch names not reused）
- Worktree: `.worktree/af00-scope-source-inventory-reboot`
- Base: `origin/main` (`d29f986a76c5523b1c358227bf6990b1a451b4bd`) — Step 00 is sequence start, no prerequisites
- Ledger path: `docs/execution/step-00-ledger.md`
- UTC run start: 2026-08-15

---

## 00.00 — 冻结产品组合与范围

**Status:** COMPLETE
**Deliverables:** `docs/scope/product-family.md`, `docs/tools/check-scope.ps1`

**Validation (exact command + result + evidence):**
- `pwsh -NoProfile -File docs/tools/check-scope.ps1` → `PASS: check-scope ... 7 invariants + product freeze + staging + Web-9 assertions green` (evidence: `docs/tools/check-scope.ps1`; run at UTC 2026-08-15)

**Gate (00.00 Completion gate):** product-family.md exists; freeze table rows == README product set, ProductId set exactly equal to the 7; every ProductId has owning step(s); plan tree grep `ArcImage` only in exit/non-target context (whitelist assertion) and zero target project/Namespace hits; Edgeless/Database/Slides -> steps 15/16/17; 7 invariants non-empty enforcement column. All assertions green.

**Evidence / notes:**
- Freeze table, exit/inheritance table, 7 product-autonomy invariants, ArcNotes staging, Android/iOS/Web freeze, business model snapshot, no-time-outputs note. Docs-only; no code/solution produced.
- Status of the five dirty tracked source files recorded for 00.01 — this substep produced no source mutation.

**Commit:** `0392f19157ac41efb7c387bb0bf3de6ad20fb500` `Step 00.00: freeze product family & scope`
**Next safe action:** 00.01 source baseline + coverage state machine.

---

## 00.01 — 来源仓库基线与 Source Coverage 状态机

**Status:** COMPLETE
**Deliverables:** `docs/scope/source-baseline.md`, `docs/scope/baseline-snapshot.txt`, `docs/tools/check-source-baseline.ps1`

**Validation (exact command + result + evidence):**
- `pwsh -NoProfile -File docs/tools/check-source-baseline.ps1` → `PASS: all six repositories match the frozen baseline; zero drift (clean repos clean, dirty repos exactly 5 dirty files with matching DiffSha256); source-baseline.md CoverageStatus all within nine-state set`. Snapshot written to `docs/scope/baseline-snapshot.txt` (UTC `2026-08-15T03:26:50Z`).
- All six `rev-parse HEAD` == frozen commits; AionUi/ArcVideo/ArcVideoFoundation clean-check skips + dirty-check DiffSha256 recomputed and equal to register (`1f87a590…`, `3302eb6c…`, `9ccbbea3…`). AFFiNE/siyuan/Serial-Studio verified clean; each `describe --tags --always` matches. **Zero drift.**

**Gate (00.01 Completion gate):** source-baseline.md + baseline-snapshot.txt exist; 6 commits verbatim match §1; workspace clean/dirty matches `source-coverage-register.md` current snapshot per-repo; the 5 dirty tracked files' Coverage/Feature rows are `NeedsRecheck` (`AF-F-AIONUI-0283, AF-F-AIONUI-0285, AF-F-ARCV-0065, AF-F-ARCV-0069, AF-F-ARCVF-0011`; coverage `SC-AION-03/05, SC-AV-01/04, SC-AVF-02`); nine-state machine complete; every subsystem has exactly one current state; drift process executable (trigger + update path). The 5 `NeedsRecheck` remain flagged — Step 00 does not claim full closure until they are re-reviewed.

**Evidence / notes:**
- Baseline table, verification snapshot, nine-state state machine, 27 per-repo per-subsystem status rows (fixed 13-column shape; states ∈ nine-state set), drift process. Docs-only; read-only source verification only.
- `StartArcForges` static packaged oracle: not enumerated as executable evidence; static-only, `NotExecuted` (no runtime launch).

**Commit:** (this commit)
**Next safe action:** 00.02 source subsystem feature inventory.

---