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

**Commit:** (this commit / branch tip — recorded below at each commit)
**Next safe action:** 00.01 source baseline + coverage state machine.

---