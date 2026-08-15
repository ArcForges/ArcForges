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

**Commit:** `1dd5f0b6039aacc8a79bbadf51e197e1ded4d41c` `Step 00.01: source baseline & coverage state machine`
**Next safe action:** 00.02 source subsystem feature inventory.

---

## 00.02 — 来源子系统功能清单

**Status:** COMPLETE
**Deliverables:** `docs/scope/source-subsystems.md`, `docs/tools/check-source-coverage.ps1`

**Validation (exact command + result + evidence):**
- `pwsh -NoProfile -File docs/tools/check-source-coverage.ps1` → `OK: ipcBridge member coverage — 277 members, diff set empty` + `PASS: check-source-coverage — ipcBridge members covered, 3 columns non-empty, SS-PRO all Replace/O4, AFFINE-BE all ReferenceOnly, siyuan all ReferenceOnly/O3`.
- ipcBridge member anti-inventory: members extracted from `ipcBridge.ts@29c9271a` via brace-depth parse (41 export groups, 277 members); every member token present in `source-subsystems.md` (diff set empty). Reverse-failure holds: deleting a member's row → diff non-empty.

**Gate (00.02 Completion gate):** 6-source per-subsystem independent rows, `DecisionClass`/`OracleClass`/`OwningStep` non-empty, zero orphan paths (path existence sampled); completeness script green; Pro/EE/siyuan rows carry UD-LIC constraints (`SS-PRO` all `Replace`+`O4` UD-LIC-5; `AFFINE-BE` all `ReferenceOnly` UD-LIC-4; siyuan `ReferenceOnly`+`O3` UD-LIC-3). Subsystem-level inventory merged per-source aligned to `feature-inventory-and-mapping.md` canonical `AF-F-*` IDs.

**Evidence / notes:**
- Sections: 1 AionUi desktop (1.1 ipcBridge 41 export-group rows w/ all members; 1.2 chatLib message model + 8 merge-rule rows; 1.3 storage config types + 13-table; 1.4 renderer pages/comps; 1.5 process; 1.6 i18n 13-language), 2 AionUi mobile (WS protocol / messageAdapter·grouping·JWT / 7-class gap / publish-credential Replace / wss+TLS), 3 AFFiNE blocksuite (per-package, Yjs/CRDT Drop), 4 AFFiNE BE (ReferenceOnly EE), 5 siyuan (ReferenceOnly/O3), 6 Serial-Studio (core Copy GPL / Pro Replace O4 / LIB per-dependency), 7 ArcVideo, 8 ArcVideoFoundation, 9 serial-merge + completeness binding.
- Docs-only; no code/solution produced.

**Commit:** `fa11f26f2550525db396ff58732441723897e986` `Step 00.02: source subsystem feature inventory`
**Next safe action:** 00.03 license & reuse matrix (license-summary).

---

## 00.03 — 许可证与复用矩阵

**Status:** COMPLETE
**Deliverables:** `docs/scope/license-summary.md`, `docs/tools/check-license.ps1`

**Validation (exact command + result + evidence):**
- `pwsh -NoProfile -File docs/tools/check-license.ps1` → `PASS: check-license — evidence paths, brand blacklist, Pro/EE isolation all green`. Evidence: `docs/tools/check-license.ps1`; plus a §2/§3 plan-matrix scan confirming 12 §2 rows (four columns non-empty) and 15 §3 vendored rows (all decisions non-empty).

**Gate (00.03 Completion gate):** license-summary.md complete; evidence script green (AionUi Apache-2.0 LICENSE + agentModes SPDX, AFFiNE EE ×2 + blocksuite MIT ×5 sample, siyuan AGPL, Serial-Studio BUILD_COMMERCIAL, ArcVideo/Foundation GPL ×2, StartArcForges as `NotExecuted` static oracle); UD-LIC-1..5 cards with file-level evidence + constraint + impact steps; AGPL-obligation → owning-step table; decision-class ↔ manifest mapping; compliance-closing 8 items bound to FG rows + steps; brand blacklist on target naming zero hits; Pro/EE isolation (SS-PRO all Replace/O4 UD-LIC-5, AFFINE-BE all ReferenceOnly UD-LIC-4). Reverse-evidence holds (flipping an SS-PRO row to Copy → isolation assertion fails citing UD-LIC-5).

**Evidence / notes:** Docs-only; no code/solution.

**Commit:** `1e1eda2e13364c51239b8745cb77b307569d80a3` `Step 00.03: license & reuse matrix summary`
**Next safe action:** 00.04 reuse manifests (5).

---

## 00.04 — 复用 Manifest（结构与首批条目）

**Status:** COMPLETE
**Deliverables:** `docs/compliance/{copied-code.md,copied-code.json,copied-asset.md,independent-reimplementation.md,replacement-backlog.md,third-party-license-register.md}`, `docs/tools/check-manifests.ps1`

**Validation (exact command + result + evidence):**
- `pwsh -NoProfile -File docs/tools/check-manifests.ps1` → `PASS: check-manifests — 5+ manifests present, copied-code rows complete+unique, UD-LIC-2..5 covered, suspicious-IP Replace-only, review/third-party baseline present`.
- copied-code.json parsed: 6 first-batch rows, all `ManifestId/SourcePath/SourceRepository/SourceCommit/OriginalLicense/TargetProduct/TargetProject/ReuseType/TemporaryOrPermanent/Attribution/ReleaseRestriction/Evidence` non-empty, ids unique.

**Gate (00.04 Completion gate):** 5 manifests under `docs/compliance/` with complete field structure + first-batch rows; every ManifestId/AssetId/ItemId unique; UD-LIC-2/3/4/5 each referenced by ≥1 manifest row; `SuspiciousThirdPartyIp=true` entries are `Status=Replace` and never in a normal `TargetPath` row; third-party register carries the frozen layout §4.1 baseline (Avalonia 12.1.1, Silk.NET 2.23.0, DOX 3.5.1, SkiaSharp 4.151.1, CSharpMath.SkiaSharp 0.5.1, TextMateSharp 2.0.4, Markdig 1.3.2, AngleSharp 1.7.1, FFmpeg 9.0.1, vcpkg checkout `36677bbd0...`); prohibited families (Nerdbank.MessagePack/Fory/AvaloniaEdit/ClosedXML/CSharpMath.Avalonia/NAudio/SqlSugar/Dapper/managed FFmpeg binding) not present as entries; QuaZip→System.IO.Compression/OpenSSL→.NET TLS/KissFFT→oracle notes. Existing Step-01 register extended (FFmpeg corrected to frozen 9.0.1), not clobbered. Reverse-evidence: dropping copied-code CM-0001 → decision-coverage still green but FeatureId evidence spot-check fails and reports the missing ManifestId.

**Evidence / notes:** Docs-only; no code/solution.

**Commit:** (this commit)
**Next safe action:** 00.05 verification oracles & golden samples.

---