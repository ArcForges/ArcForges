# Step 00 — Scope & Source Inventory : Execution Ledger

> Canonical continuation ledger for Step 00. Substeps 00.00–00.06 were implemented and merged into
> `main` via PR #18; this ledger records that history and the subsequent docs-only review passes. It
> stays honest about the final gate: a generated bridge does not close `NeedsRecheck`, the five
> authoritative source overlays keep Step 00 from full closure, and a merged PR is history — never a
> continuation, reopen, or push target.

- Active step: `00-scope-and-source-inventory.md` (whole-step mode)
- Implementation of record: merged via PR #18 (branch `feat/af00-scope-source-inventory-reboot`),
  merge commit `a2fa9273893878a8642b5bf96aeb4d6de5ddec29`. That branch/PR is closed history and is
  never reopened, pushed to, commented on, or reused.
- Current review branch: `feat/af00-scope-source-inventory-review`
- Current review worktree: `C:\MyFile\ArcForges\ArcForges\.worktree\af00-scope-source-inventory-review`
- Frozen target base: `origin/main` (`bad05dfb2d0d314a2a5cf9b2edb4ff09f3e8adb8`)
- Planning-repository writeback (prior review, still current): branch
  `docs/af00-license-matrix-dirty-state`, separate worktree, commit
  `1a918eb9f2f287139c642bcf247662bbae9d7d9a`; no planning-repository PR. This review adds no new
  planning-repository writeback (the plan chain is already consistent).
- Review dates: 2026-08-15 (initial review, merged via PR #18) and 2026-08-27 (this review; command
  evidence records UTC where available).

## 00.00 — Freeze product family and scope

**Review status:** structural evidence retained; no target-code scope violation found.

**Files:** `docs/scope/product-family.md`.

**Historical evidence retained:** the original read-only scope assertion recorded the exact seven
  ProductIds, owning steps, ArcNotes staging, platform freeze, and the ArcImage exit/non-target
  whitelist. The helper was removed because tracked `.ps1` files violate the repository policy;
  no replacement executable was added.

**Commit:** `21c2801175f001526f7355dc9f7cd2d1c6bd044a` — `Step 00.00: freeze product family & scope`.

## 00.01 — Source baselines and coverage state machine

**Review status:** source-baseline evidence is consistent; **BLOCKED** by the five authoritative
`NeedsRecheck` overlays.

**Files:** `docs/scope/source-baseline.md`, `docs/scope/baseline-snapshot.txt`,
`docs/scope/packaged-oracle-static-evidence.md`.

**Read-only assertions:** all six frozen HEADs match the planning baseline; AFFiNE, siyuan, and
Serial-Studio are clean; AionUi, ArcVideo, and ArcVideoFoundation match their declared dirty
files and DiffSha256 values. The affected rows remain `NeedsRecheck`:

- Features: `AF-F-AIONUI-0283`, `AF-F-AIONUI-0285`, `AF-F-ARCV-0065`, `AF-F-ARCV-0069`,
  `AF-F-ARCVF-0011`.
- Coverage: `SC-AION-03`, `SC-AION-05`, `SC-AV-01`, `SC-AV-04`, `SC-AVF-02`.

**Packaged oracle:** static inventory only; `StartArcForges` status is `NotExecuted`. Evidence is
in `docs/scope/packaged-oracle-static-evidence.md` with full-tree manifest hash
`0e16e92490e1986b71f2b0186ee0a0fe4212119e5eade4b0b3d7f35cd95b143d`.

**Commit:** `d561f9a0363d86df66186e9c60f547fb29e3d79c` — `Step 00.01: source baseline & coverage state machine`.

## 00.02 — Source subsystem feature inventory

**Review status:** source index corrected; **00.02 atomic-row closure is not claimed** while the
planning inventory still contains grouped ipcBridge cells that require independent member rows.

**File:** `docs/scope/source-subsystems.md`.

**Review findings fixed:** the file now distinguishes its 41-row ipcBridge export-group index from
the final Feature denominator and records the actual 315 named member tokens. The final atomic
container remains the planning-repository `feature-inventory-and-mapping.md`; the index count is
not used as the bridge denominator.

**Outstanding document finding:** several planning-inventory ipcBridge cells still combine multiple
members (for example `application.openDevTools / isDevToolsOpened` and `team.*` event groups), so
the literal 00.02 rule “each export member gets an independent line” needs a planning-inventory
reconciliation before this gate can pass.

**Commit:** `13a4e9460268d575dbc450a01606a5899d8039e3` — `Step 00.02: source subsystem feature inventory`.

## 00.03 — License and reuse matrix

**Review status:** target quick-reference corrected; planning authority repaired in a separate
planning worktree.

**Files:** `docs/scope/license-summary.md`, `docs/deviations.md`.

The quick-reference now points to the static packaged-oracle evidence. The planning matrix §1
records AionUi, ArcVideo, and ArcVideoFoundation as dirty with exact normalized DiffSha256 values;
AFFiNE, siyuan, and Serial-Studio remain clean. The tracked-helper-script conflict is recorded as
a repository-policy deviation; durable CI/test gate repair remains a later planning action.

**Commits:** target `99d02a01198448d95533753722c73a9f7917e02c` — `Step 00.03: license & reuse matrix summary`;
planning writeback `1a918eb9f2f287139c642bcf247662bbae9d7d9a` — `docs: reconcile source worktree license evidence`.

## 00.04 — Five reuse manifests

**Review status:** structure and first-batch evidence retained.

**Files:** `docs/compliance/{copied-code.md,copied-code.json,copied-asset.md,independent-reimplementation.md,replacement-backlog.md,third-party-license-register.md}`.

The copied-code JSON has six unique first-batch rows with the required non-empty fields. The five
Markdown manifests retain the UD-LIC-2..5, suspicious-IP Replace-only, and frozen dependency
baseline entries. No new source reuse or license conclusion was introduced by this review.

**Commit:** `7b95c4d3801330e4ee92d49ea7c99ea1ad7a69fe` — `Step 00.04: five reuse manifests (structure & first-batch entries)`.

## 00.05 — Verification oracles and golden samples

**Review status:** structure retained; no runtime or golden-sample capture was claimed.

**File:** `docs/scope/verification-oracles.md`.

The O1–O7 definitions, eight first-batch catalog entries, red-line rule, storage/provenance rules,
and test-pyramid landing remain present. Golden bodies remain implementation-stage work as the
active scope requires.

**Commit:** `bc9911073f40353c0465469f9c5fb055c5359508` — `Step 00.05: verification oracles & golden samples`.

## 00.06 — Sequencing and traceability seed

**Review status:** bridge structure corrected locally; closure remains blocked.

**Files:** `docs/scope/sequencing.md`, `docs/traceability-matrix.md`,
`docs/execution/step-00-review-validation.md`.

The stale local bridge was rejected (24 records, 86 feature IDs, 27 coverage IDs, abbreviated
baselines, null evidence hashes). A replacement was generated by an inline read-only PowerShell
assertion because the repository policy forbids retaining the plan-mandated helper scripts:

- `records=24`
- `featureIds=833`
- `coverageIds=27`
- `missing=0`, `extra=0`
- `closureState=BridgeGenerationRequired`
- artifact SHA-256 (raw file bytes, reproducible via
  `sha256sum artifacts/evidence/traceability/feature-trace-bridge.json`):
  `f4a8f47549a96e529af5af9582f07a81dd97af73f006ba3c4436c624210a0976`

The bridge output is recorded at `artifacts/evidence/traceability/feature-trace-bridge.json`; the
exact result and policy boundary are recorded in `docs/execution/step-00-review-validation.md`.
It does not close any `NeedsRecheck` row. (2026-08-27 review: the previously recorded hash did not
match the committed artifact — see the Review correction section below — and is replaced by the
reproducible raw-bytes SHA-256 above.)

**Commit:** `2542287395a46ddbc7f0a6637f2ba5110a6c5a60` — `Step 00.06: branch/PR sequencing & traceability seed`.

## Review correction commit (2026-08-27)

One target-repository atomic docs/evidence commit contains this ledger update and the corrected
`docs/execution/step-00-review-validation.md` only; no product code, source repository, build file,
CI workflow, or helper script is in scope. Corrections made by this review:

- Replaced the recorded traceability-bridge artifact hash (previously `e7e5768f…`, which did not
  match the committed file) with the reproducible raw-bytes SHA-256
  `f4a8f47549a96e529af5af9582f07a81dd97af73f006ba3c4436c624210a0976`.
- Refreshed the stale continuation metadata: PR #18 is now merged (main advanced past the recorded
  `96c02e7f…` base to `bad05df…`), so the earlier "not pushed / no PR created" framing is corrected
  to reflect the merged implementation and this review's own branch/PR.
- Recorded this review's read-only source re-verification (see the audit section below).

**Commit:** this commit / branch tip on `feat/af00-scope-source-inventory-review`
(`docs: correct Step 00 traceability-bridge hash and refresh continuation ledger`).

## Final whole-scope audit (2026-08-27 review)

- Read-only source re-verification (no source repository mutated): all six frozen HEADs equal the
  registered commits; AFFiNE, siyuan, and Serial-Studio are clean; AionUi (2), ArcVideo (2), and
  ArcVideoFoundation (1) carry exactly the five registered dirty tracked files. The normalized
  `DiffSha256` values were recomputed (raw `git diff` UTF-8 bytes minus the single trailing newline)
  and match `source-coverage-register.md` §2 exactly: AionUi
  `1f87a590859586a4b64831d54b0292117294dabaef93c71a5fe4bcd377525492`, ArcVideo
  `3302eb6c34d252be675ada195461f746c8965d1c2014280df52e0d51a767030c`, ArcVideoFoundation
  `9ccbbea307352499f5ad55ed6f5eb52176f5f0eff7c20df6d3e77969a9f85a96`. Zero drift.
- Tracked-file denominators re-confirmed against §2 (`git ls-files | wc -l`): AionUi 1968,
  AFFiNE 10056, siyuan 2538, Serial-Studio 3748, ArcVideo 2436, ArcVideoFoundation 48.
- Source-index re-confirmed: AionUi `ipcBridge.ts` has 2039 lines and 41 top-level export groups,
  whose names match `docs/scope/source-subsystems.md` §1.1 (`AF-F-AIONUI-0001..0041`) one-for-one;
  copied-code manifest parse → `copiedCodeRows=6`, `uniqueManifestIds=6`.
- Traceability bridge re-parsed from the committed artifact → `records=24`, unique `featureIds=833`,
  unique `coverageIds=27`, `closureState=BridgeGenerationRequired`; the 24 Markdown `TR-*` rows in
  `docs/traceability-matrix.md` equal the 24 bridge records. Raw-bytes SHA-256 (via
  `sha256sum artifacts/evidence/traceability/feature-trace-bridge.json`):
  `f4a8f47549a96e529af5af9582f07a81dd97af73f006ba3c4436c624210a0976`.
- Packaged-oracle evidence unchanged and internally consistent across three files:
  `records=11297`, manifest hash
  `0e16e92490e1986b71f2b0186ee0a0fe4212119e5eade4b0b3d7f35cd95b143d`, `Status=NotExecuted`.
- Review worktree `git status --short` → empty except this ledger and review-validation edit;
  `git ls-files '*.ps1' '*.sh'` → empty; no product/solution/source/build/CI change in scope.

## Whole-scope review result

**Status:** The 2026-08-27 review-and-correction pass is **complete**; Step 00's **overall closure
remains BLOCKED** by the five authoritative `NeedsRecheck` overlays (unchanged). This PR delivers the
review corrections only and does **not** claim Step 00 closure.

**Findings fixed by the initial (PR #18) review:** stale branch/base/PR continuation claims; stale
86-feature bridge claim; missing static packaged-oracle record; plan license-matrix dirty-state
conflict; tracked-helper-script policy wording; source-index group-vs-atomic denominator wording.

**Findings fixed by this (2026-08-27) review:**

1. The recorded traceability-bridge artifact SHA-256 was wrong and internally inconsistent (a
   63-character malformed value in two places and a differing 64-character value in a third), and
   none matched the committed file. Replaced with the reproducible raw-bytes SHA-256
   `f4a8f47549a96e529af5af9582f07a81dd97af73f006ba3c4436c624210a0976` in this ledger and in
   `step-00-review-validation.md`.
2. The ledger and review-validation narrated a pre-merge "not pushed / no PR created" state on the
   `…-reboot` branch with a `96c02e7f…` base; PR #18 is in fact merged and `main` has advanced to
   `bad05df…`. Refreshed to describe the merged implementation of record plus this review's branch
   and base, and to re-verify the six source baselines (zero drift; §2 counts and DiffSha256 exact).

**Remaining blockers/findings (unchanged authority):**

1. The five dirty source files and their five coverage rows remain authoritative `NeedsRecheck`
   (`SC-AION-03`, `SC-AION-05`, `SC-AV-01`, `SC-AV-04`, `SC-AVF-02`). Source repositories are
   read-only, so re-reading them on a clean frozen checkout or accepting a new baseline is a
   plan-owner action this review cannot perform; the overlays stay open.
2. The planning feature inventory still carries grouped ipcBridge cells, so independent member-row
   closure is a `feature-inventory-and-mapping.md` (planning-repository) action, out of scope for
   this target-evidence review even though the source-subsystem group index names all 315 tokens.

**Risk avoided:** this PR does not present the five `NeedsRecheck` overlays as closed, does not claim
Step 00 completion, and does not touch merged PR #18.

**Safe resume action for Step 00 closure:** in a clean worktree for each frozen source commit,
reread the five dirty paths and exact diffs; reconcile `source-coverage-register.md`, the
feature-inventory statuses, the planning license matrix, and the independent ipcBridge member rows;
regenerate the bridge; rerun the final production gate and whole-scope review. Only that plan-owner
work can move Step 00 to full closure.
