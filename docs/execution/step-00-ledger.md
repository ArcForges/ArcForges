# Step 00 — Scope & Source Inventory : Execution Ledger

> Canonical continuation ledger for the local review of Step 00. The review is docs-only and
> remains honest about the final gate: a generated bridge does not close `NeedsRecheck`, and the
> historical PR #18 is not a continuation target.

- Active step: `00-scope-and-source-inventory.md` (whole-step mode)
- Review branch: `feat/af00-scope-source-inventory-reboot` (the supplied original branch)
- Review worktree: `C:\MyFile\ArcForges\ArcForges\.worktree\af00-scope-source-inventory-reboot`
- Review parent: `ed6a89494389df4b7ece643e235b3816866e0acb`
- Frozen target base: `origin/main` (`96c02e7f829a9e19c0a787d4996fb2428c404ad7`)
- Related remote PR: PR #18 on this branch; the local review commit is not pushed, commented on,
  or used to reopen the PR.
- Planning-repository writeback: branch `docs/af00-license-matrix-dirty-state`, separate worktree,
  commit `1a918eb9f2f287139c642bcf247662bbae9d7d9a`; no planning-repository PR.
- Review date: 2026-08-15 (Asia/Shanghai; command evidence records UTC where available).

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
- local SHA-256: `e7e5768f879ce5607f0fcf37a504c433b3e9423a76481f620dd107f74834b41`

The bridge output is recorded at `artifacts/evidence/traceability/feature-trace-bridge.json`; the
exact result and policy boundary are recorded in `docs/execution/step-00-review-validation.md`.
It does not close any `NeedsRecheck` row.

**Commit:** `2542287395a46ddbc7f0a6637f2ba5110a6c5a60` — `Step 00.06: branch/PR sequencing & traceability seed`.

## Review correction commit

One target-repository atomic docs/evidence commit contains the ledger, review evidence, static
packaged-oracle evidence, corrected quick-reference/deviation text, corrected source-index wording,
and the machine-readable bridge only; no product code, source repository, build file, CI workflow,
or helper script is in scope.

**Commit:** this final review commit — `docs: reconcile Step 00 review evidence` (the final SHA is
  recorded in the handoff after the ledger is amended).

## Final whole-scope audit after the review commit

- `git status --short` → empty; the supplied original worktree is clean and one commit ahead of
  its remote PR #18 branch; target main and planning writeback worktrees also remain clean.
- `git diff HEAD^ HEAD --check` → no output; `git ls-files '*.ps1' '*.sh'` → empty output.
- Inline bridge assertion against the current planning files → `inventory=833`, `bridge=833`,
  `missing=0`, `extra=0`; `coverage=27`, `bridge=27`, `missing=0`, `extra=0`; `records=24`,
  `top=BridgeGenerationRequired`, `statuses=NeedsRecheck`; artifact SHA-256
  `e7e5768f8793ce5607f0fcf37a504c433b3e9423a76481f620dd107f74834b41`.
- Inline source-index assertion → `ipcGroups=41`, `declaredTokens=315`; copied-code manifest
  parse → `copiedCodeRows=6`, `uniqueManifestIds=6`.
- Inline packaged-oracle assertion using sorted `product-relative-path|file-length` records,
  UTF-8/LF encoding, and a final LF → `records=11297`, manifest hash
  `0e16e92490e1986b71f2b0186ee0a0fe4212119e5eade4b0b3d7f35cd95b143d`; evidence file contains
  the same hash and `Status=NotExecuted`.

## Whole-scope review result

**Status:** **BLOCKED — Step 00 cannot claim closure.**

**Findings fixed locally:** stale branch/base/PR continuation claims; stale commit SHAs; stale
86-feature bridge claim; missing static packaged-oracle record; plan license-matrix dirty-state
conflict; tracked-helper-script policy wording; source-index group-vs-atomic denominator wording.

**Remaining blockers/findings:**

1. The five dirty source files and their five coverage rows remain authoritative `NeedsRecheck`;
   source/current-worktree overlays have not been reconciled against clean frozen-baseline evidence.
2. The planning feature inventory still has grouped ipcBridge cells, so independent member-row
   closure is not yet evidenced even though the source-subsystem group index names all 315 tokens.

**Risk:** claiming completion, pushing, or opening a PR would present an unreviewed source overlay
and a non-atomic feature denominator as closed evidence.

**PR state:** no PR was created by this review. Historical PR #18 remains untouched.

**Safe resume action:** in a clean worktree for each frozen source commit, reread the five dirty
paths and exact diffs; reconcile `source-coverage-register.md`, the feature-inventory statuses,
the planning license matrix, and the independent ipcBridge member rows; regenerate the bridge;
rerun the final production gate and whole-scope review; only then push this review branch and open
exactly one new PR titled `Step 00: Scope & Source Inventory`.
