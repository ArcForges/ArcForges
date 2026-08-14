# Branch/PR Sequencing & Traceability Seeds

> Freezes the 00–31 merge order, branch/PR naming conventions and the machine-readable Feature/Coverage trace
> bridge contract for the whole implementation sequence. **Branch/PR granularity, one-pr-per-scope and the PR
> body template are authoritative in `arcforges.md`**; this file records naming examples and the order for
> cross-referencing — it never re-defines the process rules.

---

## 1. Branch naming examples

| Mode | Example |
|---|---|
| whole-step | `feat/af02-contracts-and-code-generation` |
| substep | `feat/af02-03-localrpc-hub-interfaces` |
| substep (lettered) | `feat/af10-05-block-editor-core`（`09.16A` → `feat/af09-16-a-native-preview`） |

- Rule: branch = `feat/af<NN>-<slug>` (whole-step) or `feat/af<NN>-<MM>-<slug>` (substep), lowercase `[a-z0-9-]`;
  one active scope = one branch/worktree/PR; never reuse a dead PR's branch name.
- Regex gate: `^feat/af\d{2}(-\d{2})?-[a-z0-9-]+$` (accepted by `docs/tools/check-seq.ps1` and usable for later
  branches).

## 2. PR completion-template fields (tracking only; the execution prompt's PR body is the sole authority)

Implementation PRs carry: changed-file list; added/modified tests; exact commands & results (restore/build/
test/publish raw); skipped GUI/native/packaging items + why; traceability-row updates (FeatureId list);
`final-production-gate.md` impact; per-feature parity list (FeatureId × Oracle × result); design conflicts and
their authoritative writebacks. This file lists the fields, not the process.

## 3. 00–31 sequence & hard ordering constraints (verbatim README §4)

| Step | Title | Gate for "next" |
|---|---|---|
| 00 | Scope & Source Inventory | this file |
| 01 | Solution & Repository Foundation | 01 |
| 02 | Contracts & Code Generation | 02 |
| 03 | Local IPC Foundation | 03 |
| 04 | Persistence & Recovery Foundation | 04 |
| 05 | Domain Foundations | 05 |
| 06 | Shared Desktop Experience Foundation | 06 |
| 07 | High-risk Technical Probes | 07 |
| 08 | ArcChat Hub & Cross-process Slice | 08 |
| 09 | ArcChat Independent Core | 09 |
| 10 | ArcNotes Document Core V1 | 10 |
| 11 | Knowledge & Search Foundation | 11 |
| 12 | First Real Cloud Vertical Slice | 12 |
| 13 | Cloud Agent Harness Runtime | 13 |
| 14 | Remote Tool Bridge & Sync | 14 |
| 15 | ArcNotes Edgeless Canvas | 15 |
| 16 | ArcNotes Multiview Database | 16 |
| 17 | ArcNotes Slides Presentation | 17 |
| 18 | MAUI Shared Architecture | 18 |
| 19 | Android Remote ArcChat | 19 |
| 20 | iOS Architecture (Deferred) | 20 |
| 21 | ArcScope Complete Product | 21 |
| 22 | ArcScope Analysis & UI | 22 |
| 23 | ArcSlate Complete Product | 23 |
| 24 | ArcSlate Native & OTIO | 24 |
| 25 | ArcSlate Render UI & Export | 25 |
| 26 | Cloud Completion | 26 |
| 27 | Extension & Developer Platform | 27 |
| 28 | Dynamic Policy & Configuration | 28 |
| 29 | ArcForges Web Boundary | 29 |
| 30 | Security, Quality & Compatibility | 30 |
| 31 | Quality, Security & Production Release | 31 |

**Hard ordering constraints** (from README §4 and 00-scope-and-source-inventory "前后步骤依赖"):

```
01 → 02 → 03/04 → 05/06 → 07 → 08–12 → 13 (Cloud Agent) → 14 (Remote Tool Bridge / Sync)
→ 15–17 (ArcNotes 扩展) → 18 (MAUI) → 19 (Android) → 20 (iOS architecture)
→ 21–22 (ArcScope) → 23–25 (ArcSlate) → 26 (Cloud 完成) → 27–29 (平台/Web) → 30 (独立审计) → 31 (发布)
```

A step's Completion Gate must be decidable before the next number: step NN's file-level Completion Gate is the
entry criterion for NN+1; no later step may be entered to backfill an earlier gate.

---

## 4. Frozen decisions registration & README §9 recovery-entry update

- Step 00 records the frozen decisions below (mirror of `00-scope-and-source-inventory.md` 末尾"冻结决策与实施核验"):
  1. Sync strategy decided: drop CRDT/Yjs/state-vector/multi-collab; use revision + change feed + durable
     inbox/outbox + conflict copy + explicit resolution (Steps 12/14).
  2. Native interop decided: prefer verified license/AOT-compatible C# binding; else owned narrow C ABI for all
     C++ libraries, invoked via `[LibraryImport]`; never cross the C++ ABI.
  3. **`ArcForges.Foundation` vs `ArcForges.Contracts.Foundation` stable-ID single landing** definitive =**
     `ArcForges.Contracts.Foundation`**（architecture §4 合同表）; `ArcForges.Foundation` keeps only
     non-serialized fundamentals (Guard/`IClock`/correlation); ArchitectureTests enforce single landing.
     Formally recorded at 02.00 and written back to `implementation-repository-layout.md` §2/§3.
  4. Source-coverage state: Step 00 recomputes the frozen source commit/file manifest hashes and verifies zero
     drift; `Unread/Inventoried/unresolved > 0` blocks Step 01. Re-verification is anti-supply-chain-drift, not a
     license to reopen closed product/architecture decisions.
- README §9 recovery entry: after Step 00 evidence is produced and verified in a real implementation repository
  run, Step 00 may be marked complete in `README.md`; the planning/generation phase must not tick that box. Any
  `docs/deviations.md` drift/conflict entry is authoritative for recovery.