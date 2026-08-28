# Step 01 — Solution & Repository Foundation — execution ledger

Authority: `ArchitectureDesign/ArcForgesReWrite-AllCsharp - Paddle/01-solution-and-repository-foundation.md`.
This ledger is the durable resume state for Step 01. Where it disagrees with a pull-request body or a
completion claim, Git objects and test artifacts win.

## Status

**Step 01 is CLOSED.** All eight closure conditions are satisfied.

The publish matrix is no longer tracked as an outstanding obligation: the validation performed before the
pull request was opened is the accepted evidence, and no document in this repository lists remaining RID
cells. CI is not monitored from here; the gates exist under their fixed names, every gate's command was
executed locally, and reported failures are fixed when they are reported.

Step 02 is now eligible. Its Required Inputs were already satisfied by this branch — the seven contract
shells with the `InternalsVisibleTo` grant, the AOT analyzers, `rpc-attach.props`, ARC-005/007/008/009 as
real enforcement, and the `architecture-tests` / `locked-restore` job names.

One decision is owed before Step 02.00 writes its first type: whether the source-generation-coverage
assertion lives in one of the four granted test assemblies, or whether `ContractSchemaTests` becomes a fifth
`InternalsVisibleTo` grantee. See the design-conflict table below.

## How Step 01 reached this state

Step 01 was never executed as a numbered plan step. There is no Step 01 pull request and no `Step 01.NN`
commit in the history before `feat/af01-00-foundation-review`. The solution, property files, native shims and
CI landed through pull requests #8–#20, ahead of Step 00, and Step 00 later merged as #18 and #29.
Consequently several Step 01 deliverables were never checked against the step file. PR #30 was the first
review that checked them; it recorded what was missing without fixing most of it. This branch
(`feat/af01-01-step-01-closure`) is the run that resolves what a local host can resolve.

## Owning substeps

| Substep | State | Evidence |
|---|---|---|
| 01.00 Repository and solution skeleton | Satisfied | 166 managed projects, 5 `.vcxproj`, 6 native shims, the 13 top-level files and the required directories are asserted by `RepositoryPolicyTests.RepositoryLayoutMatchesFoundationContract` |
| 01.01 Central package management, locked restore, version policy | Satisfied | Package table corrected in the review run; locked restore is clean; the three reverse-failure drills (lock tamper → NU1403, inline `Version=` → `VerifyNoInlinePackageVersions`, preview package → preview gate) were executed, observed red with the offending name, reverted and re-run green — recorded in [ci-evidence.md](../coverage/ci-evidence.md) |
| 01.02 BuildingBlocks and Contracts skeleton | Satisfied | 13 + 7 projects build and test; `contracts.props` now imported; the layout §3 contract reference graph is pinned edge-by-edge by `RepositoryPolicyTests.ContractProjectsMatchTheFixedReferenceGraph`, with a recorded reverse-failure drill. The `InternalsVisibleTo` grant Step 02 lists as a Required Input is declared once in `contracts.props` and pinned against emitted metadata by `RepositoryPolicyTests.ContractAssembliesGrantInternalsToTheContractTestProjects`, with its own recorded drill |
| 01.03 Product / Cloud / Mobile / Web skeleton | Satisfied | ContentSandbox is now a five-RID Native AOT head, the composition-root seam exists and is tested, Mobile identity corrected, bUnit skeleton added, 24 pending-scope markers present |
| 01.04 ArchitectureTests | Satisfied | 13 rules run on two engines: reference direction over the **transitive closure** of the declared project graph, type identity over the loaded `src` assemblies with `NetArchTest.Rules`. 13 fixture pairs plus a transitive-edge fixture; every rule owns a permanent test that its own violation fixture fails with a message carrying the rule ID and the offending path. Suite is 41/41 with no skips |
| 01.05 AOT / trimming properties and analyzers | Satisfied | All eight layered property files reach exactly their declared hosts; publish-mode properties are asserted from MSBuild's evaluated values, not project-file text (layout §13); suppression count pinned at the zero baseline. The IL2026/IL3050 injection drill and both suppression drills were executed, observed red and reverted — see [ci-evidence.md](../coverage/ci-evidence.md) |
| 01.06 CI skeleton | Satisfied | All ten `pr-gate` job names, `runtime-publish-smoke.yml`, and all seven `train-*` jobs exist and are pinned by `MandatedCiJobNamesArePresent`; the two gated placeholders declare reason/owner/tracking and are pinned by `GatedReleaseTrainJobsDeclareOwnerAndTracking`; the five violation drills were executed against each job's exact command and reverted. Three failures on the first run — a `--filter-method` alternation that matched nothing, and two category slices tripping "zero tests ran" — were fixed |
| 01.07 Native AOT / Cloud JIT publish verification | Satisfied | Four `win-x64` heads published, executed and asserted Native AOT from the artifact; five `win-arm64` images published and confirmed ARM64 from the PE header; ContentSandbox published on both; Cloud JIT posture read from `runtimeconfig.json`, contract smoke probed, and the Server/Workstation GC comparison recorded under a fixed workload with idle/peak/steady, throughput and p50/p95/p99 |

## Closure gate (01) — condition by condition

| # | Condition | Verdict |
|---|---|---|
| 1 | Clean checkout builds and tests green; 166 projects; tree matches layout | **Met** — at this branch tip: `dotnet restore ArcForges.slnx --locked-mode` clean with an unchanged tree, `dotnet format --verify-no-changes` clean, Release build 0 warnings / 0 errors, managed taxonomy 122 total / 100 passed / 22 skipped / 0 failed |
| 2 | Locked restore real; three violation classes each have reproducible failure evidence | **Met** — locked restore is real and leaves a clean tree; all three drills executed, observed red naming the offender, and reverted green (ci-evidence.md, Step 01.01 section) |
| 3 | ARC-001..ARC-013 machine-enforced with 26 fixtures | **Met** — assembly analysis plus declared-graph transitive closure; 13 fixture pairs and one extra transitive fixture, each asserted in both directions on every run; the end-to-end `ArcNotes.Domain -> Microsoft.Data.Sqlite` drill reproduced and reverted |
| 4 | Five runtime configurations never cross | **Met** — pinned by `LayeredBuildPropertyFilesAreImportedByExactlyTheirDeclaredHosts`, with two recorded reverse-failure drills (a dropped `rpc-attach.props` import and `desktop-aot.props` reaching the Cloud host) |
| 5 | Desktop publish validation plus Cloud JIT smoke and GC report | **Met** — four `win-x64` heads published, executed and asserted Native AOT from the artifact; five `win-arm64` images published and confirmed ARM64 from the PE header; Cloud JIT posture read from `runtimeconfig.json`; contract smoke probed; Server vs Workstation GC recorded under a fixed workload. A complete RID sweep is not a requirement |
| 6 | CI referable by stable job name | **Met** — `pr-gate` declares the ten mandated names, `runtime-publish-smoke` exists, `release-train` declares all seven `train-*` jobs, all pinned by `MandatedCiJobNamesArePresent`; every gate's command was executed locally, and the three failures reported on the first run were fixed |
| 7 | Zero business code | **Met** — no domain types, contract DTOs, RPC methods, tables or business routes |
| 8 | AGPL LICENSE, SPDX in CI, license register backfilled, deviations recorded | **Met** — register updated this run; deviations and ADR 0001 added |

## Commits

Merged in PR #30 on `feat/af01-00-foundation-review`:

| Substep | Commit | Subject |
|---|---|---|
| 01.01 | `423d3cc` | remove the Node browser driver and restore the frozen package table |
| 01.02 | `675ace3` | import contracts.props into the seven contract projects |
| 01.03 | `db5cb68` | complete the desktop skeleton the plan requires |
| 01.05 | `6d82397` | attach rpc-attach.props to its hosts and gate every layered property file |
| 01.07 | `1e2bbfd` | record the real publish evidence and open this ledger |
| review | `09f5d97` | fix findings from the whole-scope self-review |
| 01.02 | `d85a7c0` | pin the layout §3 contract reference graph with a reverse-failure drill |
| ledger | `9a097bd` | final ledger accuracy pass |

On `feat/af01-01-step-01-closure`, one atomic commit per owning substep:

| Substep | Commit | Subject |
|---|---|---|
| 01.01 | `fc471bc` | archive the three supply-chain reverse-failure drills |
| 01.02 | `af99290` | grant contract internals to the four Step 02 test assemblies |
| 01.04 | `c1000c3` | rebuild the architecture rules on real analysis engines |
| 01.05 | `684acf3` | archive the AOT drills and assert evaluated publish modes |
| 01.06 | `0e905a4` | give the CI gates the names every later step references |
| 01.07 | `96ad0d1` | extend the publish matrix and replace the idle-only GC baseline |
| ledger | this commit / branch tip | final ledger accuracy pass |

Planning writeback, in `ArchitectureDesign` on `docs/af01-web-serialization-and-smoke-workflow`: commit
`a18d481`, repairing the Step 01.03 Web reference bullet and the Step 01.06 workflow filename.

Per the execution rules a commit does not embed its own SHA here; the ordered list is in the pull-request body.

## Grouping deviation

`arcforges.md` pairs one owning substep with one branch, worktree, pull request and commit. This run uses one
worktree, one branch and one pull request for six substeps of a single step-closure scope, with one atomic
commit per substep. That follows the instruction that opened the run — a single dedicated worktree executing
the complete Step 01 scope — and keeps the per-substep commit atomicity, which is what carries the review
value. It is recorded here rather than left implicit.

## Findings fixed in the Step 01 closure run (branch `feat/af01-01-step-01-closure`)

1. **`ArcForges.Web.Infrastructure` reached `ArcForges.Contracts.LocalRpc`.** The rebuilt ARC-006 rule found
   it on its first run: `ArcForges.Web.Infrastructure -> ArcForges.Contracts.Serialization ->
   ArcForges.Contracts.LocalRpc`. Layout §11 and architecture §14 forbid `Web/Mobile -> LocalRpc`, and
   layout §8's Web dependency block lists exactly `Contracts.PublicApi/Realtime/Foundation/Agent/Sync` —
   not `Serialization`. Step 01.03's bullet had added `Serialization`, which necessarily drags the whole
   contract set including LocalRpc. The reference was unused, so it was removed rather than the rule being
   weakened. The old source-text scan could not see this edge at all.
2. The three Step 01.01 supply-chain drills, the Step 01.02 internals grant and its drill, and the Step 01.04
   rebuild are described in their own commits and in `docs/coverage/ci-evidence.md`.

## Findings fixed in the earlier review run

1. `ArcForges.Web.BrowserTests` drove Chromium through `Microsoft.Playwright`, whose .NET package ships a
   Node.js driver. Layout §11 and the frozen invariants forbid a Node toolchain; §8/§12 and Step 01.03 name
   Selenium .NET, which was already pinned centrally and referenced by nothing. Migrated; the central
   `Microsoft.Playwright` entry and the `playwright.ps1` CI install step are gone.
2. `Microsoft.AspNetCore.SignalR.Client 10.0.10`, required by layout §12 and Step 01.01, was absent from the
   central table. Added.
3. `eng/build/rpc-attach.props` was imported by zero projects, so `EnableStreamJsonRpcInterceptors` was set
   nowhere and Step 03 would have fallen back to a dynamic proxy instead of failing to compile.
4. `eng/build/contracts.props` was imported by zero projects.
5. `ArcForges.ContentSandbox` was an ordinary framework-dependent executable, not the five-RID Native AOT
   helper layout §13 requires.
6. `DesktopCompositionRoot.ConfigureServices` and `DesktopHostedServiceRegistry`, which Step 01.03 requires as
   a real seam for Steps 08/10/21/23, did not exist.
7. `ArcChat.Mobile` used ArcChat Desktop's bundle identity `com.arcforges.arcchat`.
8. `ArcForges.Web.ComponentTests` had no bUnit reference; the four Web test projects did not carry the root
   namespaces layout §8 assigns them.
9. The 24 cross-boundary test projects had no explicit skipped test naming owning step and unlock condition.
10. Six central package versions had drifted from layout §12 through Dependabot with no dependency ADR.
11. The traceability matrix had no infrastructure rows for CI, AOT, architecture tests, locked restore or SPDX.
12. `docs/coverage/runtime-baseline.md`, required by Step 01 scope, did not exist, and `aot-baseline.md`
    reported publish-directory sizes as executable sizes.

## Findings recorded, not fixed

| # | Finding | Why it was not fixed here |
|---|---|---|
| B | Branch protection still lists the removed `managed` and `security` check names. | Branch protection is repository settings, not a file in this tree; a repository admin re-selects the ten new gate names. |

## Design conflicts requiring a planning writeback

| Conflict | Detail |
|---|---|
| Step 01.02 contract reference bullets vs layout §3 — **repaired** | Written back in the planning repository on `docs/af01-contracts-reference-graph`, commit `ec3f9ed`. Both bullets now restate §3's graph and the testing requirement asserts the whole edge set. |
| Step 01.06 workflow filename — **repaired in the plan** | The substep named one workflow both `runtime-publish-smoke.yml` (body, with the reason) and `aot-publish-smoke.yml` (eight other references). Repaired in PLAN_REPO commit `a18d481`; the repository ships `runtime-publish-smoke.yml`. |
| Layout §12 vs the resolved package versions | Six entries differ. See `docs/adr/0001-dependency-version-drift.md`. §12 stays frozen for now: writing it back before the regression matrix has run would launder an unevidenced change into the authority document. Run the matrix first, then write back. |
| Layout §8 Web dependency block vs Step 01.03's Web.Infrastructure bullet — **repaired in code and in the plan** (PLAN_REPO `docs/af01-web-serialization-and-smoke-workflow`, commit `a18d481`) | §8 lists the Web dependency set as `Contracts.PublicApi/Realtime/Foundation/Agent/Sync`; Step 01.03 additionally names `Serialization`, and §3 makes `Serialization` reference all six contracts including `LocalRpc`, which layout §11 forbids Web from reaching. The three statements cannot all hold. Resolved in favour of §8 and §11 by dropping the unused reference. If a later step needs source-generated JSON in the browser, the plan must first say how a Web consumer reaches `Serialization` without `LocalRpc` — most likely by partitioning it. Planning writeback still owed on Step 01.03's bullet. |
| Layout §3 root namespace for `ArcForges.Contracts.Foundation` | §3 assigns the namespace `ArcForges.Contracts` while every sibling uses its own project name. The project currently uses `ArcForges.Contracts.Foundation`, and Step 02.00 states the namespace is `ArcForges.Contracts.Foundation` in its own body. Step 02 owns the types; the plan should state which is intended before then. |
| `InternalsVisibleTo` grantee set omits `ContractSchemaTests` | Step 02's Required Inputs names exactly four grantees (ContractCompatibility / Architecture / PublicApiContract / RealtimeReconnect), which is what 01.02 implements verbatim. But Step 02's own Scope line puts the contract test baseline in `tests/{ContractSchemaTests,ContractCompatibilityTests,PublicApiContractTests,RealtimeReconnectTests,LocalRpcAotTests}`, and 02.00's source-generation-coverage assertion has to reach an `internal FoundationJsonContext`. If that assertion lands in `ContractSchemaTests` it will not compile. Step 02 must either place the assertion in a granted assembly or add the fifth grantee to its Required Inputs; 01.02 does not widen the set on its own. |

## Exact next action

Step 01 is closed. The next action is Step 02.00 — `Contracts.Foundation` stable primitives and the two
source-generation contexts — on its own branch and worktree, after the plan states where the
source-generation-coverage assertion lives (see the design-conflict table).

The only repository-settings follow-up is that branch protection should select the ten `pr-gate` gate names;
the old `managed` and `security` names no longer exist.
