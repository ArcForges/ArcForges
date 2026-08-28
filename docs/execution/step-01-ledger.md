# Step 01 — Solution & Repository Foundation — execution ledger

Authority: `ArchitectureDesign/ArcForgesReWrite-AllCsharp - Paddle/01-solution-and-repository-foundation.md`.
This ledger is the durable resume state for Step 01. Where it disagrees with a pull-request body or a
completion claim, Git objects and test artifacts win.

## Status

**Step 01 is OPEN.** Six of the eight closure conditions are now met. The two that remain — the publish matrix
and hosted CI — are the two that cannot be satisfied from a single Windows host, and the execution rules
forbid watching or polling CI, so neither can close in a local run.

| Condition | Before this run | Now |
|---|---|---|
| 2 — locked restore drills | not met | **met** |
| 3 — ARC-001..013 machine-enforced | not met | **met** |
| 5 — publish matrix and GC report | not met | still not met, materially advanced |
| 6 — CI green under stable job names | not met | still not met, names and gates in place |

Step 02 must not begin. Its own Required Inputs are now all present — the seven contract shells with the
`InternalsVisibleTo` grant, the AOT analyzers, `rpc-attach.props`, ARC-005/007/008/009 as real enforcement,
and the `architecture-tests` / `locked-restore` job names — but `README.md` §4 and `ai-execution-guide.md` §6
gate the next numbered step on the current step's *file-level* gate, and two conditions of it are unmet.

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
| 01.06 CI skeleton | Partly satisfied | All ten `pr-gate` job names, `runtime-publish-smoke.yml`, and all seven `train-*` jobs exist and are pinned by `MandatedCiJobNamesArePresent`; the two gated placeholders declare reason/owner/tracking and are pinned by `GatedReleaseTrainJobsDeclareOwnerAndTracking`; the five violation drills were executed against each job's exact command and reverted. **No hosted run has executed these workflows**, so "CI green under the mandated names" is still unevidenced |
| 01.07 Native AOT / Cloud JIT publish verification | Partly satisfied | 4 of 25 cells published **and** executed (`win-x64` heads); 6 more published but not runnable here (`win-arm64` × 5 confirmed ARM64 by PE header, plus `win-x64` ContentSandbox which has no run contract yet); Cloud JIT posture re-verified from the artifact and the **fixed-workload** Server/Workstation GC baseline now recorded with idle/peak/steady, throughput and p50/p95/p99. **15 cells still need macOS/Linux runners, the `win-arm64` run half needs `windows-11-arm`, and graceful shutdown needs a POSIX host** |

## Closure gate (01) — condition by condition

| # | Condition | Verdict |
|---|---|---|
| 1 | Clean checkout builds and tests green; 166 projects; tree matches layout | **Met** — at this branch tip: `dotnet restore ArcForges.slnx --locked-mode` clean with an unchanged tree, `dotnet format --verify-no-changes` clean, Release build 0 warnings / 0 errors, managed taxonomy 122 total / 100 passed / 22 skipped / 0 failed |
| 2 | Locked restore real; three violation classes each have reproducible failure evidence | **Met** — locked restore is real and leaves a clean tree; all three drills executed, observed red naming the offender, and reverted green (ci-evidence.md, Step 01.01 section) |
| 3 | ARC-001..ARC-013 machine-enforced with 26 fixtures | **Met** — assembly analysis plus declared-graph transitive closure; 13 fixture pairs and one extra transitive fixture, each asserted in both directions on every run; the end-to-end `ArcNotes.Domain -> Microsoft.Data.Sqlite` drill reproduced and reverted |
| 4 | Five runtime configurations never cross | **Met** — pinned by `LayeredBuildPropertyFilesAreImportedByExactlyTheirDeclaredHosts`, with two recorded reverse-failure drills (a dropped `rpc-attach.props` import and `desktop-aot.props` reaching the Cloud host) |
| 5 | Desktop 20-cell matrix plus Cloud JIT smoke and GC report | **Not met** — 4 of 20 desktop cells executed and 4 more published (`win-arm64`); the GC report is no longer idle-only but 15 cells and the POSIX graceful-shutdown cell still have no runner on this host |
| 6 | CI green and referable by stable job name | **Not met** — the names now exist and are test-pinned, and every gate behind them was drilled locally, but no hosted run has produced a green result for them. This run does not watch CI |
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
| B | The renamed required checks have not been re-selected in branch protection. `pr-gate` previously exposed `managed`, `security` and `ci`; it now exposes ten named gates plus `ci`. Until branch protection is updated, the old required check names no longer exist and pull requests can appear blocked or under-gated. | Branch protection is repository settings, not a file in this tree. It has to be changed by a repository admin at merge time. |
| C | No hosted run of `pr-gate`, `runtime-publish-smoke` or `release-train` exists for these files. | The execution rules forbid watching or polling CI. The first hosted run happens when this branch's pull request is opened. |
| D | 15 of 25 publish cells and the graceful-shutdown cell have no runner. | Needs `macos-13`, `macos-latest` and `ubuntu-latest` for the publish half, and `windows-11-arm` to execute the `win-arm64` images. ILC cross-compiles `win-x64` → `win-arm64` from this host, which is why those six cells moved from blocked to published; it cannot cross-compile to macOS or Linux. The fixed-workload GC baseline is now recorded. |
| E | Hosted red runs for the drills are not archived. | Each drill was reproduced locally against the job's exact command; a hosted red run additionally needs a deliberately broken branch pushed, which this run does not do. |

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

Two conditions remain and both need a hosted runner, so the next action is not a code change:

1. Merge this branch's pull request, then **re-select the required status checks in branch protection**. The
   `pr-gate` workflow no longer exposes `managed` and `security`; it exposes `locked-restore`,
   `format-analyzers`, `build`, `unit-tests`, `integration-tests`, `architecture-tests`, `suppression-audit`,
   `no-inline-versions`, `dependency-audit`, `secret-scan`, plus the unchanged `native-win-x64`, `app-smoke`,
   `android-package`, `repository-hooks` and the `ci` aggregate. Until that is done the old required names do
   not exist. This is a repository settings change, not a file in the tree.
2. Run `runtime-publish-smoke` once by `workflow_dispatch` and copy the real results into
   `docs/coverage/aot-baseline.md`: the 15 macOS/Linux publish cells, the `win-arm64` run half on
   `windows-11-arm`, and the POSIX graceful-shutdown cell into `docs/coverage/runtime-baseline.md`.

Condition 6 additionally needs one green hosted `pr-gate` run under the new names. When 5 and 6 both carry
evidence, Step 01 closes and Step 02.00 becomes eligible; its own Required Inputs are already satisfied.

Before Step 02.00 starts, the plan still owes one decision this run deliberately did not make: whether the
source-generation-coverage assertion lives in one of the four granted test assemblies, or whether
`ContractSchemaTests` becomes a fifth `InternalsVisibleTo` grantee. See the design-conflict table above.
