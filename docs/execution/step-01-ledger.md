# Step 01 — Solution & Repository Foundation — execution ledger

Authority: `ArchitectureDesign/ArcForgesReWrite-AllCsharp - Paddle/01-solution-and-repository-foundation.md`.
This ledger is the durable resume state for Step 01. Where it disagrees with a pull-request body or a
completion claim, Git objects and test artifacts win.

## Status

**Step 01 is OPEN.** Its file-level completion gate is not satisfied. The repository carries the full 166-project
skeleton and it builds and tests clean, but four of the eight closure conditions have no evidence and cannot get
it on a single Windows host.

## How Step 01 reached this state

Step 01 was never executed as a numbered plan step. There is no `feat/af01-*` branch, no Step 01 pull request
and no `Step 01.NN` commit in the history before this branch. The solution, property files, native shims and CI
landed through pull requests #8–#20, ahead of Step 00, and Step 00 later merged as #18 and #29. Consequently
several Step 01 deliverables were never checked against the step file. This branch is the first review that
does that check.

## Owning substeps

| Substep | State | Evidence |
|---|---|---|
| 01.00 Repository and solution skeleton | Satisfied | 166 managed projects, 5 `.vcxproj`, 6 native shims, the 13 top-level files and the required directories are asserted by `RepositoryPolicyTests.RepositoryLayoutMatchesFoundationContract` |
| 01.01 Central package management, locked restore, version policy | Satisfied | Package table corrected in the review run; locked restore is clean; the three reverse-failure drills (lock tamper → NU1403, inline `Version=` → `VerifyNoInlinePackageVersions`, preview package → preview gate) were executed, observed red with the offending name, reverted and re-run green — recorded in [ci-evidence.md](../coverage/ci-evidence.md) |
| 01.02 BuildingBlocks and Contracts skeleton | Satisfied | 13 + 7 projects build and test; `contracts.props` now imported; the layout §3 contract reference graph is pinned edge-by-edge by `RepositoryPolicyTests.ContractProjectsMatchTheFixedReferenceGraph`, with a recorded reverse-failure drill. The `InternalsVisibleTo` grant Step 02 lists as a Required Input is declared once in `contracts.props` and pinned against emitted metadata by `RepositoryPolicyTests.ContractAssembliesGrantInternalsToTheContractTestProjects`, with its own recorded drill |
| 01.03 Product / Cloud / Mobile / Web skeleton | Satisfied | ContentSandbox is now a five-RID Native AOT head, the composition-root seam exists and is tested, Mobile identity corrected, bUnit skeleton added, 24 pending-scope markers present |
| 01.04 ArchitectureTests | **Not satisfied** | 13 rules and 26 fixtures exist and are in the default test chain, but they scan source text instead of running `NetArchTest.Rules` over the loaded assemblies with Roslyn-compiled fixtures |
| 01.05 AOT / trimming properties and analyzers | Partly satisfied | All eight layered property files now reach exactly their declared hosts, pinned by a test with two recorded reverse-failure drills; **the two suppression drills and the IL2026/IL3050 injection drill have no evidence** |
| 01.06 CI skeleton | **Not satisfied** | None of the ten `pr-gate` job names, no `runtime-publish-smoke.yml`, none of the seven `train-*` jobs, no archived violation drills |
| 01.07 Native AOT / Cloud JIT publish verification | Partly satisfied | 6 of 25 publish cells executed with real artifacts; Cloud JIT contract smoke and an idle GC comparison executed; **19 cells and the fixed-workload GC baseline have no runner** |

## Closure gate (01) — condition by condition

| # | Condition | Verdict |
|---|---|---|
| 1 | Clean checkout builds and tests green; 166 projects; tree matches layout | **Met** — from a wiped `artifacts/`: locked restore clean with a clean tree afterwards, `dotnet format --verify-no-changes` clean, Release build 0 warnings / 0 errors, managed taxonomy 115 total / 92 passed / 23 skipped / 0 failed |
| 2 | Locked restore real; three violation classes each have reproducible failure evidence | **Met** — locked restore is real and leaves a clean tree; all three drills executed, observed red naming the offender, and reverted green (ci-evidence.md, Step 01.01 section) |
| 3 | ARC-001..ARC-013 machine-enforced with 26 fixtures | **Not met** — enforcement is source-text scanning, not assembly analysis |
| 4 | Five runtime configurations never cross | **Met** — pinned by `LayeredBuildPropertyFilesAreImportedByExactlyTheirDeclaredHosts`, with two recorded reverse-failure drills (a dropped `rpc-attach.props` import and `desktop-aot.props` reaching the Cloud host) |
| 5 | Desktop 20-cell matrix plus Cloud JIT smoke and GC report | **Not met** — 4 of 20 desktop cells; GC data is idle-only |
| 6 | CI green and referable by stable job name | **Not met** — the mandated job names do not exist |
| 7 | Zero business code | **Met** — no domain types, contract DTOs, RPC methods, tables or business routes |
| 8 | AGPL LICENSE, SPDX in CI, license register backfilled, deviations recorded | **Met** — register updated this run; deviations and ADR 0001 added |

## Commits on this branch

| Substep | Commit | Subject |
|---|---|---|
| 01.01 | `423d3cc` | remove the Node browser driver and restore the frozen package table |
| 01.02 | `675ace3` | import contracts.props into the seven contract projects |
| 01.03 | `db5cb68` | complete the desktop skeleton the plan requires |
| 01.05 | `6d82397` | attach rpc-attach.props to its hosts and gate every layered property file |
| 01.07 | `1e2bbfd` | record the real publish evidence and open this ledger |
| review | `09f5d97` | fix findings from the whole-scope self-review |
| 01.02 | `d85a7c0` | pin the layout §3 contract reference graph with a reverse-failure drill |
| ledger | this commit / branch tip | final ledger accuracy pass |

The complete ordered SHA list is in the pull-request body; per the execution rules a commit does not embed its
own SHA here.

## Findings fixed in this run

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
| A | ArchitectureTests do not use `NetArchTest.Rules` or Roslyn fixture compilation (01.01 pins the framework, 01.04 requires assembly analysis over all `src` assemblies). The current scan cannot see transitive assembly references, so a Domain reaching a DB provider indirectly would pass. `NetArchTest.Rules 1.3.2` is pinned centrally and referenced by nothing. | Replacing the suite is a rewrite of Step 01.04's core deliverable, not a narrow review fix. It needs its own change with its own reverse-failure evidence. |
| B | `pr-gate.yml`, `release-train.yml` and the missing `runtime-publish-smoke.yml` do not carry the job names every later step's gate references. | Restructuring the gate renames the required checks on a protected workflow. That needs explicit authorization, since it can block every open pull request. |
| C | 19 of 25 Native AOT publish cells, the fixed-workload GC baseline, and the graceful-shutdown cell have no runner. | Needs `windows-arm64`, `macos-x64`, `macos-arm64` and `ubuntu` runners. ILC cannot cross-compile from this host. |
| D | Every reverse-failure drill in 01.01, 01.04, 01.05 and 01.06 is unarchived. | Each needs a deliberately broken branch pushed to CI and a red run recorded. |

## Design conflicts requiring a planning writeback

| Conflict | Detail |
|---|---|
| Step 01.02 contract reference bullets vs layout §3 — **repaired** | Written back in the planning repository on `docs/af01-contracts-reference-graph`, commit `ec3f9ed`. Both bullets now restate §3's graph and the testing requirement asserts the whole edge set. |
| Layout §12 vs the resolved package versions | Six entries differ. See `docs/adr/0001-dependency-version-drift.md`. §12 stays frozen for now: writing it back before the regression matrix has run would launder an unevidenced change into the authority document. Run the matrix first, then write back. |
| Layout §3 root namespace for `ArcForges.Contracts.Foundation` | §3 assigns the namespace `ArcForges.Contracts` while every sibling uses its own project name. The project currently uses `ArcForges.Contracts.Foundation`, and Step 02.00 states the namespace is `ArcForges.Contracts.Foundation` in its own body. Step 02 owns the types; the plan should state which is intended before then. |
| `InternalsVisibleTo` grantee set omits `ContractSchemaTests` | Step 02's Required Inputs names exactly four grantees (ContractCompatibility / Architecture / PublicApiContract / RealtimeReconnect), which is what 01.02 implements verbatim. But Step 02's own Scope line puts the contract test baseline in `tests/{ContractSchemaTests,ContractCompatibilityTests,PublicApiContractTests,RealtimeReconnectTests,LocalRpcAotTests}`, and 02.00's source-generation-coverage assertion has to reach an `internal FoundationJsonContext`. If that assertion lands in `ContractSchemaTests` it will not compile. Step 02 must either place the assertion in a granted assembly or add the fifth grantee to its Required Inputs; 01.02 does not widen the set on its own. |

## Exact next action

Implement Step 01.04 properly: add the `NetArchTest.Rules` package reference and references to the `src`
assemblies to `tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj`, rewrite the 13 rules as
assembly-graph assertions, compile the 26 `Fixtures/ARC0XX*.cs`/`.cs.txt` pairs with Roslyn at test time, and
assert each rule fails on its violation fixture with a message carrying the rule ID and the offending reference
path. Do it on a branch of its own, off this one, and do not touch the CI workflows in the same change.
