# Foundation Verification Evidence

Local results never impersonate hosted CI. GitHub run IDs are added only after the hosted job actually
executes; until then a row says where it ran.

## Executed — Step 01 foundation review, 2026-08-28

Windows 11 Pro for Workstations 10.0.26200, .NET SDK 10.0.400, branch `feat/af01-00-foundation-review`.

| Check | Command | Result |
|---|---|---|
| Locked restore | `dotnet restore ArcForges.slnx --locked-mode` | Passed; `git status` clean afterwards |
| Format | `dotnet format ArcForges.slnx --verify-no-changes --no-restore` | Passed |
| Release build | `dotnet build ArcForges.slnx -c Release --no-restore` | Passed; 0 warnings, 0 errors across 166 managed projects |
| Managed taxonomy | `dotnet test --solution ArcForges.slnx -c Release --no-build --no-restore -p:ArcForgesManagedTestTaxonomy=true --filter-trait Category=Unit Category=Integration Category=Contract Category=Ui Category=Architecture` | Passed; 115 total, 92 passed, 23 skipped, 0 failed |
| Architecture + policy | `dotnet test --project tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --no-build --no-restore` | Passed; 39 total, 38 passed, 1 skipped |
| Desktop Native AOT | `dotnet publish src/<Product>/<Product>.Desktop -c Release -r win-x64` then `<Product>.Desktop.exe --smoke` | Passed for all four heads; see [aot-baseline.md](aot-baseline.md) |
| ContentSandbox Native AOT | `dotnet publish src/DesktopHelpers/ArcForges.ContentSandbox -c Release -r win-x64` | Passed; 969,216-byte native image, 0 IL2026/IL3050 |
| Cloud JIT | publish framework-dependent, then `/health`, `/`, SignalR negotiate, Server vs Workstation GC idle | Passed; see [runtime-baseline.md](runtime-baseline.md) |

The 23 skips are the `PendingScopeTests` markers Step 01.03 requires — one per cross-boundary test project,
each naming its owning step and unlock condition. They are visible un-reached scope, not silent passes.

## Reverse-failure drills executed, 2026-08-28

Each was injected, observed red with the offending name in the message, and reverted; `git status` was clean
afterwards.

| Injected violation | Rule | Observed failure |
|---|---|---|
| Extra `Contracts.Sync -> Contracts.Agent` ProjectReference | `RepositoryPolicyTests.ContractProjectsMatchTheFixedReferenceGraph` | failed, `Actual: "ArcForges.Contracts.Agent"` at index 0 |
| Removed the `rpc-attach.props` import from `ArcSlate.LocalRpc` | `RepositoryPolicyTests.LayeredBuildPropertyFilesAreImportedByExactlyTheirDeclaredHosts` | failed, expected set contained `ArcSlate.LocalRpc`, actual set did not |
| Added `desktop-aot.props` to `ArcForges.Cloud.Host` | same rule | failed, `Actual: "ArcForges.Cloud.Host"` in the desktop-AOT host set |

These cover the layout §3 contract graph and the Step 01.05 property-file boundary. They do **not** discharge
the drills listed below, which are separate rules.

## Reverse-failure drills — Step 01.01 supply-chain gates, 2026-08-28

Windows 11 Pro for Workstations 10.0.26200, .NET SDK 10.0.400, branch `feat/af01-01-step-01-closure`.
Each violation was injected, the gate was observed red with the offending name in its own message, and the
injection was reverted; the gate was then re-run green and `git status --porcelain --untracked-files=all`
was empty.

| # | Injected violation | Gate and command | Observed failure | Reverted |
|---|---|---|---|---|
| 1 | `"resolved": "10.0.400"` → `"10.0.300"` in `src/Contracts/ArcForges.Contracts.Foundation/packages.lock.json`, project `obj` cleared so restore could not no-op | `dotnet restore src/Contracts/ArcForges.Contracts.Foundation/ArcForges.Contracts.Foundation.csproj --locked-mode` | exit 1 — `error NU1403: Package content hash validation failed for Microsoft.CodeAnalysis.NetAnalyzers.10.0.300. The package is different than the last restore.` | yes; re-run exit 0 |
| 2 | `<PackageReference Include="Markdig" Version="1.0.0" />` added to `ArcForges.Contracts.Foundation.csproj` | `VerifyNoInlinePackageVersions` via `dotnet restore src/Contracts/ArcForges.Contracts.Foundation/ArcForges.Contracts.Foundation.csproj` | exit 1 — `eng\build\NoInlineVersions.targets(8,5): error : Inline NuGet versions are forbidden. Move these packages to Directory.Packages.props: Markdig [...\ArcForges.Contracts.Foundation.csproj]` — names both project and package | yes |
| 3 | `Contoso.Preview.Probe/1.0.0-beta.1` added to the same lock file | `dotnet test --project tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --no-build --no-restore --filter-method '*LockedPackagesContainNoUnapprovedPreviewVersions*'` | exit 2 — `Unapproved preview packages: src\Contracts\ArcForges.Contracts.Foundation\packages.lock.json: Contoso.Preview.Probe/1.0.0-beta.1` | yes; re-run exit 0 |

Drill 1 note: a lock tamper does **not** invalidate NuGet's no-op restore check, which hashes project inputs
rather than the lock file. A first attempt returned exit 0 for that reason. The drill is only meaningful with
the project's `obj` directory cleared, which is what a clean CI checkout always gives; the recorded run above
clears it explicitly.

## Reverse-failure drill — Step 01.02 contract internals grant, 2026-08-28

| Injected violation | Gate | Observed failure | Reverted |
|---|---|---|---|
| Dropped the `ArcForges.Tests.RealtimeReconnectTests` grant from `eng/build/contracts.props` | `RepositoryPolicyTests.ContractAssembliesGrantInternalsToTheContractTestProjects` | exit 2 — `Assert.Equal() Failure: Collections differ`, `Actual` missing `ArcForges.Tests.RealtimeReconnectTests` | yes; re-run exit 0 |

## Step 01.04 — architecture rules rebuilt on assemblies and the project graph, 2026-08-28

`tests/ArchitectureTests` now references `NetArchTest.Rules` and every production project under `src/`
(all but the `net10.0-android` MAUI head and the Blazor WebAssembly head, which a `net10.0` test assembly
cannot reference and which are covered by the project-graph engine instead).

| Check | Command | Result |
|---|---|---|
| Architecture suite | `dotnet test --project tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --no-build --no-restore` | Passed; **41 total, 41 passed, 0 skipped** |
| Full managed taxonomy | `dotnet test --solution ArcForges.slnx -c Release --no-build --no-restore -p:ArcForgesManagedTestTaxonomy=true --filter-trait Category=Unit Category=Integration Category=Contract Category=Ui Category=Architecture` | Passed; 117 total, 95 passed, 22 skipped, 0 failed |
| Release build | `dotnet build ArcForges.slnx -c Release --no-restore` | Passed; 0 warnings, 0 errors |
| Format | `dotnet format ArcForges.slnx --verify-no-changes --no-restore` | Passed |
| Locked restore | `dotnet restore ArcForges.slnx --locked-mode` | Passed |

**The 13 violation fixtures are no longer a one-time drill.** Each rule owns a permanent
`ViolationFixtureFailsTheRule` test that compiles or materialises its fixture on every run and asserts the
rule fails with a message starting `[ARC-0XX <rule name>] ` and containing ` -> `. A rule that stops
detecting its own violation now turns the suite red by itself.

| Drill | Rule | Observed failure | Reverted |
|---|---|---|---|
| Added `<PackageReference Include="Microsoft.Data.Sqlite" />` to `src/ArcNotes/ArcNotes.Domain/ArcNotes.Domain.csproj` (the end-to-end drill Step 01.04 names) | `ARC001DomainHasNoExternalDependenciesTests` | exit 2 — `[ARC-001 Domain has no external dependencies] ArcNotes.Domain -> Microsoft.Data.Sqlite` | yes; suite back to 41/41 |
| Indirect edge `ArcChat.Domain -> ArcChat.Indirection -> Microsoft.Data.Sqlite` (fixture `ARC001TransitiveViolation.cs.txt`) | `AnIndirectForbiddenEdgeAlsoFailsAndNamesThePath` | permanent test; asserts the failure names the whole path | n/a — runs every build |

Two `NetArchTest.Rules 1.3.2` behaviours were established empirically while building this and are recorded
because either one silently produces a green rule that checks nothing:

- it converts Cecil definitions to runtime `Type`s and **drops** those the CLR cannot resolve, so a rule run
  over an unloaded file passes having analysed zero types. Assemblies are loaded before analysis, and
  `ArchitectureSurfaceTests` fails when the analysed surface is implausibly small;
- its dependency search **never matches a term ending in `.`** — `"Android"` matches, `"Android."` does not.

## Executed earlier

| Check | Environment | Result |
|---|---|---|
| Android package | Windows | `android-arm64` Mono AOT signed APK publish passed locally, 2026-08-13 |
| CMake native x64 | Windows | both `windows-msvc-x64-*` profiles: build + CTest + install + managed P/Invoke passed locally, 2026-08-13 |
| Independent VCXPROJ x64 | Windows | `MSBuild win.slnx /p:Configuration=Release /p:Platform=x64` + managed P/Invoke passed locally, 2026-08-13 |
| Deep native/security | weekly/manual | C# CodeQL, Linux clang-tidy, ASan/UBSan, libFuzzer — reported by the Deep check workflow; not a pull-request blocker |

## Required by Step 01 and NOT executed

These are the reverse-failure drills the plan makes release-blocking. Each remaining row still has no archived
evidence, so Step 01 cannot close on them. The three Step 01.01 drills were discharged above.

| Drill | Plan source | Expected failure |
|---|---|---|
| Inject `[UnconditionalSuppressMessage]` without the four-part justification, and one with `Scope=module` | 01.05 | the suppression audit fails naming the line and the missing segment |
| Inject a reflection path into a desktop head | 01.05 | Release build fails with IL2026/IL3050 on the exact line |
| Five CI violation drills (lock, ARC-004, missing SPDX, unregistered package, IL2026) | 01.06 | the corresponding job goes red and the summary names the rule |
| Turn off `PublishAot` on a desktop head | 01.07 | the desktop publish gate fails (the Cloud half of this drill is already executed above) |

## Required by Step 01 and structurally missing

| Gap | Plan source |
|---|---|
| `pr-gate.yml` has none of the ten mandated stable job names (`locked-restore`, `format-analyzers`, `build`, `unit-tests`, `integration-tests`, `architecture-tests`, `suppression-audit`, `no-inline-versions`, `dependency-audit`, `secret-scan`) | 01.06 |
| No `runtime-publish-smoke.yml` (the desktop 5-RID × 4-head matrix plus the separate Cloud JIT job) | 01.06 |
| `release-train.yml` has none of the seven mandated `train-*` jobs, and no gated placeholder emits skip reason, owning step and tracking item | 01.06 |
| 19 of the 25 Native AOT publish cells have no runner | 01.07 |
