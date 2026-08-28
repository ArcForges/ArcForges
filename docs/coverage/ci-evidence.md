# Foundation Verification Evidence

Every row records a command that was actually run and what it printed. A row says where it ran.

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

## Step 01.05 — suppression and AOT gates, 2026-08-28

| Drill | Gate | Observed failure | Reverted |
|---|---|---|---|
| `JsonSerializer.Serialize(object)` added to `src/ArcChat/ArcChat.Desktop/AotDrillProbe.cs` | Release build of the desktop head | exit 1 — `AotDrillProbe.cs(7,55): error IL2026` *and* `error IL3050`, both naming the exact member and line | yes |
| `[UnconditionalSuppressMessage]` with `Justification = "it is fine"` (no four-part evidence) | `RepositoryPolicyTests.TrimmingSuppressionsCarryReviewEvidence` | exit 2 — `Unreviewed trimming suppressions: src\ArcChat\ArcChat.Desktop\SuppressionDrillProbe.cs:7` | yes |
| `[UnconditionalSuppressMessage]` with all four segments but `Scope = "module"` | same gate | exit 2 — same message; a complete justification does not buy a module-wide suppression | yes |
| `<PublishAot>true</PublishAot>` added to `ArcForges.Cloud.Host.csproj` | `RepositoryPolicyTests.PublishModePropertiesEvaluateToTheirDeclaredValues` | exit 2 — `Assert.Equal() Failure`, `Expected: false`, `Actual: true` | yes |

Two gates were added here. `TrimmingSuppressionCountStaysAtTheStep0105Baseline` pins the count at the Step
01.05 baseline of zero, which is a different question from whether a suppression is well documented.
`PublishModePropertiesEvaluateToTheirDeclaredValues` reads `PublishAot`, `TrimMode`, `PublishTrimmed` and
`RunAOTCompilation` back out of MSBuild's own evaluation for the desktop head, ContentSandbox, the Cloud
host and the WASM head, because `implementation-repository-layout.md` §13 is explicit that a publish mode
must be asserted from the evaluated value rather than from the text of a project file.

## Step 01.06 — CI job-name contract, 2026-08-28

`pr-gate.yml` now declares the ten mandated gate names, `runtime-publish-smoke.yml` exists with the desktop
matrix and two separate Cloud jobs, and `release-train.yml` declares all seven `train-*` jobs. The names are
themselves asserted by `RepositoryPolicyTests.MandatedCiJobNamesArePresent`, and the two gated placeholders
are asserted to declare skip reason, owning step and tracking item by
`GatedReleaseTrainJobsDeclareOwnerAndTracking`, so a placeholder cannot quietly start reading as done work.

The five violation drills Step 01.06 makes release-blocking were executed against the exact command the
corresponding job runs. Each drill was reverted and the tree left clean.

| # | Injected violation | Job whose command was run | Observed failure |
|---|---|---|---|
| 1 | `"resolved": "10.0.400"` → `"10.0.300"` in `src/ArcChat/ArcChat.Domain/packages.lock.json` | `locked-restore` — `dotnet restore ArcForges.slnx --locked-mode` | exit 1 — `error NU1403: Package content hash validation failed for Microsoft.CodeAnalysis.NetAnalyzers.10.0.300` |
| 2 | `ArcNotes.Application` given a ProjectReference to `ArcChat.Domain` | `architecture-tests` | exit 2 — `[ARC-004 Products stay isolated] ArcNotes.Application -> ArcChat.Domain` |
| 3 | New `.cs` file with no SPDX header | `no-inline-versions` | exit 2 — `Missing SPDX header: src\ArcNotes\ArcNotes.Domain\SpdxDrillProbe.cs` |
| 4 | `Contoso.Unregistered.Probe` added to `Directory.Packages.props` | `dependency-audit` | exit 2 — `Packages missing from the third-party license register: Contoso.Unregistered.Probe` |
| 5 | `JsonSerializer.Serialize(object)` in a desktop head | `build` (Release) | exit 1 — `error IL2026` and `error IL3050` on the exact line (recorded under Step 01.05) |

## Gate fixes after the first two CI runs, 2026-08-28

Three gates failed on the first run and two on the second. Every diagnosis below came from the job log, and
each fix was re-run locally against the exact command the job executes.

| Run | Job | Log evidence | Root cause | Fix |
|---|---|---|---|---|
| 1 | `no-inline-versions` | `Zero tests ran`, `Exit code: 5` | `--filter-method '*A*\|*B*'` — Microsoft.Testing.Platform takes repeated values, not pipe alternation, so the filter selected nothing | two space-separated patterns |
| 1 | `unit-tests` | `error: 36`, `total: 6`, `failed: 0`, exit 8 | a single-category filter over the whole solution leaves most assemblies empty, and MTP reports "zero tests ran" as exit 8 per assembly | tolerance for code 8 declared once in `Directory.Build.targets`, scoped to test projects during a taxonomy run |
| 1 | `integration-tests` | `error: 7`, `total: 70`, `failed: 0`, exit 8 | same | same |
| 2 | `unit-tests` | `The unit slice printed no summary.` | the summary line is emitted as `ESC[m  total: 6` — ANSI colour survives the pipe, so the `^\s*total:` anchor could never match | strip ANSI escapes before matching |
| 2 | `integration-tests` | `The integration slice printed no summary.` | same | same |

Run 2 also proved the run-1 fix: both jobs reached the summary check, which only happens after the exit-code
check passes, so exit code 8 was no longer being returned.

The run-2 parser fix was verified before pushing, against both a synthetic line carrying the exact
`ESC[m  total: 6` prefix from the CI log and the real slice output:

| Input | Old anchored regex | New parser |
|---|---|---|
| synthetic ANSI summary line | no match — reproduces the CI failure | `6` |
| real unit slice output | — | `6` |

Both slice steps were then run verbatim, parser included: unit `exit 0, total 6, failed 0`; integration
`exit 0, total 70, failed 0`.

### A duplicate key nearly shipped

While editing the slice steps, an edit inserted the new `run:` block without removing the old one. Two `run:`
keys in one step is legal YAML — the last wins — so the file read as fixed while the job would have kept
executing the old command. `RepositoryPolicyTests.WorkflowStepsDeclareEachKeyOnce` now rejects a repeated
sibling key inside any workflow list item. Drill: re-injecting a second `run:` fails it with
`pr-gate.yml:82 repeats 'run' in one step`; reverted, green.

## Executed earlier

| Check | Environment | Result |
|---|---|---|
| Android package | Windows | `android-arm64` Mono AOT signed APK publish passed locally, 2026-08-13 |
| CMake native x64 | Windows | both `windows-msvc-x64-*` profiles: build + CTest + install + managed P/Invoke passed locally, 2026-08-13 |
| Independent VCXPROJ x64 | Windows | `MSBuild win.slnx /p:Configuration=Release /p:Platform=x64` + managed P/Invoke passed locally, 2026-08-13 |
| Deep native/security | weekly/manual | C# CodeQL, Linux clang-tidy, ASan/UBSan, libFuzzer — reported by the Deep check workflow; not a pull-request blocker |
