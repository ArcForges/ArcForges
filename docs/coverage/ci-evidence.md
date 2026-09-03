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

At the Step 01.06 checkpoint, `pr-gate.yml` declared the ten mandated gate names, `runtime-publish-smoke.yml`
existed with the desktop matrix and two separate Cloud jobs, and `release-train.yml` declared all seven
`train-*` jobs. The later authorized CI topology change removed only the redundant standalone `build` gate;
the current `pr-gate.yml` retains the nine remaining managed names, which are asserted by
`RepositoryPolicyTests.MandatedCiJobNamesArePresent`. The two gated placeholders are asserted to declare skip
reason, owning step and tracking item by
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

## Step 02.00 — Contracts.Foundation stable primitives, 2026-08-29

Windows 11 Pro for Workstations 10.0.26200, .NET SDK 10.0.400, branch `feat/af02-00-contracts-foundation`.

| Check | Command | Result |
|---|---|---|
| Locked restore | `dotnet restore ArcForges.slnx --locked-mode` | Passed |
| Format | `dotnet format ArcForges.slnx --verify-no-changes --no-restore` | Passed |
| Release build | `dotnet build ArcForges.slnx -c Release --no-restore` | Passed; 0 warnings, 0 errors |
| Full managed taxonomy | `dotnet test --solution ArcForges.slnx -c Release --no-build --no-restore -p:ArcForgesManagedTestTaxonomy=true --filter-trait Category=Unit Category=Integration Category=Contract Category=Ui Category=Architecture` | Passed; **300 total, 280 passed, 20 skipped, 0 failed** |
| Contract compatibility | `dotnet test --project tests/ContractCompatibilityTests/ArcForges.Tests.ContractCompatibilityTests.csproj -c Release --no-build --no-restore` | Passed; 111 total, 111 passed |
| Contract schema | `dotnet test --project tests/ContractSchemaTests/ArcForges.Tests.ContractSchemaTests.csproj -c Release --no-build --no-restore` | Passed; 69 total, 69 passed |
| Architecture + policy | `dotnet test --project tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --no-build --no-restore` | Passed; 48 total, 48 passed |

### Reverse-failure drills

| Injected violation | Gate | Observed failure | Reverted |
|---|---|---|---|
| Changed `"revision":7` to `8` in `golden/foundation/v1/resource-ref-local.json` | `FoundationGoldenTests.SerialisingTheFixtureProducesTheCommittedBytes` | exit 2 — `Assert.Equal() Failure: Strings differ` | yes |
| `Contracts.Foundation` given a ProjectReference to `ArcForges.Foundation` plus a `typeof` usage | `RepositoryPolicyTests.ContractFoundationEmitsNoForbiddenAssemblyReference`, `ARC-005`, and the contract reference graph | exit 2, three tests red — `ArcForges.Contracts.Foundation references: ArcForges.Foundation` and `[ARC-005 Contracts stay pure] ArcForges.Contracts.Foundation -> ArcForges.Foundation` | yes |

Two results from these drills are worth recording because they bound what the gates can prove.

**A `const` usage emits no assembly reference.** The purity drill first probed
`ArcForges.Foundation.AssemblyPlaceholder.Name`, a `const string`, and the emitted-reference assertion did
*not* fire — the compiler inlines constants, so no reference is written. Redone with `typeof(...)`, which does
emit one, all three gates fired. This is precisely why the declared-graph rule (ARC-005) is the primary purity
gate and the emitted-reference check only complements it.

**Deleting a `[JsonSerializable]` for a still-reachable type does not fail coverage, correctly.** Removing the
registration for `LocalResourceLocator` left the coverage assertion green, because the generator still emits
metadata for it through `ResourceRef`. Having compile-time metadata is the property that matters for Native
AOT, so that is what the gate asserts. A type that is neither listed nor reachable does fail: `ErrorCategory`
was exactly that case and the gate caught it during development, and `UnregisteredProbe` holds the behaviour
in place permanently.

## Step 02.00 — Ninja/sccache build split, 2026-08-30

Windows 11 Pro for Workstations 10.0.26200, Visual Studio 18 Community MSVC x64, CMake 4.3, Ninja,
sccache 0.17.0, vcpkg `36677bbd0b3bf11da7376e62e14bffcc54d2eaeb` at `C:\vcpkg`, branch
`feat/af02-00-contracts-foundation`.

The Visual Studio CMake generators are gone; every preset is Ninja and is named for the RID it produces, so
one name serves the configure, build and test preset. `win.slnx` moved out of CI and into a Windows-only
`pre-push` hook.

The managed PR gate keeps Release compilation in the self-contained `unit-tests` and `integration-tests`
jobs immediately before their `--no-build` test slices. The standalone `build` job and its separate Debug
compilation are intentionally not part of the PR gate; this documents the CI topology and is not a hosted
CI result.

| Check | Command | Result |
|---|---|---|
| Preset inventory | `cmake --list-presets` / `--list-presets=build` / `=test` | Passed; only the `win-x64-*` presets are offered on this host, the `linux-x64-*`/`osx-*` presets are filtered out by their `hostSystemName` conditions |
| CMake runtime-shared | `cmake --preset win-x64-runtime-shared`, `cmake --build --preset win-x64-runtime-shared`, `cmake --install artifacts/cmake/win-x64/runtime-shared` | Passed; configure, build and install all succeeded |
| CTest runtime-shared | `ctest --preset win-x64-runtime-shared --output-on-failure` | Passed; 1/1 tests passed |
| CMake shim-static | `cmake --preset win-x64-shim-static`, `cmake --build --preset win-x64-shim-static`, `cmake --install artifacts/cmake/win-x64/shim-static` | Passed; configure, build and install all succeeded |
| CTest shim-static | `ctest --preset win-x64-shim-static --output-on-failure` | Passed; 4/4 tests passed |
| sccache cold | `sccache --zero-stats`, both presets, `sccache --show-stats` | `Compile requests 15`, `Cache hits 0`, `Cache misses 15`, **`Non-cacheable compilations 0`** |
| sccache warm | rebuild from a clean binary directory against the same `SCCACHE_DIR`, `sccache --show-stats` | `Compile requests 15`, **`Cache hits 15`**, `Cache misses 0`, hit rate `100.00%`, `Non-cacheable compilations 0` |
| Managed P/Invoke over CMake artifacts | `ArcForges.Tests.NativeAbiTests.exe` against the DLLs staged into `artifacts/stage/native/win-x64/native` | Passed; `Total: 2, Errors: 0, Failed: 0, Skipped: 1` |
| `win.slnx` pre-push hook | `pre-commit run --hook-stage pre-push win-slnx-release-x64` | Passed; MSBuild located through `vswhere`, all five `.vcxproj` built, `Build succeeded. 0 Warning(s) 0 Error(s) Time Elapsed 00:00:17.50` |
| Hook stage separation | `pre-commit run --all-files` (default stage) | Passed; runs `clang-format` only — the `pre-push` hook is not selected, which is what keeps the Ubuntu repository-hooks job free of MSBuild |
| Workflow syntax | all four workflows and `.pre-commit-config.yaml` parsed with a duplicate-key-strict YAML loader | Passed; no duplicate keys. `grep -rniE 'msbuild\|win\.slnx' .github/` returns only the pull-request template checklist item |
| Pinned sccache identity | local `sccache --version`; `curl` the Linux musl release tarball and `sha256sum` it | `sccache 0.17.0` on Windows. `sccache-v0.17.0-x86_64-unknown-linux-musl.tar.gz` hashes to `67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006`, which is exactly the `SCCACHE_SHA256` pinned in `deep-check.yml` |
| Locked restore | `dotnet restore ArcForges.slnx --locked-mode` | Passed; all projects up to date |
| Format | `dotnet format ArcForges.slnx --verify-no-changes --no-restore` | Passed; no output |
| Release build | `dotnet build ArcForges.slnx -c Release --no-restore` | Passed; 0 warnings, 0 errors |
| Full managed taxonomy | `dotnet test --solution ArcForges.slnx -c Release --no-build --no-restore -p:ArcForgesManagedTestTaxonomy=true --filter-trait Category=Unit Category=Integration Category=Contract Category=Ui Category=Architecture` | Passed; 300 total, 0 failed — unchanged by the build split |
| Architecture + policy | `dotnet test --project tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --no-build --no-restore` | Passed; 48 total, 0 failed, 0 skipped. `RepositoryPolicyTests` still finds the vcpkg toolchain line in the rewritten `CMakePresets.json`, still finds no tracked `.ps1`/`.sh`, and still finds `vcpkg.exe integrate install` in `deploy/README.md` |

### `vcvars64.bat` overwrites `VCPKG_ROOT`

Ninja needs `cl.exe` on `PATH`, so a Windows CMake build now has to run inside `vcvars64.bat`. Probing the
variable either side of that call showed it is not preserved:

```
before  VCPKG_ROOT=C:\vcpkg
after   VCPKG_ROOT=C:\Program Files\Microsoft Visual Studio\18\Community\VC\vcpkg
```

`implementation-repository-layout.md` §9.1 pins one vcpkg baseline and lock file as the only dependency
root, and the substitution is not a harmless duplicate: configure failed in `FindFFMPEG.cmake` against the
Visual Studio copy. Every
Windows CMake entry point — the local run, `pr-gate.yml`, and `release-train.yml` — now captures the pinned
value into `ARCFORGES_VCPKG_ROOT` before `vcvars64.bat` and restores it after, and `pr-gate.yml` fails the
job if the restore did not take.

### `Embedded` debug information is what makes MSVC cacheable

`CMAKE_MSVC_DEBUG_INFORMATION_FORMAT=$<$<CONFIG:Debug,RelWithDebInfo>:Embedded>` is not a style choice.
Separate PDB files make every MSVC compilation non-cacheable, so sccache would report a healthy-looking
`Compile requests` count with a permanent 0% hit rate. The `Non-cacheable compilations` assertion in both
workflows is there to fail loudly if anything reintroduces `/Zi`.

### Not executed here

No Linux host was available in this scope. The `linux-x64-*` presets were validated by parsing and by
`cmake --list-presets` on Windows — which confirms they are well-formed and correctly host-filtered, and
nothing more. Their compile, CTest, and sccache behaviour is asserted by `deep-check.yml`, and this document
does not claim a Linux result that was not produced.

## Executed earlier

| Check | Environment | Result |
|---|---|---|
| Android package | Windows | `android-arm64` Mono AOT signed APK publish passed locally, 2026-08-13 |
| CMake native x64 | Windows | both `windows-msvc-x64-*` profiles: build + CTest + install + managed P/Invoke passed locally, 2026-08-13. Superseded on 2026-08-30 by the Ninja `win-x64-*` presets recorded above |
| Independent VCXPROJ x64 | Windows | `MSBuild win.slnx /p:Configuration=Release /p:Platform=x64` + managed P/Invoke passed locally, 2026-08-13. Now covered by the `win-slnx-release-x64` `pre-push` hook rather than by CI |
| Deep native/security | weekly/manual | C# CodeQL, Linux clang-tidy, ASan/UBSan, libFuzzer — reported by the Deep check workflow; not a pull-request blocker |

## Executed — Step 02.01 Contracts.LocalRpc StreamJsonRpc interface contracts, 2026-09-02

Windows 11, .NET SDK 10.0.400, branch `feat/af02-01-contracts-localrpc`.

| Check | Command | Result |
|---|---|---|
| Locked restore | `dotnet restore ArcForges.slnx --locked-mode` | Passed; all projects up to date with zero lockfile drift |
| Format | `dotnet format ArcForges.slnx --verify-no-changes --no-restore` | Passed; zero formatting errors |
| Release build | `dotnet build ArcForges.slnx -c Release --no-restore` | Passed; 0 warnings, 0 errors across all 166 projects |
| Contract compatibility tests | `dotnet test tests/ContractCompatibilityTests/ArcForges.Tests.ContractCompatibilityTests.csproj -c Release` | Passed; **162 total, 162 passed, 0 failed**. All 18 LocalRpc golden samples asserted for byte equality, structural round-trip, and repeatability |
| Contract schema tests | `dotnet test tests/ContractSchemaTests/ArcForges.Tests.ContractSchemaTests.csproj -c Release` | Passed; **75 total, 75 passed, 0 failed**. Manifest and golden document schema verified without internals grant |
| Architecture + policy | `dotnet test tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release` | Passed; **48 total, 48 passed, 0 failed**. ARC-007 (interface signature purity) and ARC-009 (proxy export & GenerateShape) verified with positive and counter-evidence |
| Managed test taxonomy | `dotnet test --solution ArcForges.slnx -c Release --no-build --filter "Category!=Browser&Category!=NativeAbi"` | Passed; 337 passed, 21 skipped (`PendingScopeTests` future milestones), 0 failed |

