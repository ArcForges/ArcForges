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
| Managed taxonomy | `dotnet test --solution ArcForges.slnx -c Release --no-build --no-restore -p:ArcForgesManagedTestTaxonomy=true --filter-trait Category=Unit Category=Integration Category=Contract Category=Ui Category=Architecture` | Passed; 114 total, 91 passed, 23 skipped, 0 failed |
| Architecture + policy | `dotnet test --project tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --no-build --no-restore` | Passed; 38 total, 37 passed, 1 skipped |
| Desktop Native AOT | `dotnet publish src/<Product>/<Product>.Desktop -c Release -r win-x64` then `<Product>.Desktop.exe --smoke` | Passed for all four heads; see [aot-baseline.md](aot-baseline.md) |
| ContentSandbox Native AOT | `dotnet publish src/DesktopHelpers/ArcForges.ContentSandbox -c Release -r win-x64` | Passed; 969,216-byte native image, 0 IL2026/IL3050 |
| Cloud JIT | publish framework-dependent, then `/health`, `/`, SignalR negotiate, Server vs Workstation GC idle | Passed; see [runtime-baseline.md](runtime-baseline.md) |

The 23 skips are the `PendingScopeTests` markers Step 01.03 requires — one per cross-boundary test project,
each naming its owning step and unlock condition. They are visible un-reached scope, not silent passes.

## Executed earlier

| Check | Environment | Result |
|---|---|---|
| Android package | Windows | `android-arm64` Mono AOT signed APK publish passed locally, 2026-08-13 |
| CMake native x64 | Windows | both `windows-msvc-x64-*` profiles: build + CTest + install + managed P/Invoke passed locally, 2026-08-13 |
| Independent VCXPROJ x64 | Windows | `MSBuild win.slnx /p:Configuration=Release /p:Platform=x64` + managed P/Invoke passed locally, 2026-08-13 |
| Deep native/security | weekly/manual | C# CodeQL, Linux clang-tidy, ASan/UBSan, libFuzzer — reported by the Deep check workflow; not a pull-request blocker |

## Required by Step 01 and NOT executed

These are the reverse-failure drills the plan makes release-blocking. None of them has archived evidence, so
Step 01 cannot close. Each needs a deliberately broken branch pushed to CI, which this review did not do.

| Drill | Plan source | Expected failure |
|---|---|---|
| Tamper one `packages.lock.json` version | 01.01 | `dotnet restore --locked-mode` fails naming the lock/project mismatch |
| Add an inline `Version="1.0.0"` to one `PackageReference` | 01.01 | `VerifyNoInlinePackageVersions` fails naming the project and package |
| Add any preview-suffixed package | 01.01 | preview gate fails; only the one audited AndroidX transitive is allowlisted |
| Compile each of the 26 ARC fixtures in the violating direction | 01.04 | the matching rule fails with its rule ID and the offending reference path |
| Inject `[UnconditionalSuppressMessage]` without the four-part justification, and one with `Scope=module` | 01.05 | the suppression audit fails naming the line and the missing segment |
| Inject a reflection path into a desktop head | 01.05 | Release build fails with IL2026/IL3050 on the exact line |
| Five CI violation drills (lock, ARC-004, missing SPDX, unregistered package, IL2026) | 01.06 | the corresponding job goes red and the summary names the rule |
| Turn off `PublishAot` on a desktop head; turn it on for Cloud | 01.07 | desktop publish gate fails; Cloud AOT is rejected by the property-file test |

## Required by Step 01 and structurally missing

| Gap | Plan source |
|---|---|
| `pr-gate.yml` has none of the ten mandated stable job names (`locked-restore`, `format-analyzers`, `build`, `unit-tests`, `integration-tests`, `architecture-tests`, `suppression-audit`, `no-inline-versions`, `dependency-audit`, `secret-scan`) | 01.06 |
| No `runtime-publish-smoke.yml` (the desktop 5-RID × 4-head matrix plus the separate Cloud JIT job) | 01.06 |
| `release-train.yml` has none of the seven mandated `train-*` jobs, and no gated placeholder emits skip reason, owning step and tracking item | 01.06 |
| ArchitectureTests scan source text instead of running `NetArchTest.Rules` over the loaded `src` assemblies with Roslyn-compiled violation fixtures | 01.01 / 01.04 |
| 19 of the 25 Native AOT publish cells have no runner | 01.07 |
