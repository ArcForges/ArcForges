# ADR 0001: Central package versions that differ from `implementation-repository-layout.md` §12

- Status: Accepted (partial — regression evidence incomplete)
- Date: 2026-08-28
- Owner: Step 01.01
- Tracking issue/PR: Step 01 foundation review

## Context

`implementation-repository-layout.md` §12 freezes the exact version of every direct managed dependency and
states that upgrades are not at implementer discretion: each one requires a dependency ADR plus license,
vulnerability, AOT/JIT, memory, and contract-regression evidence.

A Step 01 review of the current `Directory.Packages.props` against §12 found six entries that no longer match
the frozen table. Five arrived through merged Dependabot pull requests and one is an SDK-pack compatibility
override; none of them carried an ADR at the time.

| Package | `implementation-repository-layout.md` §12 | Repository | How it changed |
|---|---|---|---|
| `xunit.v3` | `3.2.2` | `4.0.0` | PR #25 (`Bump xunit.v3 from 3.2.2 to 4.0.0`), migrated to the Microsoft Testing Platform runner in `6e98bd9` |
| `Microsoft.NET.Test.Sdk` | `18.8.1` | `18.9.0` | PR #27 (`Bump the dotnet-foundation group with 3 updates`) |
| `Microsoft.CodeAnalysis.NetAnalyzers` | `10.0.302` | `10.0.400` | PR #27; tracks the pinned `10.0.400` SDK band |
| `Microsoft.Maui.Controls` | `10.0.90` | `10.0.100` | PR #27; matches the installed `maui-android` workload manifest `10.0.20/10.0.100` |
| `Microsoft.AspNetCore.Components.WebAssembly.DevServer` | `10.0.10` | `10.0.11` | Aligns with the `KnownWebAssemblySdkPack` override already recorded in `docs/deviations.md` |
| `Microsoft.AspNetCore.Components.Web` | not listed | `10.0.10` | Razor component surface for `ArcForges.Web.Components`; a `Microsoft.AspNetCore.App` family member at the same pinned version |

`xunit.runner.visualstudio` stays at the frozen `3.1.5` — its `4.0.0` bump (PR #24) was rejected.

## Decision

Keep the resolved versions above and treat `Directory.Packages.props` plus the committed `packages*.lock.json`
set as the restorable truth, rather than reverting to the §12 values. Reverting would itself be an unevidenced
change: it invalidates every committed lock file, and `xunit.v3 3.2.2` cannot host the
`Microsoft.Testing.Platform` runner that `global.json` pins and that `RepositoryPolicyTests` asserts.

Do **not** write `implementation-repository-layout.md` §12 back to these versions yet. §12 freezes them and
requires an upgrade to carry license, vulnerability, AOT/JIT, memory and contract-regression evidence; that
evidence does not exist, so amending the authority document now would launder an unevidenced change into the
plan. §12 stays frozen and this ADR carries the divergence until the regression matrix below has run — then the
writeback lands as one reviewed planning change.

## Consequences

- Licensing is unchanged: every entry keeps the SPDX identifier already recorded in
  `docs/compliance/third-party-license-register.md` (Apache-2.0 for the xUnit/Selenium stack, MIT elsewhere).
- Test-stack changes are confined to test projects; `BenchmarkDotNet`, `Microsoft.Extensions.TimeProvider.Testing`
  and the xUnit stack still have zero production publish closure.
- `Microsoft.Maui.Controls 10.0.100` keeps the one audited prerelease-labeled transitive
  (`Xamarin.AndroidX.Security.SecurityCrypto/1.1.0.4-alpha07`) already allowlisted in `docs/deviations.md`.
- The AOT/JIT, memory and contract regression matrix that §12 demands for an upgrade has **not** been executed
  for these six entries. That gap is release-blocking for Step 01 closure and is recorded as such.

## Isolation and verification

- Executed on Windows, 2026-08-28: `dotnet restore ArcForges.slnx --locked-mode` (clean, no lock churn),
  `dotnet format --verify-no-changes` (clean), `dotnet build ArcForges.slnx -c Release` (0 warnings, 0 errors),
  the managed taxonomy (114 total, 91 passed, 23 skipped), `win-x64` Native AOT publish and `--smoke` for all
  four desktop heads plus ContentSandbox, and the Cloud JIT contract smoke with an idle Server/Workstation GC
  comparison.
- Not executed: the `win-arm64`, `osx-x64`, `osx-arm64` and `linux-x64` AOT cells, the fixed-workload GC
  baseline, and the previous/current contract compatibility matrix. Step 01 stays open until those exist; see
  `docs/coverage/aot-baseline.md` and `docs/coverage/runtime-baseline.md`.
- Rollback: pin each entry back to its §12 value and regenerate every lock file in one dependency pull request.
- Exit criteria, in order: execute and archive the regression matrix above under `docs/coverage/`, then land
  the `implementation-repository-layout.md` §12 writeback as one reviewed planning change. Not the reverse.
