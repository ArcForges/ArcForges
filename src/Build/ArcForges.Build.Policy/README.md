# ArcForges.Build.Policy

Portable MSBuild defaults and enforcement for C# 14 repositories: nullable, deterministic builds,
warnings-as-errors, package locks, central package versions and AOT/trim warning escalation.
This build-only AGPL-3.0-only package contains no runtime assembly or native dependency.

Declare the exact version in your repository's `Directory.Packages.props` and reference the package
with `PrivateAssets="all"`. Each repository owns its `global.json`, target frameworks, runtime/AOT host
settings and package locks. This package never invokes CMake/vcpkg and does not set output/cache paths.
Normal NuGet `build/` imports activate after restore; it intentionally does not flow transitively.

Diagnostics AFP001–AFP003 reject missing central management, inline overrides and floating versions;
AFP004–AFP005 reject compiler-policy or lock-policy overrides. Invalid package graphs may additionally
be rejected directly by NuGet. Check compiler settings with `dotnet msbuild -getProperty:LangVersion`.

Owned assemblies also expose `AssemblyMetadataAttribute` keys `ArcForges.SourceCommit`,
`ArcForges.BuildId`, `ArcForges.PipelineRun`, `ArcForges.SourceDateEpoch` and `ArcForges.BuildKind`.
CI identity uses the full Git SHA and actual GitHub run ID/attempt, with the commit timestamp in
Unix seconds; this deterministic source time is not wall-clock compilation time. AFP006 rejects
incomplete or mismatched CI identity. Non-repository local consumer fixtures remain explicitly
local (source `local`, epoch `0` when Git metadata is unavailable) and cannot establish publication.
The owner's candidate tooling separately seals dirty state and rejects dirty/local publication.

The package also carries one shared C# architecture-policy engine in `tools/architecture`.
An offline test host explicitly imports `$(PkgArcForges_Build_Policy)/tools/architecture/ArchitecturePolicy.props`
after declaring the package with `GeneratePathProperty="true"` and `PrivateAssets="all"`.
It uses the compiler binaries from that host's selected .NET SDK, with no additional Roslyn NuGet dependency.
The import rejects production hosts unless they explicitly identify themselves as a build tool.
There is no automatic architecture target in normal consumer builds.

The host supplies complete reviewed project classifications, evaluated MSBuild source/reference inputs,
resolved package licences, exact toolchain input hashes, individual API-to-contract-test mappings,
and owned, expiring exceptions. `ProjectGraph.Evaluate` uses the completed locked owning build;
`ReadCompilation` reads compiler metadata without loading production assemblies. `PolicyEngine.Check`
checks AT-01–AT-14, RP-01–RP-10 and seven semantic banned-symbol categories. Unknown project references,
cycles, unclassified dependencies, missing compilations and unresolved invocations fail closed.
Generated service/wire bindings belong to the consumer's canonical schema authority.

RP-01/RP-08 consume the canonical naming package result; RP-09 consumes the existing required secret gate.
DesktopPlatform joins their same-source, same-run, same-attempt receipts before its actual graph test.
Local runs without that hosted secret evidence remain unverified and fail the complete graph assertion;
they must not manufacture a successful secret receipt. Offline fixtures remain independently runnable.
The producer retains compiled positive/negative fixtures for every rule and explicit current API mappings
under `eng/policy/architecture-*.json`. A correspondence is a test contract, not a claim of runtime coverage.
