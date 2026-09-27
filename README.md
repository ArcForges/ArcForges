# ArcForges DesktopPlatform

Shared desktop mechanisms and native interoperability for ArcChat, ArcNotes, ArcScope and ArcSlate.
This repository owns the CMake/vcpkg toolchain, narrow C ABIs, C# wrappers and capability NuGet packages.
Product applications and services build independently from published packages.

## Current implementation

- Five native shim foundations: media, OpenTimelineIO, colour, image and macOS Metal. Their existing
  ABI/version/error probes are retained; full product capabilities are still implementation work.
- `ArcForges.Foundation` and `ArcForges.Application.Abstractions`: exact-value adapters, execution
  identities, revision/sequence, clocks, errors, version axes and storage-free application ports.
  Their verified package entries join the normal candidate publication; durable owner receipts
  and cross-language closure acceptance remain tracked delivery tasks.
- Other shared C# mechanisms and ContentSandbox remain scaffolds excluded from NuGet publication.
- `ArcForges.Build.Policy`: portable C# build defaults and enforced central package-version rules.
- Five managed native packages and four Windows x64 runtime packages deliver the existing version,
  build-information and error APIs, real DLL dependencies, C headers, import libraries and source records.
- Platform-only managed and Windows IDE solutions, native ABI CI, package verification and NuGet OIDC CI.

See [extraction scope and evidence](docs/platform-bootstrap.md). The accepted product family design is
maintained in [ArcForges-Design](https://github.com/ArcForges/ArcForges-Design).

## Design policy data

`eng/policy` contains generated glossary and invariant data from the exact Design
commit in `design-source.json`. The portable checker compares fresh exports and
validates document links, scoped citations, occurrence classifications and the
work-package graph. CI requires these platform-independent checks once on Linux before packaging.

```text
python -m unittest discover -s eng -p test_design_policy.py -v
python eng/design_policy.py
```

The second command fetches only the pinned public documentation into a temporary
checkout and retains a report under `artifacts/evidence/design-policy.json`. It
does not execute Design code examples. For reviewed source changes and read-only
pre-merge checks, see [policy maintenance and evidence](docs/design-policy.md).

## Reference planning inputs

The five completed Design matrices are registered through `eng/policy/reference-baselines.json`.
Run `python eng/reference_baselines.py` to verify the pinned documents and all six source commits
in isolated bare repositories. See [registration, local observation and drift](docs/reference-baselines.md)
for the packaged reference boundary and later maintenance.

## Project licence boundaries

The [WP00.02 profile](docs/licence-boundary.md) checks all 35 owned build scopes,
effective managed/IDE properties and native target declarations. A read-only family
audit can inspect explicitly supplied roots without importing or building them.

```text
python -m unittest discover -s eng -p test_licence_boundary.py -v
python eng/licence_boundary.py --evaluate-managed
```

## Build and verify

Source reuse and the existing native artifact closure are enforced by the
[provenance records and review process](docs/provenance.md). Linux policy CI
checks the real inventory, immutable history and failure tests before packaging.

Install the .NET SDK selected by `global.json` and Python 3.11 or newer. No Mobile/Web workloads are needed.

```powershell
dotnet restore DesktopPlatform.slnx --locked-mode
dotnet build DesktopPlatform.slnx -c Release --no-restore
dotnet test --project tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --no-build
```

CMake 4.3.3, Ninja 1.13.1, sccache and a C++20 compiler are needed only for native producer builds.
Follow [native prerequisites and commands](deploy/README.md). `win.slnx` additionally builds the native
Windows projects and stages their DLLs for `NativeAbiTests`; CI uses the independent CMake path.
After native staging, follow [package production](eng/packaging/README.md). C#, Native AOT and C17
consumer diagnostics are explicit local opt-in only when an affected behavior needs them. See [native package scope and evidence](docs/native-package-release.md).

The scheduled/manual [Deep check](.github/workflows/deep-check.yml) runs C# CodeQL only.
C++ CI compiles and stages the Windows native libraries. CTest, managed ABI execution and isolated
package consumers are local opt-in only; no macOS or hosted runtime testing is permitted. To validate the
current configuration, use Actions → Deep check → Run workflow and select the desired branch.
Re-running a historical workflow uses its original commit and can still execute the removed jobs.

## Packages and Contracts

[Package publishing](eng/packaging/README.md) documents the release allowlist, candidate verification,
NuGet trusted-publisher setup and consumer examples. Only admitted packages are published; shared
placeholders remain excluded. These runtime packages expose the existing ABI, not future product APIs.
Every push to `main`, including a merged PR, automatically allocates a prerelease version. Native
compilation and source checks must finish before packing; targeted offline checks and the
aggregate gate must pass before the same package bytes are published to nuget.org through OIDC.
No manual workflow run, version entry or publish checkbox is required for main candidates.
Deliberate canonical stable tags use the same gated pipeline; see [dependency admission](docs/dependency-policy.md).

Contracts is a separate repository with handwritten proto as the business RPC authority. It also owns
schema validation, compatibility checks, generators and generated SDK packaging:

| Consumer | Published dependency |
|---|---|
| C# desktop / Cloud | `ArcForges.Contracts.*` NuGets: generated protobuf messages and gRPC stubs |
| TypeScript Web | `@arcforges/proto`, `@arcforges/api-client` |
| Kotlin Android Mobile | `io.github.arcforges:contracts-proto`, `io.github.arcforges:contracts-connect-client` from Maven Central |
| AI / Cloud internal integration | Separate internal schema/client package; never imported by public SDKs |

Consumers reference exact NuGet/npm/Maven versions and commit their locks. They neither clone Contracts nor
run its generators during ordinary builds. Contracts CI publishes all three ecosystems from one reviewed
schema commit and records descriptor/package hashes. Compatible additive changes can roll out without
simultaneously updating every consumer; breaking changes require a new protocol major and migration.
There are no Git submodules. Contracts publishes independently from its own reviewed source commit.

## Licence

[AGPL-3.0-only](LICENSE). See [NOTICE.md](NOTICE.md) and the
[dependency register](docs/compliance/third-party-license-register.md) for attribution.

[Runtime and source ownership](docs/runtime-ownership.md) records the current nine-owner
policy, bounded runtime checks and retained bootstrap/scaffold dispositions.

[Current repository reconciliation](docs/reconciliation-inventory.md) binds current projects,
historical dispositions and planned directory owners to exact source and candidate identities.

## Pinned Python tooling and local native reuse

Python-running CI jobs select `.python-version`. Install the reviewed hook tooling with `python -m pip install --require-hashes -r eng/requirements-ci.txt`; all transitive tools are exact and hash-verified. After downloading that closure to a wheel directory, `pip install --no-index --find-links <directory> --require-hashes -r eng/requirements-ci.txt` verifies an offline repeat. Dependency updates review the complete closure and hashes.

For ordinary local native compilation, reuse the already installed vcpkg and suitable installed dependencies. Pass the existing installed-root to the build or use ignored local configuration; do not reinstall vcpkg or rebuild working dependencies just for a patch-version difference. The admitted CI candidate still uses the committed producer baseline and provenance. Local compatibility results record the actual tools and do not attest arbitrary local binaries as the publishable candidate.

[Build identity and independent version axes](docs/build-identity.md) documents package reports, compiled
metadata, runtime retrieval and the distinction between current ABI probes and future product schemas.
