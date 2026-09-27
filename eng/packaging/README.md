# NuGet package production

`packages.json` admits four packages in one exact-version release set:

| Packages | Delivered content |
|---|---|
| `ArcForges.Build.Policy` | Portable build defaults and central-version/lock enforcement; no runtime dependencies |
| `ArcForges.Native.Abstractions` | Shared status, ABI version and error values; bounded error handling and native loader |
| `ArcForges.Native.Image` | Source-generated C# bindings for every existing entry point |
| Image `.Runtime.win-x64` | Actual owned DLL, full non-system DLL closure, CRT, C headers, import library and provenance |

The retained image ABI provides version, dependency build-information and thread-local error queries.
Image decoding and sandbox containment are not implemented by these
bindings. Shared placeholders and the internal ABI probe project are excluded from this
Windows release. See [scope and validation evidence](../../docs/native-package-release.md).

## Local and PR candidates

Use existing native dependencies and build/stage the Windows CMake profiles as described in
[native producer builds](../../deploy/README.md). CI builds/stages native binaries on Windows,
then performs locked managed build, architecture tests and one package production pass on Linux.
Source, licence, provenance and security checks precede publication. No macOS outputs are produced.

```powershell
dotnet restore DesktopPlatform.slnx --locked-mode
dotnet build DesktopPlatform.slnx -c Release --no-restore
dotnet test --project tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --no-build
python eng/packaging/packages.py pack --version 1.0.0-ci.local.1
```

Packing validates the native input at its handoff, builds the explicit allowlist and validates
the completed candidate once. Publication checks the source/version and retained package integrity
at the credentialed handoff, then pushes those bytes. No public package download or consumer rerun
is part of completion. The candidate artifact remains `nuget-candidate-<run-id>-<producer-attempt>`.

Use a new empty `--directory` for each candidate; do not overwrite or rebuild a version solely
for verification. Runtime CTest, P/Invoke, Build.Policy, JIT/AOT and C17 consumer tools remain
explicit local diagnostics for affected behavior, outside default CI/build/release commands:

```powershell
python eng/packaging/packages.py smoke --version 1.0.0-ci.local.1
python eng/packaging/native_consumer.py --version 1.0.0-ci.local.1
```

These commands reject CI execution. Use the existing local toolchain; do not install tools or
repeat passing tests to expand coverage. Candidate guard fixtures are offline unit tests, not
a requirement to download and inspect published packages. See [AGENTS.md](../../AGENTS.md).

## First-time nuget.org setup

Configure [NuGet trusted publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing)
using the NuGet account that owns the packages. No long-lived API key is needed.

| Setting | Value |
|---|---|
| Repository owner | `ArcForges` |
| Repository | `DesktopPlatform` |
| Workflow filename | `publish-nuget.yml` |
| Environment | `nuget` |
| Package scope | `ArcForges.*` (the repository allowlist limits this workflow to reviewed package IDs) |
| Permissions | Publish new packages and new versions |
| GitHub repository variable `NUGET_USER` | Your NuGet profile username, not email |

Create the GitHub `nuget` environment, restrict deployments to `main` and `v*` tags, and leave required reviewers and
wait timers unset for unattended publication. The workflow independently rejects publication outside
pushes to this repository's main branch or canonical stable tags on main ancestry, rejects a missing or placeholder `NUGET_USER` before expensive
work, and requests `id-token: write` only in the publish job. PR candidate validation needs no NuGet
account. These account settings are external prerequisites; committing YAML does not configure them.

## Release

Every push to `ArcForges/DesktopPlatform` `main`, including a merged PR, automatically starts
**Publish NuGet**. There is no manual dispatch form, version input or publish checkbox. PRs, other
branches do not publish; deliberate canonical `vX.Y.Z` tags publish `X.Y.Z` after tag/source and main-ancestry checks; PR CI continues to produce and verify internal candidates.

The workflow allocates `1.0.0-ci.<workflow-run-number>.<run-attempt>` once before build, for example
`1.0.0-ci.3.1`, then `1.0.0-ci.4.1`. GitHub owns the counter; no version commit or tag is written back
to the repository. The counter continues from earlier runs of this workflow, and failed runs can leave
gaps. Re-running all jobs uses the new attempt suffix. Retrying only failed downstream jobs retains
the already allocated version and producer artifact. Publication therefore authorizes that retained
candidate instead of deriving a version from its own attempt: the version must carry this run number
and an allocation attempt no later than the current attempt, and the downloaded manifest and artifact
name must name this commit, this run and a producing attempt between the allocation and the current
attempt. An artifact from another run, attempt or candidate is rejected; there is no latest-artifact
selection. Main remains a prerelease stream. Stable tags
select the exact stable version before building and reject prerelease dependency closures. Never create
a tag solely for verification. See [dependency admission](../../docs/dependency-policy.md).

Main and stable-tag publications share one non-cancelling queue, so a later merge cannot cancel or
replace a pending publication. Each main push retains its own immutable version. The run performs the complete gate above on the merged commit. Only after all candidate jobs
succeed does it obtain an OIDC credential and upload those exact `.nupkg` bytes. The summary records
the version and source commit. The account must own or be allowed to create each admitted package ID.
NuGet validation and indexing follow upload; a successful push does not mean search/restore is already
available. See [NuGet publication status](https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package#package-validation-and-indexing).

Versions are immutable. `1.0.0-ci.1` cannot be renamed/promoted to `1.0.0`: the latter is a new candidate
and must run through all gates. Local builds and PR candidates never upload to the public feed.
Duplicate versions fail; there is deliberately no `--skip-duplicate`. NuGet cannot atomically publish
four packages. If upload partially succeeds, inspect the registry and retained manifest and re-run all
jobs to allocate a new complete version; do not promote a partial release set or retry it blindly.
Retrying a diagnosed failed publication (re-run failed jobs) uses the retained candidate and its version;
re-running all jobs deliberately builds and publishes a new candidate. A re-run always executes the
workflow of the original commit, so a fix to publication tooling applies only to runs of later commits. A bad published version is superseded by a new
version; consumers retain their prior exact version/lock until the upgrade is approved.

## Consume

After **all required package IDs** at the selected version are available on the feed, pin the version
shown in its successful run. Automatic producer publication never changes consumer pins or locks.
The example version below is illustrative, not a claim of public availability:

```xml
<!-- Directory.Packages.props -->
<Project>
  <PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="ArcForges.Build.Policy" Version="1.0.0-ci.10.1" />
    <PackageVersion Include="ArcForges.Native.Image" Version="1.0.0-ci.10.1" />
    <PackageVersion Include="ArcForges.Native.Image.Runtime.win-x64" Version="1.0.0-ci.10.1" />
  </ItemGroup>
</Project>
```

```xml
<!-- Consumer.csproj -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
    <PublishAot>true</PublishAot>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="ArcForges.Build.Policy" PrivateAssets="all" />
    <PackageReference Include="ArcForges.Native.Image" />
    <PackageReference Include="ArcForges.Native.Image.Runtime.win-x64" />
  </ItemGroup>
</Project>
```

```csharp
using ArcForges.Native.Image;
Console.WriteLine(ImageAbi.GetAbiVersion());
Console.WriteLine(ImageAbi.GetBuildInfo());
Console.WriteLine(ImageAbi.GetLastError());
```

The managed package pulls the exact same `Native.Abstractions` version; the RID package also requires
its exact managed version. Retired Media, Colour and Otio versions remain historical and receive no new publication. Commit the lock
created by the first restore; CI restores with `--locked-mode`. Consumers do not build CMake/vcpkg.

The native loader validates the per-library app-local manifest and DLL hashes before using absolute
paths, with only DLL-directory dependencies and Windows system libraries allowed. Missing DLLs do not
fall back to PATH or the working directory. Keep all runtime files together when publishing. To replace
an upstream DLL with a compatible modified build, update its hashes in each affected app-local manifest;
there is no secret or vendor signature required by this check. The product installer owns application
directory write permissions, signing, upgrades and rollback. The Image runtime includes its upstream notices, recipes and SPDX records, including static inputs.

Each owner commits `global.json` and package locks and restores locked in CI. Build policy is a direct,
private build dependency and never leaks as a transitive runtime dependency. Contracts publishes its own
NuGet and npm SDK packages; this repository does not duplicate that schema generation pipeline.

## Admit further capabilities

Add only implemented, verified packages with explicit metadata, version compatibility, licence/source
closure and relevant local behavior evidence. Extend the validator for
that capability. Native capabilities require one explicit managed
package and matching per-RID runtime package, complete transitive native assets under `runtimes/<rid>/native`,
ABI/AOT evidence, and NOTICE/SBOM. New content-parsing APIs also require the relevant sandbox acceptance;
the existing metadata/error queries do not accept untrusted media. New RIDs need producer builds and honest platform-specific evidence before admission;
macOS CI and hosted runtime consumers remain prohibited.
