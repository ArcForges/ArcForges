# Project licence boundaries (WP00.02)

The accepted Design profile at commit
`3825a24fd7530cb51c3fb30b757e644ebab33459` assigns DesktopPlatform's original
source, tools, tests and build adapters to `AGPL-3.0-only` / `AGPL`.
`eng/policy/licence-boundary.json` enumerates 35 existing project/build scopes:
24 managed projects, four native IDE projects and seven CMake directories.

The standalone `eng/licence_boundary.py` discovers tracked and nonignored project
manifests independently. It rejects missing, duplicate or inconsistent declarations,
changed repository assignments, imported property overrides, source references
outside the owning repository, unknown first-party package owners and direct or
transitive Apache-to-AGPL edges. Npm aliases and locked dependency graphs are
included. This is original AGPL tooling; Apache owners implement their own checks.

```text
python -m unittest discover -s eng -p test_licence_boundary.py -v
python eng/licence_boundary.py --evaluate-managed --report artifacts/evidence/licence-managed.json
python eng/licence_boundary.py --evaluate-ide --report artifacts/evidence/licence-ide.json
```

The second command evaluates actual Debug/Release MSBuild properties and references
for all 24 managed projects. The third uses Visual Studio MSBuild on Windows for
Debug/Release and x64/ARM64 on all four native IDE adapters; it evaluates declarations
without claiming those cross-architecture binaries were built. Build/pack targets
also reject changed effective values. NuGet packing runs the source inventory gate.

Each configured owned CMake target explicitly receives the directory's declaration.
A deferred final check rejects missing/changed target properties and records source,
dirty state, targets and configure-time link expressions in
`artifacts/cmake/<rid>/<profile>/licence-boundary.json`. Imported dependencies keep
their own licences; CTest's generated utility targets are identified separately.
The existing native-stage audit still verifies the actual third-party binary,
notice and source closure. Declaration checks do not replace it. Only targets created
by the CTest module are exempt; owned targets added before it still require declarations,
with both native-test settings covered by a regression using the actual root CMake file.

CI requires both operating systems' source/managed checks and the Windows native
IDE/CMake reports before packaging. Eleven negative/positive test groups include real
MSBuild global overrides, real CMake target changes and malformed reference graphs.
The current Design exports are refreshed to the same accepted baseline; glossary
content and forbidden-alias digests are unchanged.

For a read-only family audit, repeat explicit `--repository Owner=/absolute/root`
arguments for the nine implementation owners. This mode never executes, imports or
builds an adjacent repository and cannot be combined with evaluated build options.
Reports include source commit, dirty state, discovered inventory and reference edges.
The normal owner CI needs no adjacent checkout or future shared policy package.

Actual package and native/AOT consumers, registry publication and product acceptance
remain distinct evidence. Mobile's distributable third-party audit stays with its
Apache owner; a passing family reference-direction result cannot close that gate.

## Reduced-family adoption (GOV.18)

The current owner allowlist contains DesktopPlatform, Contracts, ArcScope, Cloud, AI, Web and Mobile. DesktopPlatform licence declarations enumerate the actual retained projects; removed native family projects are no longer active. OpenColorIO may remain an admitted transitive OpenImageIO dependency without restoring a Colour capability package.
