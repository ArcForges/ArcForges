<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Current dependency upgrade

`current.json` records the actual current restored NuGet closure and exact
central selections for AFV2-ENV-01. The existing admissions file binds those
central coordinates to their content identities and package/source licences.
Every changed author proposal remains pending independent review and current
native verification.

The current selection is SDK11.0.100/net11.0/C#15, Python3.15.2 and the published
DesktopPlatform150.1 cohort. Contracts remains at its actually published450.1
cohort until the next normal producer publication is available. The current
Build.Policy150.1 validator rejects legal four-segment stable NuGet versions
used by ANGLE/HarfBuzz; its producer needs a reviewed compatibility successor
before compilation can proceed. No consumer overrides that check.

The current managed source uses explicit ordinal character comparisons for
.NET11's comparison diagnostics. System.CommandLine3 and CsCheck5 are selected;
their complete compiler/test/AOT compatibility is still pending the producer
repair. All existing trim/AOT/analyzer, real-OS, exclusive, closed-loop, size,
schema and startup checks remain required. Historical receipts are not new
qualification.

`eng/check_toolchain.py` checks both Python entry points, the SDK and actual
MSBuild roots before current build work. The negative selector tests use real
installed tools. `eng/baseline_sdk.py` selects the merge base's retained exact SDK
in a child process so that startup comparison uses an unchanged historical
baseline. It does not install tools or edit baseline source.
CI and both native verification legs set `PYTHONDONTWRITEBYTECODE=1` for the
same source-only Python behavior. For an independent manual tooling unittest,
use `python -B -m unittest discover -s eng -p 'test_*toolchain.py' -v`.

The current Linux selector uses official LLVM23.1.5 and signed GNU binutils2.47
(the unmodified formal banner is2.47.20260726), with isolated x64/arm64 archive
and cache identities. Original Apache tooling comes from reviewed Contracts
commit0b9114435bd4677c256714b864b8cb8f970c2d57; its exact source hashes and
ArcForges adaptations are recorded in `eng/policy/native-tooling-reuse.json`.
Native GNU source and generated source-context patches stay in the external
tool cache. The tool sources are not a runtime package dependency.

Actual current native compiler qualification remains pending, particularly the
first ARM64 archive layout/core-resource measurement and native CI execution.
No x64 binary or receipt qualifies ARM64. The Ubuntu26.04 GA labels alone do
not establish compiler parity. The complete required host profiles and final
independent review must pass at the pushed candidate.
