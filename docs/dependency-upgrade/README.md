<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Current dependency upgrade

`current.json` records the actual current restored NuGet closure and exact
central selections for AFV2-ENV-01. The existing admissions file binds those
central coordinates to their content identities and package/source licences.
The existing source/licence review is retained. Actual compiler compatibility
and the required current native profiles are recorded separately.

The current selection is SDK11.0.100/net11.0/C#15 and Python3.15.2.
The normally published DesktopPlatform policy fix 1.0.0-ci.151.1 is
restored with the actual package/source identities in current.json. Existing
Contracts450.1 is retained; no new Contracts cohort is a prerequisite for the
current build. Actual compiler/tests and native qualification remain required.

The current managed source uses explicit ordinal character comparisons for
.NET11's comparison diagnostics. System.CommandLine3 and CsCheck5 are selected;
the entire solution now compiles with zero warnings and errors on native Windows.
All existing trim/AOT/analyzer, real-OS, exclusive, closed-loop, size,
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

The required Windows/Linux profiles qualify the current x64 candidate after its
push. Existing manual hosted ARM64 coverage remains separate; no x64 result
claims ARM64 execution. The Ubuntu26.04 labels alone do not establish compiler
parity. Exact final host results are recorded in the PR and Plan delivery evidence.
