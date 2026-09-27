# Source and native package provenance

WP00.03 implements the [reviewed Design profile](https://github.com/ArcForges/ArcForges-Design/blob/5322d698a1b650a52a5a139d986dd85b00b48581/docs/assurance/reference-coverage-and-provenance.md).
The audit subject is the current DesktopPlatform repository. The retired initialization
repository is not a producer or source input. The existing package identities, ABI and
runtime tests remain independent release gates.

## Before introducing material

Use `eng/provenance/template.json` to create a record under `eng/provenance/records`.
The ten fields identify the exact source repository/commit/paths, file-level licence,
attribution, target, disposition, independent oracle, NOTICE and lifetime. The
Licensing and Provenance Owner reviews the actual files and compatibility; a maintainer
may exercise that role through an authorized implementation review. Architecture decides
boundary questions. Register conflicts under `eng/provenance/conflicts`; unresolved
conflicts block acceptance. A word such as `approved` does not replace review evidence.

Record an explicit removal owner/trigger for temporary material. Generated material
records each generator and input separately. A tool's implementation is not automatically
included in its output. Preserve original legal text and subordinate licence overrides;
the source notice summary does not replace them. The five-row decision table is closed,
and source copyleft remains prohibited at the Apache interoperability boundary.

Bind each identified reused file in `eng/provenance/files.json`; every other tracked or
non-ignored new file has an explicit first-party classification. Review also detects
newly copied content within previously authored files. The initial records reconcile
existing material honestly; they do not assert that a record existed before its historic
copy. Used records are immutable, including retired records. Create a revision and
`supersedes` link for any changed input, intent or content, retain history and update the
active binding. CI compares with the event's trusted base, not a contributor-selected
empty baseline.

```text
python -m unittest discover -s tests/tooling -p "test_*.py" -v
python eng/check_provenance.py --owner DesktopPlatform
python eng/native_provenance.py
```

After a reviewed inventory change, `--write-notice` updates the deterministic source
summary. Checks fail for incomplete records, unknown classifications, prohibited
boundaries, changed bytes, escaped/linked paths, missing notices and altered history.
The Python checker and its original tests are reused under Apache-2.0 from Contracts
18a970c67c463f1971ca05773b80f31a1b1ba1a7; the local extension records the exact native
expressions already audited here. This does not import AGPL tooling into Contracts.

## Current Windows native closure

The immutable `native-win-x64-r4.json` artifact profile records the retained Image
package's 21 components, 97 port recipe files, four toolchain definitions and exact
dependency/feature closure. The owned logical library is `ArcImageNative`; the public
`arc_image_*` symbols and C header remain unchanged. Media, Colour and Otio package
registrations, their native wrappers and the Metal probe are retired under P2-019/GOV.17.
OpenColorIO remains an Image dependency; retiring the owned Colour wrapper does not
remove the Image dependency closure.

Revision 4 reuses the exact reviewed source identities, legal/recipe bytes, features,
generator versions and compiler-runtime identities from revision 3. It does not claim
a new upstream byte audit. Twenty-one new component records supersede their revision 3
predecessors and bind the new Image-only profile. Every earlier record and profile
remains unchanged. `retired-artifacts.json` names each exact former project/package/material
registration and its historical record. The checker rejects unregistered or still-active
retirements and cannot use this exception to remove Image or another retained producer.

The owned image wrapper uses CMake 4.3.3 and Ninja 1.13.1 with the `shim-static` preset.
The pinned vcpkg tool manifest selects CMake 4.4.0 for upstream dependency builds. The
producer reads the actual retained CMake cache and its dependency root; each distributed
dependency retains its installed `vcpkg_abi_info.txt`. Candidate inspection rejects
another generator version. Two minimal overlays include unchanged standard triplets
and pin MSVC 14.51.36231. Their hashes and included upstream definitions are verified
from installed ABI records and retained with the full vcpkg MIT licence. The owned
compiler path is checked independently. Local builds with other tools do not prove
this production gate.

The retained source/configuration matters: liblzma uses 0BSD and zstd selects BSD.
Full referenced companions remain for IJG, OpenColorIO and OpenImageIO. OpenImageIO's
`function_view.h` retains its actual NCSA header notice despite the summary's LLVM
description. ICC/SunSoft identifiers name exact recorded permissive texts. libtiff
retains its original LZW notice and the official UC Berkeley advertising-clause
amendment. Build-only tools are absent from the runtime DLL closure.

## Historical native evidence

Revision 3 recorded 36 components, 174 recipe files and four native package closures.
Those historical receipts include AMF header comparisons, FFmpeg/libusb source archives,
miniaudio, RapidJSON, Vulkan, pkgconf and bin2c legal material, and the two verified
cold/cached SPDX forms of the Meson helper. They remain evidence for their original
published versions; none of those retired-family receipts authorizes a new Image
payload or a new retired-family publication. The current Image closure does not use
Meson and admits no cached source-resource omission. Original archive/source/license
identities and vendor terms remain authoritative; new binary hashes belong to each
actual producer receipt. No historical publication is deleted or rewritten.

The separate compiler-runtime record binds the three currently distributed Microsoft
DLLs to approved hashes, publisher and actual file/product version **14.51.36247.0**.
The enclosing redist directory is **14.51.36231**, a different identity. Public source
repository/commit fields are explicitly null because Microsoft publishes these files
as signed binaries. The official Community redistribution grant/list and the narrow
AGPL System Libraries position are reviewed independently. Original formatted vendor
terms accompany the package. Vendor restrictions apply only to those DLLs; ArcForges
source retains its AGPL rights. A changed version, file, publisher or terms needs a
new reviewed record/profile.

For compatibility, `visualCppRuntime.version` retains its original directory-version
meaning. `redistributableDirectoryVersion` makes that meaning explicit, and `files`
contains the separately verified actual DLL versions and hashes.

`native.py stage` checks the source inventory, installed versions/recipes/library hashes,
approved compiler-runtime signatures and fixed versions, exact legal companions and
matching LGPL sources. It seals `provenance/native-closure.json` with the source commit,
selected records and every native producer member/hash. Both the independent packager
and candidate inspector verify that receipt and the profile, including every legal
and recipe member. Existing CMake/CTest, P/Invoke and isolated JIT/AOT/C17 consumers
remain mandatory. Main publication and exact public NuGet byte verification close a
release; policy checks alone do not prove product or commercial readiness.
