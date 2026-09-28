# DesktopPlatform dependency register

The authoritative managed versions and hashes are the central manifest and per-project package locks.
Foundation consumes the exact published `ArcForges.Contracts.Foundation` `1.0.0-ci.113.1`
(Apache-2.0, Contracts source `b10b2f6f316bf0c007e00632c5442fc102ebbe6e`) and its
`Google.Protobuf` `3.36.1` runtime (BSD-3-Clause). Application.Abstractions depends on
the same-candidate Foundation package. These licences permit the AGPL-3.0-only consumer
boundary; upstream packages retain their own licences and notices. Exact lock hashes,
cached nuspec metadata and the reviewed closure are recorded in
`eng/policy/dependency-reviews/fnd-01-06-r1.json`. No wire schema is copied here.
`ArcForges.Assistant.Abstractions` retains only its two Architecture 27 owned package edges
(`ArcForges.Foundation` and `ArcForges.Application.Abstractions`) and the same already-admitted
`ArcForges.Contracts.Foundation` `1.0.0-ci.113.1` transitive closure; it adds no external version.
Other retained runtime scaffolds have no new external runtime package references. Build/test-only dependencies
are Microsoft.CodeAnalysis.NetAnalyzers (MIT), Microsoft.NET.Test.Sdk and its platform dependencies (MIT),
xunit.v3 and xunit.runner.visualstudio (Apache-2.0), and coverlet.collector (MIT).
`ArcForges.Build.Policy` includes none of those dependencies in its NuGet closure.

Native upstream sources/versions are listed in [NOTICE](../../NOTICE.md), the classic vcpkg pin in
[deploy](../../deploy/README.md), and the OTIO overlay's source digest/patch. Preserve all upstream
licences, static dependencies and corresponding source in the admitted runtime packages.
`native.py stage` validates the installed upstream versions, recipe hashes and release library hashes,
then copies each dependency's copyright and SPDX record. The artifact records every DLL's PE imports,
exports and SHA256, and supplies the complete non-system DLL closure. Microsoft CRT files come from
the installed Visual Studio redistributable directory; its version and redistribution terms are
recorded in `sbom.json`. The actual DLL product/file version is recorded separately
from the enclosing redistributable-directory version. The reviewed vendor record
requires unchanged bytes, valid Microsoft Authenticode signatures and separate full
vendor terms. Windows system libraries remain OS prerequisites.

The [provenance profile](../provenance.md) binds every selected component to exact
source commits, release archives, feature selections, recipes and original notices.
Full referenced legal companions supplement the installed copyright files. Root or
port SPDX summaries do not override subordinate headers or licence alternatives.
The sealed native receipt and actual NuGet inspector reject changed or unclassified
legal, recipe, source and runtime members.

Media includes SHA512-verified FFmpeg/libusb source archives, selected build configuration and every
vcpkg recipe/patch in its closure. The actual FFmpeg binary must report the admitted LGPL configuration;
GPL/nonfree configurations fail staging. Package verification cross-checks these files against the
immutable native producer artifact before both consumer validation and public upload. See the
[native release evidence](../native-package-release.md) for what actually ran and remaining scope.

The old monorepo's planned product-source adoption register remains in Git at base commit
`99bfe7d695ed0d65a0d035af7d219fc9b86100f5`; those product imports are not DesktopPlatform imports.
No reference-repository code was copied by this extraction.

## SQLite persistence producer (PLT.01, PLT.02, PLT.04)

`ArcForges.Persistence.Sqlite` retains exact NuGet dependencies rather than embedding copied
upstream source or binaries. Microsoft.Data.Sqlite and Microsoft.Data.Sqlite.Core 10.0.12
declare MIT and source commit `95017c711e6afc1085133d440e42b4bd78155701` in dotnet/dotnet.
SQLitePCLRaw.bundle_e_sqlite3, core, provider.e_sqlite3 and lib.e_sqlite3 2.1.12 declare
Apache-2.0 package licensing and the ericsink/SQLitePCL.raw source repository. The latter
supplies the native SQLite dependency; consumers must preserve its original package notices.
The immutable PLT.01/02/04 dependency receipt binds all six exact cached nuspec digests and
generated lock content hashes. It does not claim a new first-party native-family build,
device execution, or product snapshot/recovery acceptance.
