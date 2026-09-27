# Version axes

FND.06 supplies nine independent value types in `ArcForges.Foundation.Versions`. No cross-axis conversions exist. Callers supply each value from its own authoritative source; these types never infer capabilities or deployed schemas from a build/package version.

Eight semantic axes accept one to three unsigned numeric components (omitted minor/patch normalize to zero), optional SemVer prerelease and build identifiers. Ordering follows SemVer, compares numeric prerelease identifiers without bounded-integer truncation, and ignores build metadata; identity equality retains metadata. `ContractSet` represents the version of one independently named contract set, not a dependency package release. Subject/contract identity remains with the caller.

`StorageSchemaVersion` instead accepts only a canonical unsigned migration number and exposes `Number`. Schema version zero is explicit; default values on every axis are absent (`IsValid == false`) and cannot be compared or formatted as an invented implementation.

`VersionRange<T>` never accepts another axis. Expressions are `*`, exact values, intervals such as `[1.2.0,2.0.0)` or `(,2.0.0]`, and semantic partial prefixes `1.*` / `1.2.*`. A missing bound is unbounded and must use an exclusive bracket. Empty or reversed intervals refuse. Partial ranges begin at a stable version and therefore do not implicitly admit prereleases before that lower bound; an explicit prerelease lower bound can admit them. Migration ranges use integer endpoints and do not accept semantic wildcards. These mechanisms do not choose a product's supported compatibility policy.

Validation includes every axis, invalid/default inputs, boundary/open/partial ranges, SemVer ordering/metadata, and an offline SDK compiler test. Its positive control first compiles same-axis assignments, then verifies CS0029 at every one of the 72 ordered cross-axis assignments. This is source compilation against the just-built assembly, not an installed-package or live consumer test.
