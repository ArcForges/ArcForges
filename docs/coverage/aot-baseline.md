# Desktop Native AOT Baseline

Recorded figures come from cells that were actually executed. A figure is never inferred from a neighbouring
RID or from a successful compile, and publishing a cell is recorded separately from running it, because a
cross-published binary proves the toolchain rather than the behaviour.

## Environment

| Field | Value |
|---|---|
| Host | Windows 11 Pro for Workstations 10.0.26200, x64 |
| SDK | .NET 10.0.400 (pinned by `global.json`) |
| ILCompiler | `Microsoft.DotNet.ILCompiler 10.0.11` |
| Linker | MSVC 14.51.36231 `link.exe` (Hostx64/x64 and Hostx64/arm64) |
| Date (UTC) | 2026-08-28 |
| Branch | `feat/af01-01-step-01-closure` |

`vswhere.exe` must be on `PATH` for the ILC link step; without it the publish fails with `MSB3073 ... exited
with code 123` from `link.exe`. It lives in `C:\Program Files (x86)\Microsoft Visual Studio\Installer`.

## Executed — `win-x64`

`Executable` is the single native image. `Publish tree` is the whole output directory, which also carries the
Skia and Avalonia native assets and the PDBs — the two numbers are not interchangeable.

| Host | Mode | Executable (bytes) | Publish tree (bytes) | Cold start to smoke line | Smoke result | IL2026/IL3050 |
|---|---|---:|---:|---:|---|---:|
| ArcChat Desktop | Native AOT | 18,207,232 | 219,005,936 | 635 ms | `arcchat ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcNotes Desktop | Native AOT | 18,207,232 | 219,005,972 | 584 ms | `arcnotes ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcScope Desktop | Native AOT | 18,207,232 | 219,020,840 | 634 ms | `arcscope ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcSlate Desktop | Native AOT | 18,207,232 | 219,012,644 | 656 ms | `arcslate ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcForges.ContentSandbox | Native AOT | 969,216 | 7,090,184 | n/a — one-shot helper, no smoke contract yet | published, exit 0 | 0 |

## Published — `win-arm64`

ILC cross-compiles `win-x64` → `win-arm64` on this host. Each image was confirmed ARM64 by reading the PE
header rather than trusting the RID: COFF machine type `0xAA64`. These rows record a publish, not a run — an
ARM64 image does not execute on x64 Windows.

| Host | Mode | Executable (bytes) | Publish tree (bytes) | Machine | IL2026/IL3050 |
|---|---|---:|---:|---|---:|
| ArcChat Desktop | Native AOT | 18,684,416 | 214,031,904 | `0xAA64` ARM64 | 0 |
| ArcNotes Desktop | Native AOT | 18,684,416 | 214,040,132 | `0xAA64` ARM64 | 0 |
| ArcScope Desktop | Native AOT | 18,684,416 | 214,046,808 | `0xAA64` ARM64 | 0 |
| ArcSlate Desktop | Native AOT | 18,684,416 | 214,046,804 | `0xAA64` ARM64 | 0 |
| ArcForges.ContentSandbox | Native AOT | 964,096 | — | `0xAA64` ARM64 | 0 |

Commands, from a clean `artifacts/`:

```text
dotnet publish src/<Product>/<Product>.Desktop/<Product>.Desktop.csproj -c Release -r <rid> --self-contained true --no-restore -o artifacts/smoke/<rid>/<Product>
./artifacts/smoke/win-x64/<Product>/<Product>.Desktop.exe --smoke
```

Native AOT is proven per cell by three facts, not by the presence of `PublishAot` in a project file: the build
log reaches `Generating native code`, the publish tree contains no `*.runtimeconfig.json` and no
`System.Private.CoreLib.dll`, and the smoke binaries were executed directly rather than through `dotnet`.

The posture itself is additionally pinned by
`RepositoryPolicyTests.PublishModePropertiesEvaluateToTheirDeclaredValues`, which reads `PublishAot`,
`TrimMode`, `PublishTrimmed` and `RunAOTCompilation` back out of MSBuild's evaluation for the desktop head,
ContentSandbox, the Cloud host and the WASM head. Flipping any of them fails that test.

**Locked restore interacts with the RID matrix and it is worth stating precisely.** The committed lock files
carry only the RID-agnostic `net10.0` target. `dotnet restore <project> --locked-mode` followed by
`dotnet publish -r <rid> --no-restore` works for every RID and leaves the lock files untouched. Passing `-r`
to `restore` instead rewrites the lock with a `net10.0/<rid>` target and dirties the tree, so neither the
recorded commands nor `runtime-publish-smoke.yml` do that.

## History

The figures published before 2026-08-28 recorded ~214 MB per desktop head. That number was the publish
directory, not the executable, and it predates the composition-root wiring. Both quantities are now recorded
separately so a size regression is attributable.
