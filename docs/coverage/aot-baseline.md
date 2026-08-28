# Desktop Native AOT Baseline

Only cells that were actually executed appear as `Passed`. A RID with no runner stays `NotExecuted` — it is
never inferred from a neighbouring RID or from a successful compile.

Step 01.07 requires **20 desktop cells** (4 heads × `win-x64`, `win-arm64`, `osx-x64`, `osx-arm64`,
`linux-x64`) plus the ContentSandbox helper on the same five RIDs. **6 of 25 cells are executed.** The rest
need `windows-arm64`, `macos-*` and `ubuntu` runners; cross-compiling ILC from this Windows host is not
possible, so they are blocked on CI rather than skipped.

## Environment

| Field | Value |
|---|---|
| Host | Windows 11 Pro for Workstations 10.0.26200, x64 |
| SDK | .NET 10.0.400 (pinned by `global.json`) |
| ILCompiler | `Microsoft.DotNet.ILCompiler 10.0.11` |
| Linker | MSVC 14.51.36231 `link.exe` (Hostx64/x64) |
| Date (UTC) | 2026-08-28 |
| Commit | this branch tip (`feat/af01-00-foundation-review`) |

## Executed cells

`Executable` is the single native image. `Publish tree` is the whole output directory, which also carries the
Skia and Avalonia native assets and the PDBs — the two numbers are not interchangeable.

| Host | RID | Mode | Executable (bytes) | Publish tree (bytes) | Cold start to smoke line | Smoke result | IL2026/IL3050 |
|---|---|---|---:|---:|---:|---|---:|
| ArcChat Desktop | `win-x64` | Native AOT | 18,207,232 | 219,005,564 | 893 ms | `arcchat ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcNotes Desktop | `win-x64` | Native AOT | 18,207,232 | 219,005,600 | 1,051 ms | `arcnotes ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcScope Desktop | `win-x64` | Native AOT | 18,207,232 | 219,020,472 | 1,012 ms | `arcscope ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcSlate Desktop | `win-x64` | Native AOT | 18,207,232 | 219,020,472 | 1,013 ms | `arcslate ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcForges.ContentSandbox | `win-x64` | Native AOT | 969,216 | 7,063,600 | n/a (one-shot helper, no smoke contract yet) | published, exit 0 | 0 |

Commands, in order, from a clean `artifacts/`:

```text
dotnet publish src/<Product>/<Product>.Desktop/<Product>.Desktop.csproj -c Release -r win-x64 -o artifacts/smoke/win-x64/<Product>
./artifacts/smoke/win-x64/<Product>/<Product>.Desktop.exe --smoke
dotnet publish src/DesktopHelpers/ArcForges.ContentSandbox/ArcForges.ContentSandbox.csproj -c Release -r win-x64 -o artifacts/smoke/win-x64/contentsandbox
```

Native AOT is proven by the build log reaching `Generating native code` and by the publish tree containing no
`*.runtimeconfig.json`, no `System.Private.CoreLib.dll` and no framework assemblies — the smoke binaries were
executed directly, not through `dotnet`.

## Not executed

| Host | RIDs | Reason | Unblocked by |
|---|---|---|---|
| Four desktop heads | `win-arm64`, `osx-x64`, `osx-arm64`, `linux-x64` | ILC cannot cross-compile these from a `win-x64` host | `runtime-publish-smoke` workflow on native runners |
| ArcForges.ContentSandbox | `win-arm64`, `osx-x64`, `osx-arm64`, `linux-x64` | same | same |
| All cells | — | Reverse drill: disabling `PublishAot` must fail the desktop gate | the same workflow, which does not exist yet |

## History

The figures published before 2026-08-28 recorded ~214 MB per desktop head. That number was the publish
directory, not the executable, and it predates the composition-root wiring. Both quantities are now recorded
separately so a size regression is attributable.
