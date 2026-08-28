# Desktop Native AOT Baseline

Only cells that were actually executed appear as `Passed`. A RID with no runner stays `NotExecuted` — it is
never inferred from a neighbouring RID or from a successful compile. **Publishing a cell and running it are
recorded separately**, because a cross-published binary proves the toolchain, not the behaviour.

Step 01.07 requires **20 desktop cells** (4 heads × `win-x64`, `win-arm64`, `osx-x64`, `osx-arm64`,
`linux-x64`) plus the ContentSandbox helper on the same five RIDs, so 25 in total.

| Cell state | Count | Which |
|---|---:|---|
| Published **and** executed | 4 | 4 heads × `win-x64` |
| Published, cannot be executed here | 5 | 4 heads + ContentSandbox × `win-arm64` (ARM64 images do not run on an x64 host) |
| Published, no run contract yet | 1 | ContentSandbox × `win-x64` (one-shot helper; Step 06/07 give it a smoke contract) |
| Not executed | 15 | 4 heads + ContentSandbox × `linux-x64`, `osx-x64`, `osx-arm64` |

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

## Executed cells — `win-x64`

`Executable` is the single native image. `Publish tree` is the whole output directory, which also carries the
Skia and Avalonia native assets and the PDBs — the two numbers are not interchangeable.

| Host | Mode | Executable (bytes) | Publish tree (bytes) | Cold start to smoke line | Smoke result | IL2026/IL3050 |
|---|---|---:|---:|---:|---|---:|
| ArcChat Desktop | Native AOT | 18,207,232 | 219,005,936 | 635 ms | `arcchat ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcNotes Desktop | Native AOT | 18,207,232 | 219,005,972 | 584 ms | `arcnotes ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcScope Desktop | Native AOT | 18,207,232 | 219,020,840 | 634 ms | `arcscope ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcSlate Desktop | Native AOT | 18,207,232 | 219,012,644 | 656 ms | `arcslate ok arcforges-smoke avalonia-window`, exit 0 | 0 |
| ArcForges.ContentSandbox | Native AOT | 969,216 | 7,090,184 | n/a — one-shot helper, no smoke contract yet | published, exit 0 | 0 |

## Published cells — `win-arm64`

ILC **does** cross-compile `win-x64` → `win-arm64` on this host, so these five cells are no longer blocked on
a runner for the *publish* half. They are still `NotExecuted`: an ARM64 image cannot run on x64 Windows, so
the `--smoke` line and the cold-start figure must come from a `windows-11-arm` runner.

Each image was confirmed ARM64 by reading the PE header rather than trusting the RID: COFF machine type
`0xAA64`.

| Host | Mode | Executable (bytes) | Publish tree (bytes) | Machine | Run | IL2026/IL3050 |
|---|---|---:|---:|---|---|---:|
| ArcChat Desktop | Native AOT | 18,684,416 | 214,031,904 | `0xAA64` ARM64 | NotExecuted | 0 |
| ArcNotes Desktop | Native AOT | 18,684,416 | 214,040,132 | `0xAA64` ARM64 | NotExecuted | 0 |
| ArcScope Desktop | Native AOT | 18,684,416 | 214,046,808 | `0xAA64` ARM64 | NotExecuted | 0 |
| ArcSlate Desktop | Native AOT | 18,684,416 | 214,046,804 | `0xAA64` ARM64 | NotExecuted | 0 |
| ArcForges.ContentSandbox | Native AOT | 964,096 | — | `0xAA64` ARM64 | NotExecuted | 0 |

Commands, from a clean `artifacts/`:

```text
dotnet publish src/<Product>/<Product>.Desktop/<Product>.Desktop.csproj -c Release -r <rid> --self-contained true --no-restore -o artifacts/smoke/<rid>/<Product>
./artifacts/smoke/win-x64/<Product>/<Product>.Desktop.exe --smoke
```

Native AOT is proven per cell by three facts, not by the presence of `PublishAot` in a project file: the build
log reaches `Generating native code`, the publish tree contains no `*.runtimeconfig.json` and no
`System.Private.CoreLib.dll`, and the smoke binaries were executed directly rather than through `dotnet`.

**Locked restore interacts with the RID matrix and it is worth stating precisely.** The committed lock files
carry only the RID-agnostic `net10.0` target. `dotnet restore <project> --locked-mode` followed by
`dotnet publish -r <rid> --no-restore` — the sequence `runtime-publish-smoke.yml` uses — works for every RID
and leaves the lock files untouched. Passing `-r` to `restore` instead rewrites the lock with a
`net10.0/<rid>` target and dirties the tree, so the workflow deliberately does not do that.

## Not executed

| Host | RIDs | Reason | Unblocked by |
|---|---|---|---|
| Four desktop heads + ContentSandbox | `linux-x64`, `osx-x64`, `osx-arm64` | ILC cannot cross-compile these from a Windows host | `runtime-publish-smoke` on `ubuntu-latest`, `macos-13`, `macos-latest` |
| Four desktop heads + ContentSandbox | `win-arm64` (run half only) | an ARM64 image does not run on x64 Windows | `runtime-publish-smoke` on `windows-11-arm` |
| All cells | — | Reverse drill: disabling `PublishAot` must fail the desktop gate | the same workflow; the evaluated-property gate `PublishModePropertiesEvaluateToTheirDeclaredValues` already fails locally when the posture is flipped |

## History

The figures published before 2026-08-28 recorded ~214 MB per desktop head. That number was the publish
directory, not the executable, and it predates the composition-root wiring. Both quantities are now recorded
separately so a size regression is attributable.
