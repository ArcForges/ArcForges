# Runtime Baseline — Cloud JIT and the other non-AOT hosts

Step 01 scope requires the two host classes to be recorded apart, so a Cloud number is never read as a Native
AOT number. Desktop and ContentSandbox Native AOT cells live in [aot-baseline.md](aot-baseline.md); this file
covers `ArcForges.Cloud.Host` (framework-dependent JIT), the Android Mono AOT head, and the trimmed Blazor
WebAssembly head.

## ArcForges.Cloud.Host — framework-dependent JIT

| Field | Value |
|---|---|
| Host | Windows 11 Pro for Workstations 10.0.26200, x64 |
| SDK | .NET 10.0.400 |
| Command | `dotnet publish src/Cloud/ArcForges.Cloud.Host/ArcForges.Cloud.Host.csproj -c Release --self-contained false -o artifacts/smoke/cloud` |
| Date (UTC) | 2026-08-28 |

The publish is JIT, not AOT, and this is asserted from the artifact rather than from the project file: the
emitted `ArcForges.Cloud.Host.runtimeconfig.json` declares the `Microsoft.NETCore.App` and
`Microsoft.AspNetCore.App` shared frameworks, and the output directory contains no `System.Private.CoreLib.dll`
and no native image.

### Contract smoke

Each row was observed against the published artifact started with `--urls http://127.0.0.1:5099`.

| Probe | Expected | Observed |
|---|---|---|
| `GET /health` | `{"status":"ok"}` | `status = ok` |
| `GET /` | `{"app":"arcforges-cloud","ok":true}` | `app = arcforges-cloud`, `ok = True` |
| `POST /hubs/v1/events/negotiate?negotiateVersion=1` | non-empty `connectionToken` | non-empty |

### GC comparison — idle only

Both runs used the same published artifact and the same probe sequence, switching only `DOTNET_gcServer`.
Measurements were taken two seconds after the negotiate probe, with no connections held and no agent run.

| Configuration | Working set (bytes) | Private bytes (bytes) | Threads |
|---|---:|---:|---:|
| Server GC (`DOTNET_gcServer=1`, the `runtimeconfig` default) | 56,627,200 | 23,465,984 | 36 |
| Workstation GC (`DOTNET_gcServer=0`) | 54,939,648 | 15,622,144 | 20 |

**This is not the Step 01.07 GC baseline.** That cell requires a fixed workload — steady and peak RSS, managed
heap, the delta after connections are established, single-agent-run peak, Gen0/1/2 and LOH counts, and p95
latency. Those need the Cloud vertical slice from Steps 12–13 and a load generator; nothing above may be quoted
as a GC decision. Per `README.md` §2.3 the choice between Server and Workstation GC stays open until that
evidence exists.

### Not executed

| Cell | Reason |
|---|---|
| Graceful shutdown on `SIGTERM` → exit 0 | `SIGTERM` is a POSIX signal; the Windows run terminated the process. Belongs on the Linux CI runner. |
| `linux-x64` / `osx-arm64` publish and start | no runner on this host |
| Fixed-workload GC matrix, LOH/Gen counters, p95 | requires the Steps 12–13 workload |

## ArcChat.Mobile — Android Mono AOT

`eng/build/Android.aot.props` sets `RunAOTCompilation=true` for Release Android only. The production baseline is
**Mono AOT**; it is not CoreCLR Native AOT and must not be described as such anywhere in the repository.

| Cell | Status |
|---|---|
| `net10.0-android` Release Mono AOT signed package on this host | NotExecuted in this run; the last recorded local pass is 2026-08-13 (see [ci-evidence.md](ci-evidence.md)) |
| `net10.0-ios` | Planned / Build Deferred — excluded unless `EnableIosTarget=true`, by design (Step 20) |

## ArcForges.Web.App — trimmed standalone WebAssembly

`eng/build/web-wasm.props` fixes `PublishTrimmed=true`, `RunAOTCompilation=false`,
`InvariantGlobalization=false`, and `RepositoryPolicyTests` asserts the WASM head never acquires the desktop AOT
posture.

| Cell | Status |
|---|---|
| `dotnet publish src/Web/ArcForges.Web.App -c Release` boot-manifest inspection | NotExecuted in this run |
| Selenium browser probe against the published static site | NotExecuted locally; runs in the `app-smoke` CI job, which now resolves its driver through Selenium Manager instead of a Node driver |
