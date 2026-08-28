# Runtime Baseline — Cloud JIT and the other non-AOT hosts

The two host classes are recorded apart so a Cloud number is never read as a Native AOT number. Desktop and ContentSandbox Native AOT cells live in [aot-baseline.md](aot-baseline.md); this file
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

### GC comparison — fixed workload

Both runs used the same published artifact and the same probe sequence, changing only `DOTNET_gcServer`.
Workload: 4,000 sequential `GET /health` requests from one client after a two-second settle, with the working
set sampled every 500 requests.

| Measure | Server GC (`DOTNET_gcServer=1`) | Workstation GC (`DOTNET_gcServer=0`) |
|---|---:|---:|
| Requests | 4,000 | 4,000 |
| Wall clock (s) | 5.343 | 3.346 |
| Requests/second | 748.6 | 1,195.6 |
| Idle working set (bytes) | 56,909,824 | 55,156,736 |
| Idle private bytes | 23,339,008 | 15,605,760 |
| Idle threads | 37 | 19 |
| Peak working set (bytes) | 70,471,680 | 68,833,280 |
| Steady working set (bytes) | 70,471,680 | 68,833,280 |
| Steady private bytes | 33,591,296 | 26,681,344 |
| Steady threads | 40 | 22 |
| Latency p50 / p95 / p99 (ms) | 1.028 / 1.496 / 1.987 | 0.742 / 1.202 / 1.625 |

**This is a baseline, not a GC decision, and the numbers must not be quoted as one.** The workload is a single
client issuing sequential requests against a hello endpoint. That shape cannot show Server GC's advantage,
which is parallel collection under concurrent allocation across cores, so Workstation GC leading on throughput
and latency here says almost nothing about a real Cloud load. Per `README.md` §2.3 the choice stays open until
Steps 13/26 measure it against the real agent workload with concurrency, and `architecture-and-communications.md`
§12 additionally requires per-connection and per-agent-run deltas, streaming buffers, Npgsql pool, Channel
backlog and LOH/Gen2 counters — none of which exist to measure yet.

Idle, peak and steady are recorded separately under a repeatable fixed workload, with throughput and latency
percentiles alongside.

### Contract smoke and JIT posture, re-verified at the current tip

| Probe | Expected | Observed |
|---|---|---|
| `runtimeconfig.json` frameworks | shared frameworks declared | `Microsoft.NETCore.App 10.0.0`, `Microsoft.AspNetCore.App 10.0.0` |
| `System.Private.CoreLib.dll` in output | absent | absent |
| `GET /health` | `{"status":"ok"}` | `status = ok` |

## ArcChat.Mobile — Android Mono AOT

`eng/build/Android.aot.props` sets `RunAOTCompilation=true` for Release Android only. The production baseline is
**Mono AOT**; it is not CoreCLR Native AOT and must not be described as such anywhere in the repository.

| Cell | Status |
|---|---|
| `net10.0-android` Release Mono AOT signed package | built and signed by the `android-package` gate |
| `net10.0-ios` | Planned / Build Deferred — excluded unless `EnableIosTarget=true`, by design (Step 20) |

## ArcForges.Web.App — trimmed standalone WebAssembly

`eng/build/web-wasm.props` fixes `PublishTrimmed=true`, `RunAOTCompilation=false`,
`InvariantGlobalization=false`, and `RepositoryPolicyTests` asserts the WASM head never acquires the desktop AOT
posture.

| Cell | Status |
|---|---|
| `dotnet publish src/Web/ArcForges.Web.App -c Release` | published by the `app-smoke` gate |
| Selenium browser probe against the published static site | driven by the `app-smoke` gate, resolving its driver through Selenium Manager rather than a Node driver |
