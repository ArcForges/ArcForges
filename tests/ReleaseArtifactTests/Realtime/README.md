# SPDX-License-Identifier: AGPL-3.0-only

# Realtime Native AOT probe (PRF.06)

`RealtimeAotProbe` is a non-packable Native AOT executable that holds the **client side** of annex 10 realtime
under Native AOT: the generated `EventService.Watch`/`Poll` and `ExecutionService.WatchOutput`/`ReadOutput`
clients from the published `ArcForges.Contracts.Events` candidate `1.0.0-ci.270.1`, binary gRPC-Web through
`Grpc.Net.Client.Web`, and the recovery logic of annex 10 section 5. It is not a product host and it is **not**
evidence of any deployed service: at the time of writing no task has built a public `Watch` or `WatchOutput`
server (`CLOUD.29`, `CLOUD.32` and `CLOUD.34` own them), and PRF.07 (WP-06.04) does not provide `EventService.Watch`.
The live acceptance of WP-06.03 therefore stays unperformed and is never claimed from this directory.

## What it contains

| File | Role |
|---|---|
| `Policy.cs` | The limits of annex 10 as one value, the exponential full-jitter reconnect ladder and the cadence jitter |
| `Sequence.cs` | Per-subscription event sequence rules (baseline, next, gap, duplicate, conflict) and the append-only output offset rules |
| `Classification.cs` | Typed `ArcError` and gRPC status to retry, stop, unsupported or protocol violation |
| `ReconnectingStream.cs` | The shared Watch/WatchOutput loop: 45 second silence, reset frames, typed errors, backoff, cancellation |
| `Events.cs`, `Readers.cs` | `EventWatcher` (stream) and `EventPoller` (10 second fallback) over one shared cursor and sequence |
| `Outputs.cs`, `Readers.cs` | `OutputWatcher` (stream with ReadOutput recovery) and `OutputReader` (5 second fallback) |
| `Transport.cs` | The four generated calls behind one seam and the binary gRPC-Web channel |
| `Live.cs`, `Program.cs` | The explicit local live run and the entry point |
| `SelfTest*.cs` | The offline checks (below) |

## Offline self-test (default mode)

Running the executable with no arguments (or `--self-test`) runs the checks, opens no socket and calls no service:

- the generated codecs under the executing runtime (all seven `StreamFrame` variants, all 17 event hint payloads, 64 bit values beyond 2^53, optional-field presence);
- the real generated clients and the real `GrpcWebHandler` over a handler that replays HTTP bytes: binary request framing and routes, frames split across reads, trailer status, a body that ends without trailers, cancellation, a malformed message, the receive bound and the authorization header;
- the sequence, backoff, cadence and classification rules, with boundary values on both sides of every limit;
- the Watch, WatchOutput, Poll and ReadOutput loops against scripted transports and a **manual clock**, so no check depends on real time.

The replayed bytes and scripted transports are test doubles for the probe's own logic. They prove how this client
behaves, not what any server does, and they are not registered substitutes of any real producer.

```powershell
dotnet publish tests/ReleaseArtifactTests/Realtime/RealtimeAotProbe.csproj -c Release -r win-x64 -o artifacts/prf-06/win-x64
artifacts/prf-06/win-x64/RealtimeAotProbe.exe
```

The first output line says whether a Native AOT image or the managed JIT ran. Hosted CI only restores and
publishes this project with Native AOT (`realtime-aot` in `package-validation.yml`); it never executes it.

## Live run (explicit local opt-in, never run so far)

```powershell
$env:RTPROBE_AUTHORIZATION = '<full Authorization header value>'
artifacts/prf-06/win-x64/RealtimeAotProbe.exe --live https://<worker-host> --subscription <key> [--output-task <uuid>] [--mode watch|poll] [--seconds n]
```

The authorization value is read only from the environment, is sent only to an HTTPS (or loopback) address, never
follows a redirect and is never printed. The run prints states, sequence numbers, offsets and counters, never a hint
or chunk body. It needs a deployed Worker/Container/DO that serves the public `Watch` route, which does not exist yet,
and the exclusive `RES-cloud-deployment` lease held only for that run. Its observer cannot read the owner RPC a snapshot
or gap names, so it records that obligation instead of discharging it.

## Interpretations and limits

- "Exponential full jitter from 0.5s to 30s" is read as a delay drawn uniformly under a ceiling that doubles from 0.5 seconds to 30 seconds and resets after a connection that stayed up 30 seconds.
- The chunk and final hashes are compared for equality only; their algorithm belongs to the Cloud producer, so the bytes are not verified against them.
- A stream reset restarts an execution output from offset zero through ReadOutput; the resume cursor is not used for output because partial text is never a commit.
- An output is complete only when an authoritative ReadOutput returns the terminal outcome; a terminal frame on the stream only triggers that read.
- The policy bounds this probe adds itself, not quoted from the design: 5 minutes for a server retry time, 512 KiB received message size, 64 remembered items for duplicate conflict detection.
- No SignalR, WebSocket or JSON event protocol is used or referenced.
