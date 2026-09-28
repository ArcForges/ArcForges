# SPDX-License-Identifier: AGPL-3.0-only

# Local RPC Native AOT probe

This executable is a dedicated process-to-process proof for the generated
`ArcForges.Contracts.LocalRpc.Platform` contract. It is not a product host and
does not claim the restricted launcher, inherited descriptor, or production
lease guarantees owned by later platform work.

Publish and run locally on each available OS (the run is intentionally opt-in;
CI only restores and publishes the binary and never executes it):

```powershell
C:\Users\J7Rdm\.dotnet\dotnet.exe publish tests/LocalRpcAotTests/LocalRpcAotTests.csproj -c Release -r win-x64 -o artifacts/prf-04/win-x64
artifacts/prf-04/win-x64/LocalRpcAotTests.exe
```

```sh
dotnet publish tests/LocalRpcAotTests/LocalRpcAotTests.csproj -c Release -r linux-x64 -o artifacts/prf-04/linux-x64
./artifacts/prf-04/linux-x64/LocalRpcAotTests
```

On a macOS host, publish and run either supported macOS RID the same way:

```sh
dotnet publish tests/LocalRpcAotTests/LocalRpcAotTests.csproj -c Release -r osx-arm64 -o artifacts/prf-04/osx-arm64
./artifacts/prf-04/osx-arm64/LocalRpcAotTests
```

The runtime peer-PID proof supports Windows Named Pipes, Linux Unix-domain
sockets (`SO_PEERCRED`), and macOS Unix-domain sockets (`SOL_LOCAL` /
`LOCAL_PEERPID`). Apple publishes those macOS socket-option values in its
XNU `<sys/un.h>` header (`SOL_LOCAL=0`, `LOCAL_PEERPID=0x002`):
[Apple XNU header](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/un.h#L81-L89).
The parent starts owner A and peer B, authenticates them in both directions,
then stops B while A's process, owner-session ID, and server remain alive. It
restarts B at the same endpoint with the same installation ID but a fresh
instance ID and parent-issued one-use launch nonce. The OS PID may be reused;
A must reject the old channel/lease, then reconnect and authenticate B's fresh
instance/launch identity without restarting or replacing A's owner session.

Each peer's accepted connection checks the OS-observed process ID against the
parent-provisioned PID, the caller manifest's process/installation/instance
tuple, and a one-use launch nonce supplied only over redirected private stdin.
The same-user spoof child is given the actual test bootstrap secret and expected
tuple but runs under a different OS PID; it must be refused before confirmation.
The executable also checks bidirectional challenge/confirm, eight overlapping
same-epoch renewals (one linearized success, stale fences refused), an
expiry-boundary race held behind a server barrier (all post-expiry renewals
refused), cancellation, sanitized malformed-protobuf refusal followed on the
same authorized HTTP/2 channel by a generated challenge/confirm that succeeds,
and the 4 MiB receive bound. The malformed request must not reach service
dispatch; the successful generated challenge must reach it exactly once. A
reattached peer may reuse its OS PID, but must preserve its installation while
rotating its instance ID and one-use launch nonce. The lease epoch/fence headers
are private test-fixture state;
they do not change the generated Contracts wire DTOs or claim production lease
semantics.

The runtime checks use the published Native AOT executable itself as the
parent, client, server, and worker. The test does not substitute an in-memory
transport or TCP. CI's Windows/Linux matrix proves locked restore and AOT
compilation only; local runtime evidence must identify the actual OS and RID.
The `--verify-unix-peer-pid-backends` mode checks the Linux/macOS dispatch and
the unsupported-platform fail-closed case without opening sockets; it is not a
substitute for the required local process-to-process run on macOS. Record an
actual macOS run only when one has been performed on a macOS host.
