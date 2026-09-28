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

For macOS, publish and run the matching `osx-x64` or `osx-arm64` RID on a macOS
host. The probe selects Windows Named Pipes or Unix-domain sockets from the
current OS. It creates two fresh worker-process pairs, provisions each pair a
one-use secret over redirected private stdin (never argv, environment, or a
file), completes challenge/confirm/renew in both directions, then checks
cancellation, same-user wrong-secret refusal, malformed protobuf refusal, a
4 MiB receive bound, and process disconnect/re-attach with new identities.

The runtime checks use the published Native AOT executable itself as the
parent, client, server, and worker. The test does not substitute an in-memory
transport or TCP. CI's Windows/Linux matrix proves locked restore and AOT
compilation only; local runtime evidence must identify the actual OS and RID.
