# ArcForges.LocalRpc

Generated gRPC over HTTP/2 between a parent and the helper or extension children it owns, carried only by
a Windows Named Pipe or a Unix domain socket. The project is non-packable until its package task admits it.

This is transport and framing (WP-08.00). It has no endpoint descriptor, nonce, registration lease, routing,
call queue, retry or brokered-resource logic; those are the later local RPC tasks. It does not define a
contract: the services it serves are the generated `ArcForges.Contracts.LocalRpc.*` bindings, registered
explicitly by their owner.

## What it provides

- `LocalRpcEndpoint` validates an address: a flat Windows pipe name, or a canonical absolute Unix socket path of
  at most 100 UTF-8 bytes. A pipe is refused off Windows and a socket is refused on Windows. There is no host,
  port, URL, discovery manifest or DNS name.
- `LocalRpcServer` hosts Kestrel with a custom `IConnectionListenerFactory` that can bind nothing but this
  transport; its builder registers each generated service explicitly (`AddService`) and nothing is found by
  scanning. The host is a generic web host; it does read `ASPNETCORE_*` settings into host configuration,
  but its only Kestrel endpoint is the explicit private one, which overrides any URL or port setting, so no address
  results, and `ASPNETCORE_PREFERHOSTINGURLS=true` makes startup fail. The other connection listener factories are
  removed, and `StartAsync` fails closed if any non-local address is bound. An optional `AuthorizeConnections` decision runs
  on every accepted connection before HTTP/2 reads a byte.
- At most `MaxConnections` connections are served at once. The listener waits for a free slot before it accepts, so
  an extra peer waits in the OS backlog (16) and is served when a slot frees; it is not reset.
- `LocalRpcStreamSupplier` is the launcher's hand-over of already-connected OS streams. A server built over a
  supplier accepts only those streams.
- `LocalRpcClientChannel` is a `GrpcChannel` over `http://arcforges.invalid` whose `ConnectCallback` returns
  only the verified OS stream: one HTTP/2 connection, no retry, hedging, load balancing, connection recycling
  or fallback to DNS/TCP, and no compression providers.
- gRPC messages are limited to 4 MiB in both directions (`LocalRpcLimits`). Compression is refused: a request that
  names any `grpc-encoding` other than `identity` is answered `UNIMPLEMENTED` before routing and before any
  decompression, so the bound holds for the decoded size as well. Detailed error text is off.

## OS user boundary

A Named Pipe is created with `CurrentUserOnly` (a DACL granting only the current user); the first instance also
uses `FirstPipeInstance`, so binding fails when the name already has an instance, and the client requires the
server end to be owned by the current user. The pipe is not created with the reject-remote-clients flag and a
client reaches it through `\\127.0.0.1\pipe\<name>` as well; it is limited to the current account by its DACL and
is not claimed to be network-isolated. A Unix socket is bound only in a directory with no group or other
permission bits, is never created over an existing file, is set to mode 0600 and is removed when the listener is
unbound; the client refuses a symbolic link.

This package does not read the peer process or user of an accepted connection and does not authenticate the
child: that is the parent-owned launch identity of the endpoint-identity task (PRF.04 read the peer PID with
platform calls; `Socket.GetRawSocketOption` could read `SO_PEERCRED` without a native binding, but neither is
used here). The authorizer is a synchronous decision over `(Transport, Sequence)` that runs on the accept loop; the
endpoint-identity task is expected to change it to carry peer identity and to be asynchronous. Pipe-name squatting
by another process of the same user is contained by unguessable per-launch names (that task) and the client's
owner check; the owner check against a foreign pipe is not tested.

## Validation

`Tests/` (`ArcForges.LocalRpc.Tests`) runs offline in CI: real Kestrel HTTP/2 and Grpc.Net.Client over
in-memory duplex streams, with raw HTTP/2 and gRPC frame fixtures. Opt-in local OS checks, skipped by default and
in hosted CI, exercise a real Named Pipe, a real Unix-domain-socket code path and the absence of a TCP
listener for the process:

```powershell
$env:ARCFORGES_LOCALRPC_OS_STREAMS = '1'
dotnet test --project src/BuildingBlocks/ArcForges.LocalRpc/Tests/ArcForges.LocalRpc.Tests.csproj -c Release
```

Hosted CI never executes those checks and a successful run on one OS says nothing about the others.
