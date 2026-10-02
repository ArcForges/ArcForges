# ArcForges.LocalRpc

Generated gRPC over HTTP/2 between a parent and the helper or extension children it owns, carried only by
a Windows Named Pipe or a Unix domain socket. The project is non-packable until its package task admits it.

This is transport and framing (WP-08.00) and the parent-owned launch identity (WP-08.01). It has no LocalBootstrap
authentication, registration lease, routing, call queue, retry or brokered-resource logic; those are the later local
RPC tasks. It does not define a contract: the services it serves are the generated `ArcForges.Contracts.LocalRpc.*`
bindings, registered explicitly by their owner.

## What it provides

- `LocalRpcEndpoint` validates an address: a flat Windows pipe name, or a canonical absolute Unix socket path of
  at most 100 UTF-8 bytes. A pipe is refused off Windows and a socket is refused on Windows. There is no host,
  port, URL, discovery manifest or DNS name.
- `LocalRpcServer` hosts Kestrel with a custom `IConnectionListenerFactory` that can bind nothing but this
  transport; its builder registers each generated service explicitly (`AddService`) and nothing is found by
  scanning. The host is a generic web host; it does read `ASPNETCORE_*` settings into host configuration,
  but its only Kestrel endpoint is the explicit private one, which overrides any URL or port setting, so no address
  results, and `ASPNETCORE_PREFERHOSTINGURLS=true` makes startup fail. The other connection listener factories are
  removed, and `StartAsync` fails closed if any non-local address is bound. An optional connection decision
  (`AuthorizeConnections`, or `AuthorizeConnectionsAsync` with a cancellable asynchronous decision) runs on every
  accepted connection before HTTP/2 reads a byte. The decision runs on the thread pool, off the accept loop; a decision that
  throws, does not finish within `LocalRpcLimits.AuthorizationTimeout` (default 2 s, whether it yields or blocks its thread, in
  either overload) or is cancelled denies the connection. A decision that ignores its token and never returns keeps its
  pool thread. Stopping the server cancels a pending decision and drops the stream unread. The decision sees the transport, a sequence number and, for a listening
  endpoint, that endpoint; it does not see the peer process or user.
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

## Parent-owned launch identity (WP-08.01)

A parent creates one `LocalRpcLaunchAuthority` (`Create(runtimeRoot)`), and each child it starts is one
`Launch(slot, identity, transport)`:

- **Descriptor.** `LocalRpcLaunchDescriptor` is the parent's immutable record of the launch: launch id, slot, epoch,
  endpoint (or none when the launcher supplies streams), the parent process (id and start time), the expected child kind,
  build id and digest, protocol version and contract-set digest, a random 32-byte nonce, the issue time and the bootstrap
  deadline (default 30 s). `Encode`/`Decode` are one canonical versioned binary form that refuses truncation, trailing
  bytes and every malformed value as `FormatException`. The descriptor holds no secret.
- **Epoch fencing.** A slot is one logical child. Launching a slot again gives the next epoch and revokes the previous
  launch, so a descriptor of an older epoch is stale and `Verify` refuses it whatever else it carries. Epochs are per
  authority and in memory: they do not survive a parent restart (a new parent has a new process identity and random launch
  ids, so an old descriptor matches nothing; registration freshness after a restart belongs to the registration task).
- **Claims.** A child makes a `LocalRpcLaunchClaim` from its descriptor. `Verify` checks, in order: the launch is not
  revoked, the descriptor was issued by this running process, a bound child process still runs, the bootstrap window has not
  passed, the launch id/slot/epoch, the nonce (fixed-time), the child kind/build id/build digest, and the protocol version
  and contract-set digest. Each failure has its own `LocalRpcLaunchRefusal`; callers must not reveal which one to a child.
  Build id, build digest, kind and protocol are compared with what the child claims: nothing here measures the child's binary,
  so a matching claim is not an attestation of the executable (the launcher's signed-inventory check owns that).
- **One-use secret.** Each launch holds a random 32-byte secret. `HandoffBootstrapResource()` returns the descriptor
  followed by the secret once, for the launcher to write into a private inherited resource (never argv, environment or a
  file) and clear. `ConsumeSecret` runs a callback over the secret exactly once, destroys it whatever the outcome and, when the callback
  returns and the launch still authorizes, ends the bootstrap window. It refuses (the secret is destroyed, the callback does not run,
  `InvalidOperationException`) when the launch does not authorize at the start: expired, revoked, issuing parent gone or bound child
  gone. A callback that finishes after the deadline does not extend the launch (expiry is latched), and a callback that throws leaves
  the window running with the secret spent. The callback runs outside the launch lock, over a copy that is zeroed when it returns, throws
  or is refused. **A callback that returns, whatever its result, ends the bootstrap window**: a caller that rejects the proof must
  revoke the launch itself (the registration task does). The bootstrap window runs out on whichever clock gets there first, the
  monotonic one (a wall-clock step back cannot extend it) or the wall clock (a step forward, or a suspended machine, shortens it); when
  expiry is first seen it is latched and the stored secret is destroyed. The secret is zeroed in managed memory only: it is not pinned, locked or protected from a debugger. The
  HMAC transcript that uses it is the registration task's.
- **Child process.** `BindChild` records the launcher's verified child process (id and start time); from then on the launch
  authorizes only while that process runs. The check happens when a claim or connection is decided; no watcher runs, so a
  child that exits is noticed at the next decision. Process start values are compared within 2 s. On Windows and macOS the start
  value is the UTC start time. On Linux it is the start in clock ticks since boot read from `/proc/<pid>/stat` (USER_HZ taken as 100),
  because the start time .NET reports on Linux follows the wall clock; a process that is gone or a zombie counts as dead, an unreadable
  `/proc` entry as unknown. The value is ticks since boot, so a record written before a reboot whose process id and tick happen to
  coincide with a running process is taken as that process: the directory is kept, never deleted (it fails safe). The Linux path
  ran only in hosted CI (a self-probe and the parser tests), and the reboot case was not exercised at all.
- **Endpoint files.** A private endpoint on Linux/macOS is a socket inside a per-launch directory of an owner-only root. The
  root and each launch directory are created with owner-only access in the same call (mode 0700 on Unix, a protected DACL
  naming only the current user on Windows), a launch directory is built under a temporary name with its record and renamed into
  place, and it is removed by renaming it away and then deleting it. The record names the launch id, parent process and epoch
  (its endpoint-address field is written empty) and no nonce or secret. Existing roots must not be links and must be owner-only: on
  Windows the owner must be the current user or Administrators and any allow rule for another principal than the current user, SYSTEM or
  Administrators is refused; on Unix the check is the mode only (no group or other bits), with no ownership check, so a directory owned by
  someone else with mode 0700 fails closed for an ordinary user but a root parent is not protected. On Windows the private endpoint is a Named Pipe with
  an unguessable per-launch name and no file.
- **Parent death.** A killed parent runs no cleanup. `Create` and `SweepStale` remove a launch directory only when its creator is proven
  gone: its record names a parent that is not running (id and start value compared, so a recycled id counts as gone), or it has no record at
  all and is older than 60 s; leftover removals go at once and a temporary directory that was never renamed into place after 60 s (the sweep
  never opens anything inside it). A record that exists but cannot be read or understood (a newer format, damage, a handle held by another
  program) proves nothing, so that directory is never removed and accumulates until someone clears it. A directory of a running or unverifiable
  parent, a link, or anything this library did not create is never touched. Launches abandoned in memory are not detected; an owner disposes each
  launch (`DisposeAsync`), and disposing the authority disposes every launch it issued.
- **Connections.** `launch.AuthorizeConnectionAsync` is the decision for a server built over the launch's endpoint or streams. It
  admits a connection only while the launch authorizes and only when the connection arrived on the launch's own endpoint.
  Revoking a launch cancels `Revoked`; the owner closes its server connections then, since an HTTP/2 connection admitted earlier
  stays open until the owner closes it. `Revoked` callbacks run synchronously on the thread that revoked, outside the authority's lock, so
  they may call the authority. An exception a callback throws is swallowed: the launch is revoked either way and the failure does not
  reach the caller that caused the revocation (for example the launch call that superseded it).

## OS user boundary

A Named Pipe is created with `CurrentUserOnly` (a DACL granting only the current user); the first instance also
uses `FirstPipeInstance`, so binding fails when the name already has an instance, and the client requires the
server end to be owned by the current user. The pipe is not created with the reject-remote-clients flag and a
client reaches it through `\\127.0.0.1\pipe\<name>` as well; it is limited to the current account by its DACL and
is not claimed to be network-isolated. A Unix socket is bound only in a directory with no group or other
permission bits, is never created over an existing file, is set to mode 0600 and is removed when the listener is
unbound; the client refuses a symbolic link.

This package does not read the peer process or user of an accepted connection and does not authenticate the
child. A same-user process that learns an endpoint's address can connect to it: the launch descriptor, the nonce and the
one-use secret decide what a claim may do, and the proof that uses the secret is the registration task's (WP-08.02); until that
task exists nothing here proves who is on the other end of a connection. Reading the peer would need a native binding on
Windows (the repository restricts those) and, for the launch-bound streams the design prefers, names the creating parent rather
than the child (see annex 09); `Socket.GetRawSocketOption` could read `SO_PEERCRED` on Linux without a native binding but is
not used. Pipe-name squatting by another process of the same user is contained by the unguessable per-launch names and the
client's owner check; the owner check against a foreign pipe is not tested.

## Validation

`Tests/` (`ArcForges.LocalRpc.Tests`) runs offline in CI: real Kestrel HTTP/2 and Grpc.Net.Client over
in-memory duplex streams, with raw HTTP/2 and gRPC frame fixtures. Opt-in local OS checks, skipped by default and
in hosted CI, exercise a real Named Pipe, a real Unix-domain-socket code path and the absence of a TCP
listener for the process:

```powershell
$env:ARCFORGES_LOCALRPC_OS_STREAMS = '1'
dotnet test --project src/BuildingBlocks/ArcForges.LocalRpc/Tests/ArcForges.LocalRpc.Tests.csproj -c Release
```

The launch directory, owner-only and sweep checks are ordinary file-system tests that also run in hosted CI; the Windows
access-control and the Unix mode checks each run only on their own platform. A second opt-in class
(`LocalRpcLaunchProcessChecks`, same variable) starts real helper processes from the test assembly through
`DOTNET_STARTUP_HOOKS`: concurrent launches from four processes, a parent killed without cleanup followed by a sweep, and a
launch-authorized server over a real endpoint whose bound child is killed.

Hosted CI never executes those checks and a successful run on one OS says nothing about the others.
