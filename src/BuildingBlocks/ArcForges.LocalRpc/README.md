# ArcForges.LocalRpc

Generated gRPC over HTTP/2 between a parent and the helper or extension children it owns, carried only by
a Windows Named Pipe or a Unix domain socket. The project is non-packable until its package task admits it.

This is transport and framing (WP-08.00), the parent-owned launch identity (WP-08.01) and the call bounds on top of
them (WP-08.04). It has no LocalBootstrap authentication, registration lease, routing, retry or brokered-resource logic; those
are the later local RPC tasks. It does not define a contract: the services it serves are the generated
`ArcForges.Contracts.LocalRpc.*` bindings, registered explicitly by their owner.

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
  an extra peer waits in the OS backlog (16) and is served when a slot frees; it is not reset. A peer that holds a slot
  without calling is closed by the handshake and idle limits below.
- `LocalRpcStreamSupplier` is the launcher's hand-over of already-connected OS streams. A server built over a
  supplier accepts only those streams.
- `LocalRpcClientChannel` is a `GrpcChannel` over `http://arcforges.invalid` whose `ConnectCallback` returns
  only the verified OS stream: one HTTP/2 connection, no retry, hedging, load balancing, connection recycling
  or fallback to DNS/TCP, and no compression providers.
- gRPC messages are limited to 4 MiB in both directions (`LocalRpcLimits`). Compression is refused: a request that
  names any `grpc-encoding` other than `identity` is answered `UNIMPLEMENTED` before routing and before any
  decompression, so the bound holds for the decoded size as well. Detailed error text is off.

## Call bounds (WP-08.04)

Every connected peer (one connection) has its own lanes; a peer that saturates its lanes does not slow another.

- **Data lane: 16 active, 64 queued.** A call that is routed to a registered gRPC method (an unknown service is
  answered `UNIMPLEMENTED` before admission) takes one of 16 active slots or waits for one in arrival order in a queue
  of 64. Inside the gate the queue is strictly first in, first out and a freed slot is handed to the oldest waiter; that is
  order of arrival at the admission gate, not order on the wire (the server starts concurrent requests on the thread pool,
  so calls submitted back to back can reach the gate slightly out of submission order). A call over the
  bounds is refused before dispatch and before its body is read. `LocalRpcLimits` may lower the numbers, never raise them.
- **Two reserved control slots.** Methods the owner declares with `RegisterControl` (bootstrap, lease renewal,
  cancellation, health) run in two slots of their own, outside the data budget, so 16 data calls and 2 control calls run at
  the same time. A control call never waits: a third concurrent control call is refused at once. `StartAsync` fails when a
  declared control method is not served by a registered service, so a misspelled name cannot silently run as a data
  call. Nothing is declared by default: the library names no contract method, the owner of each service declares its own.
- **Deadlines.** A data call without a deadline gets 10 s, a declared deadline is shortened to at most 30 s, and a control
  call is held to 5 s. Time spent waiting for a slot counts: a call whose deadline passes in the queue is refused
  `DEADLINE_EXCEEDED` without dispatch, and an admitted call is handed the time that remains. The slot is held until the
  handler actually returns, so the active bound counts running code even for a handler that ignores its deadline;
  that handler pins its slot, and the control slots exist so that cancellation and lease renewal still get through.
- **Typed refusal.** A refused call fails with `RESOURCE_EXHAUSTED` (data lane full, control slots busy, callback with no
  free slot) or `DEADLINE_EXCEEDED`, plus the trailers `x-af-refusal` and `x-af-dispatched: 0`;
  `LocalRpcRefusal.TryRead` reads them. Any other failure may or may not have dispatched.
- **Memory.** Two different amounts, stated separately. *Not yet dispatched:* a waiting call costs one queue node and at
  most the HTTP/2 stream window it was granted, which the host pins to 64 KiB (Kestrel's minimum); the worst case for the
  100 streams of one connection is 6.25 MiB of unread request body, 50 MiB across the 8 connections. *Dispatched:* the 16
  admitted calls of a connection may each hold a request and a response of up to 4 MiB, about 128 MiB per connection and
  about 1 GiB across 8 connections. The connection window is flow-control credit, not memory, and it is pinned to 3 x 100 x
  64 KiB (18.75 MiB). Kestrel returns connection credit in half-window steps, so progress needs a free pool of at least half
  the window while every other stream's body sits unread (2 x the 6.25 MiB the streams can hold, plus margin). Smaller
  windows were wrong twice and each failure was reproduced: at 128 KiB two queued 64 KiB bodies stopped every other call on
  the connection, and at 6.25 MiB a burst of 80 concurrent calls with 256 KiB bodies left 16 admitted calls waiting for body
  credit that never came and a health call on the same connection timed out.
- **Silent and idle peers.** A connection that does not begin a call within 10 s of being accepted is closed, and so is a
  connection with no call in flight for 60 s (twice the 30 s lease; a live peer renews every 10 s). A closed connection frees
  its connection slot. A call that is in flight, even one waiting in the queue, keeps its connection open. The limits are about silence, not
  lifetime: a peer that makes one cheap call every 59 s keeps its slot, and nothing accounts per caller. The clock starts when
  a connection is accepted, so a launcher that supplies a stream before its child is ready must raise `HandshakeTimeout`.
  A timer that fires slightly before the clock agrees is re-armed for the remainder rather than dropped.
- **Callbacks.** The reverse direction is a second server and client channel over a separately provisioned, parent-created
  stream, with its own lanes, so callbacks are never queued behind the other direction's data calls. A call made from inside
  a handler carries a marker; the receiving server never queues a marked call (a marked call that finds no free slot is
  refused at once), and a call made from inside such a callback handler is refused by the client before it is sent. Two
  saturated lanes therefore cannot wait on each other. The marker is cooperative and protects first-party endpoints;
  a hostile peer that omits it is still held to the data bounds, the deadlines and the connection limits.
- **Not done here:** there is no client-side limit on outgoing calls (the server refuses the excess), no per-caller
  fairness inside one connection, and the 16/64 bound is per connection, so several connections each have their own
  (the connection bound of 8 limits the total). A call to an unknown service is answered `UNIMPLEMENTED` without admission,
  so a flood of them is limited only by the stream and connection caps. No streaming method exists in the pinned contracts and
  streaming calls are untested (they would hold a slot until they end). The library has not been published with Native AOT by
  this task; only the static trim and AOT analyzers ran.

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

The call-bounds tests run offline in CI over real Kestrel HTTP/2 and Grpc.Net.Client on in-memory streams, with a manual
clock for queue deadlines and the handshake and idle limits and a hand-written test-only service (`BoundsProbe`) standing in
for the cancellation and health methods, which the pinned Platform contract does not have (`CancelSession` is in the Sandbox
contract, which this repository does not admit). Bootstrap and lease renewal use the real generated `LocalBootstrapService`.
One opt-in check runs the 16/64 saturation, a typed refusal, a health call and a cancel over a real Named Pipe and AF_UNIX.

Hosted CI never executes those checks and a successful run on one OS says nothing about the others.
