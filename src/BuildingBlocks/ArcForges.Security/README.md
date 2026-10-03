# Principals and actor-chain provenance (PLT.36)

This nonpackable mechanism constructs a complete, immutable actor chain at an
entry point and carries it explicitly. Identity evidence does not authenticate a
caller or authorize an operation. Agent profiles are configuration, never human
principals. Delegated execution retains the human owner and each intervening actor.

Offline queue and serialization tests cover lossless propagation and malformed
input refusal. They do not prove live process authentication, persisted queues,
product integration, or the later PLT.38 enforcement decision pipeline.

## Instruction provenance (PLT.42)

Instruction-bearing text enters this building block through `InstructionInput.Capture` with
one of six explicit origins: model output, extension output, retrieved content, imported
document, deep link, or catalog metadata. Each input owns an immutable string and carries a
bounded source reference plus a SHA-256 binding over the origin, reference, and content. The
binding detects accidental snapshot corruption; it is not a signature and does not authenticate
the asserted source.

`InstructionSnapshot` is a bounded, strict process-boundary representation. It rejects unknown,
duplicate, missing, unsupported, and content-mismatched fields. Decoding preserves the same
untrusted status. `ActorOperation<T>` can carry or forward marked content and the actor chain,
but it is only a carrier: neither provenance nor the chain authorizes execution. An enforcement
point must still run the separate decision and authorization pipeline before acting.

## Supporting registrations (ADP.07)

The owned artifact is `src/BuildingBlocks/ArcForges.Security/**` including its
nested offline test project. Before supporting edits, claim epoch 1 binds:

- `DesktopPlatform.slnx` and `.github/workflows/package-validation.yml`: append
  Security test registration using the shared solution/CI append protocol.
- `eng/policy/licence-boundary.json`, `eng/policy/runtime-ownership.json`, and
  `eng/policy/reconciliation/active-projects.json`: register the exact owned
  project and its offline tests using the shared project-inventory protocol.
- `eng/provenance/files.json`: append first-party source/test paths and remove
  the replaced scaffold path using the provenance registration protocol.
- `eng/policy/dependency-policy.json` and
  `eng/policy/dependency-reviews/plt-36-r1.json`: bind regenerated owned locks and
  the already admitted Foundation/xunit closure via an immutable successor
  receipt. No dependency version, framework, or publication admission changes.

## Decision pipeline and the four enforcement points (PLT.38)

`SecurityDecisionPipeline` (namespace `ArcForges.Security.Decisions`) implements the fourteen-step decision pipeline
of requirements 07 section 11 once and runs it at the four enforcement points of architecture 08 section 2. It holds no
mutable state, so one instance serves concurrent requests. Every step produces a typed `StepOutcome`; a refusal names
the failing step and a stable reason (`DecisionReasons`: 59 reasons, each belonging to exactly one step and mapped to a
code of the closed registered reason-code set, which this task does not extend). Reasons are more granular than steps,
so a step can refuse for several distinct causes; every step 1 to 14 has at least one reason.

| Point | Steps it runs | Authority |
|---|---|---|
| `CallerPreCheck` | 1, 2, 3, 4, 5, 6, 9 | Advisory only (`IsAuthority` is false); nothing is audited, no approval is read and no step-up proof is spent |
| `TransportBoundary` | 3, 5 | Admission of a connection only |
| `ServiceDecision` | 1 to 10 | The substantive decision; the input of `ExecuteDecidedAsync` |
| `OwnerFinalValidation` | 11, then 12 to 14 through the execution route | Final; the owner validates last and never relies on an earlier point |

The steps are: 1 capability exists in the authoritative catalogue, 2 product policy, 3 actor identity (the transport
session is verified first, then the identity verifier), 4 realm and workspace scope, 5 software and package trust,
6 capability permission, 7 resource authorization, 8 secret use and data egress, 9 effective risk, 10 approval, step-up
and local presence, 11 owner final validation, 12 execution, 13 result and effect recording, 14 audit write.

What is real and what is a port:

- Real Security mechanisms are used directly: the `ActorChain` (step 3 compares the transport-bound caller instance with
  the chain's), `RiskModel.Assess` (step 9: the descriptor is read from the catalogue and cloned, never taken from the
  request; for a chain with several actors the most severe actor decides; declared and owner-established risk facts are
  combined and can only raise risk), and `ApprovalCoordinator` and `StepUpCoordinator` (step 10).
- Facts owned elsewhere are consumed through ports the host must implement. None has a permissive default and every
  verdict enum starts at `Unknown`, which refuses: catalogue, product policy, identity, scope, trust, permission grants,
  resource authorization, secret and egress authorization, the owner validator, the result recorder and the audit sink. A
  source that throws, is cancelled by its timeout, answers `Unknown` or an undefined value, or does not answer within
  `DecisionPipelineOptions.StepTimeout` (default 15 s, at most 5 min) refuses its step with that step's `Unavailable` reason;
  only the caller's own cancellation propagates.
- Step 6 reads a `PermissionGrantRecord` (principal, capability, scope, constraints, lifetime). The record must name exactly
  the requested principal, capability and scope. The lifetime is half open (valid from its start, over at its end) and is
  judged at use. The pipeline understands exactly two constraints (`origin.local-only` and `device:<id>`) and refuses any
  other, so a constraint can narrow a grant but never widen it.
- Step 10: approval is required when the descriptor's approval posture is anything but `none` (or absent) or when effective
  risk is R3 or R4. Step-up is required for an enumerated sensitive operation or at R4, and R4 also needs a step-up operation,
  a local-presence proof, a local request and a locally decided approval. The approval must be approved, unexpired (an
  approved approval expires at its expiry instant too), decided by the owner and bound to the exact command, capability,
  resource, revision, effect digest and effective risk. A step-up proof is spent only when every other requirement of the step
  already holds, and it stays spent if a later step refuses. The approval store has no executed state, so a repeated command is
  prevented by the invocation record's command identity (PLT.24), not by this step.

Trust boundaries and limits worth stating plainly:

- Which capabilities are enumerated sensitive operations is decided by the host's `ISensitiveOperationSource`, never by the caller:
  if the source names an operation for the capability, the request must declare exactly that operation (otherwise step 10
  refuses with `S10StepUpOperationUnspecified`) and carry a matching step-up proof; a source that fails or answers an undefined
  value refuses. A caller can still add an operation the source does not name, which only makes the step stricter.
- The permission instant is read after the grant source answers, so a slow source cannot make an expired grant look current.
- `ExecuteDecidedAsync` re-runs only step 11 (steps 1 to 10 are not repeated, because a step-up proof and an approval are consumed
  once): a revocation inside the service decision's lifetime (default 60 s, configurable up to 10 min) is caught only if the owner
  validator notices it. Keep the lifetime short, or have the owner validator re-check grants.
- The step timeout bounds sources that are asynchronous or ignore their token; it cannot interrupt a source that blocks its thread
  synchronously, which holds that thread until it returns.
- The ticket carries no single-use or expiry state of its own and is valid for the one call it was made for: an owner operation
  must compare the ticket's capability and resource with what it is about to touch.

Unbypassable by construction: the only code that can reach an owner operation is `ExecuteAsync` and `ExecuteDecidedAsync`.
They pass the operation an `AuthorizedExecution` ticket (sealed, no public constructor or factory, not serializable) only
after steps 1 to 11 passed, the owner's validation being the last. An owner operation that takes the ticket as its parameter
cannot be called without the pipeline. `ExecuteDecidedAsync` continues only from this pipeline's own allowed service decision
for the same request object; the decision is single use and stale at its lifetime (default 60 s, judged on the monotonic and
the wall clock, whichever gets there first), and a foreign, refused, earlier-point, reused or stale decision is refused at
step 11. A decision that fails any of those checks other than reuse is not spent. This is a type-level guarantee for owners
written against the ticket; it does not stop code that calls its own functions without the pipeline. Attaching the pipeline to
the invocation pipeline's authorize step in a real product is PLT.57. `SecurityDecision.ToAuthorizationOutcome()` gives the
shape that step expects (success, or a typed failure with the registered code) and is only offered for service and owner
decisions.

Bookkeeping after the owner ran: the result is recorded (step 13) and audited (step 14) with tokens that the caller's
cancellation does not cancel, each bounded by the step timeout. If either fails the execution reports `BookkeepingFailed`,
the visible result for a succeeded owner is a typed failure whose effect certainty is `Happened`, and the decision lists the
failing step. A failed audit write of a refusal never changes the refusal. Owner exceptions become the registered
unknown-effect failure and owner cancellation keeps the effect certainty the owner reported.

`ProjectPermissionAsync` and the pre-check give the read-only permission projection (`PermissionAvailabilityEvidence`) for
a principal, capability and scope: disposition, constraints, lifetime, issuer and source generation as of an observation
instant. It is a user-interface preflight only, never a grant, resource authorization or substitute for the owner's
validation. Mapping it into the Capabilities availability evidence belongs to the composition that owns both projects.

Not provided here and not claimed: the real permission-grant store, product policy, the host's trust fact sources, egress
decision (PLT.41) and the record and audit adapters (the invocation record store and the audit store are separate projects
that Security does not reference); the registration lease and bootstrap proof exchange (PLT.11); peer operating-system
identity; and any cross-process call, since the service decision and the ticket are in-process objects.

### Transport boundary over LocalRpc (`ArcForges.Security.LocalRpcBoundary`)

A separate non-packable nested project binds the transport-session port to the real `ArcForges.LocalRpc` launch identity,
so Security itself stays free of the ASP.NET Core and gRPC references. `LocalRpcTransportSession.Establish` requires the
claim to name exactly the launch, then the launch authority to verify it (launch, slot, epoch, nonce, build, protocol,
parent and any bound child still running, bootstrap window open), and only then consumes the launch's one-use secret through
a proof check supplied by the caller. A claim that does not verify spends nothing. A proof that is rejected or throws revokes
the launch, because the secret is already spent (the known PLT.10 limit that a returned callback ends the bootstrap window
whatever it decided). A second establishment on a spent launch is refused without revoking the first session. The session is
verified again at every boundary through `LocalRpcLaunchAuthority.Verify`, so a revoked, superseded (relaunched slot) or
disposed launch, or one whose parent or bound child is gone, stops vouching at the next call. The refusals are collapsed to
a closed set (`TransportRefusal`) and callers must not tell the child which one applied. The binding records the assurance
`LaunchClaimWithSecretProof`: it does not read the peer's operating-system identity (PLT.10's known limit) and does not run
the registration or the proof exchange. The caller instance it binds is whatever the caller passes (null until PLT.11
supplies it); when set, the actor chain's caller instance must equal it. `TransportSessions.InProcess` is the explicit session
of a caller in the same process: it authenticates nobody and every other step still runs.

### Capability leases (PLT.43)

`ArcForges.Security.Leases` implements BR-07, CL-01 to CL-04, DG-01 and DG-02. A lease is a durable, scoped, expiring,
revocable and audited narrowing of the delegator's own authority for one accepted tool or extension invocation:

- **Identity.** `CapabilityLeaseId` is a non-empty, immutable, Guid-backed value; every lifecycle fact of a lease carries the
  same one, and an audit intake maps its `Value` directly. The identity is an address, not a credential.
- **What a lease covers.** Exactly one capability, an exact set of 1 to 64 resource identities, one realm and workspace, one
  task, one holder (an agent or an extension, by kind and exact actor identity) and one owner. The coverage is immutable; a
  stored lease can only end. It lives at most 24 hours (`LeaseOptions.MaximumLifetime`, default one hour).
- **Issue** (`CapabilityLeaseManager.IssueAsync`). The delegator's own permission is read through `ILeaseCeilingSource` at the
  instant it answered and must be granted, inside its lifetime and constraints (a constraint that is not understood refuses);
  the lease cannot outlive it. A chain whose last actor is an agent or an extension cannot issue (no sub-delegation, CL-03);
  automation and internal services may issue for the owner; automation and internal services cannot hold a lease. The
  "issued" fact is written durably before the lease is stored, so a lease exists only if its issue was audited; the cost of that
  order is an audit record of an issue that never took effect when the store fails afterwards. A replayed request is a
  duplicate and writes no second fact.
- **Use is judged at every use** (`ValidateAsync`): stored state, then the exact holder, owner, scope, capability and
  resource (anything else is out of scope, whatever the lease's state), then expiry (exclusive: at `ExpiresAt` it is over).
  Time is the wall clock but never earlier than the monotonic time since the manager started and never earlier than an
  instant it already judged, so a wall-clock step back cannot extend a lease. An expiry that is observed is stored, so it cannot
  be revived by a later step back or a new manager. Across a restart only the wall clock exists; that gap is real.
- **Revocation and the end of the task** (`RevokeAsync`, `EndTaskAsync`, `ExpireDueAsync`). Only the lease's owner can revoke.
  The end is stored before its fact is written, so authority ends even while the audit sink is down; the fact is then owed
  (`EndEventRecorded` is false) and a sweep retries it. A use never writes anything for an ended lease. Facts are written at
  least once (a failure after the write but before the mark, or a sweep racing the ending call, can repeat one): the lease
  identity plus the event kind identify a fact because a lease ends exactly once. The host calls `EndTaskAsync` when a task
  ends; nothing here observes tasks, so a lease still ends at its expiry if the host never does.
- **Durability.** `ILeaseStore` is the contract (insert-if-absent, compare-and-swap on the version, forward transitions only,
  a true result only after the commit). Production Security stays Foundation-only; the durable adapter is the host's. The offline
  tests drive a test-only adapter over the real `SqliteStore` (close and reopen, stale replacement across two open stores,
  restart after revocation, expiry, task end and owed facts). `SqliteStore` has no enumeration, so that adapter keeps a lease
  index aggregate written after the lease; a production adapter would index its own table.
- **In the decision pipeline.** `DecisionRequest.Lease` names the lease a delegated actor claims, and
  `DecisionPipelineServices.Leases` (optional) is the use-time check. At step 6, after the delegator's own permission passes
  (a lease never replaces it), an agent or extension acting without a lease is refused (`S06LeaseRequired`), a lease that does
  not cover exactly this use is refused (`S06LeaseOutOfScope`), and a lease that is expired, ended with its task or revoked is
  refused (`S06LeaseExpired`, registered code `perm.lease_expired`; `S06LeaseRevoked`); a check that fails, is unknown or is
  not configured refuses (`S06LeaseUnavailable`). Step 11 runs the same check again before the owner is asked (`S11Lease...`),
  so an expiry or revocation after the service decision still stops the owner operation. `AuthorizedExecution.Lease` hands a
  long operation the `LeaseUse` to re-check at each security boundary. The audit record of step 14 carries the lease identity.
  An owner acting directly needs no lease and a lease it claims is out of scope; automation and internal services are
  re-authorized by permission at each trigger (DG-03) and need none.

### Typed trust (PLT.43)

`ArcForges.Security.Trust` implements section 9 of the security requirements and section 10 of the architecture. Trust is typed,
never a scalar: five kinds with their own closed states (publisher, package, software identity, device, extension state), each
starting at `Unknown`, which is never eligible; the namespace has no numeric trust level and names no permission, grant, lease or
decision type. A verified signature or publisher is "eligible", never "safe" (TR-02, TR-03).

- **Defined points** (`TrustEvaluationPoint`, `TrustPoints.KindsAt`): package install or update (publisher, package), extension
  host start (package), local RPC handshake and extension host handshake (software identity), cloud authentication and remote
  invocation (device), extension invocation (extension state). `TrustEvaluator.AssessAsync` reads exactly the kinds of one point,
  once each, from the host's `ITrustFactSource`.
- **Step 5** (`TrustEvaluator` implements `ITrustEvaluator`): every request reads the caller's software identity, an extension
  also its package and extension state, a remote request also its device. Eligibility combines strictest first: any kind not
  eligible (revoked, mismatched, untrusted, installed but not enabled) refuses as `TrustVerdict.Revoked`, any kind unknown or
  undefined refuses, any kind eligible but unverified (unverified, developer mode) passes with the pipeline's higher risk floor,
  and only all eligible is verified.
- **Trust never substitutes for permission** (TR-01, TR-04, TR-09): verified trust of every kind with no grant is refused at
  step 6; a grant with revoked or unknown trust is refused at step 5 without consulting the permission source; changing trust
  from unverified to verified changes nothing about the permission outcome; unverified trust raises risk and grants nothing; trust
  is not a lease either.

### Validation actually run

Offline `ArcForges.Security.Tests` on Windows 11 with the pinned SDK 10.0.400: the refusal matrix (every reason of steps 1
to 11), step coverage, point profiles, bypass, execution, bookkeeping, service-decision, risk, approval, permission, bounds
and LocalRpc boundary tests. The last run against real launch authorities and launches (no child process and no OS stream).
The matrix proves a distinct stable code per reason and a refusal at the failing step through both `EvaluateAsync` and
`ExecuteAsync`. Timeout tests use the real clock.

## Egress control (PLT.41)

`ArcForges.Security.Egress` makes every outbound data transfer its own authorization, distinct from the read access that let a
caller see the data (EG-01, I-254). `EgressAuthority.DecideAsync` takes a pipeline `DecisionRequest` and the exact destination and
returns an `EgressDecision`; `EgressAuthority.TransferAsync` is the guarded route for the owner's send operation.

A transfer is allowed only when all of these hold, checked in this order, and the first failure refuses with a typed
`EgressReason` (each with a stable code and a registered semantic code: `perm.egress_denied` for a denial, `resource.unavailable`
when a source cannot answer):

1. The destination is an exact destination identity (`EgressDestinationIdentity`): one lower-case HTTPS origin, written as a name.
   A wildcard, category, path, query, userinfo, single-label name, invalid port or non-ASCII host is not an identity, and neither is
   an address literal: the last label must be letters only or an `xn--` label, so decimal, octal, hexadecimal and short-form IPv4
   literals (`127.1`, `0x7f.0x1`, `0xa9.0xfe.0xa9.0xfe`) are refused. Names that are not public are refused too: `localhost`,
   `.local`, `.internal`, `.localdomain`, `.lan`, `.home.arpa`, and the reserved or conventionally private suffixes `.test`,
   `.example`, `.invalid`, `.corp`, `.intranet`, `.private` and `.home` (a private suffix not on that list still passes; the
   allowlist, not the parser, is what makes a destination reachable). Two identities are equal only when their canonical
   origins are equal (so `api.example.com.evil.net` or `api.example.com:8443` is another destination). It must also be the
   destination the invocation declared (`DecisionRequest.EgressDestination`).
2. The content is classified by the host's `IEgressContentClassifier` (data class, and whether the knowledge policy makes it
   AI-eligible). The classification never comes from the caller. `SecretMaterial` never leaves, whatever an allowlist or a grant says.
3. The scope's `IEgressAllowlist` names the destination (the entry states the destination class and the highest data class that may
   go there), and a destination of class `CloudAiProvider` receives only AI-eligible content (EG-02, EG-03).
4. The principal holds an egress grant (`IEgressGrantSource`, `EgressGrantRecord`) for exactly this principal, capability, scope and
   destination, in its half-open lifetime, admitting the content class. A standing `Denied` record wins over every grant. The grant
   records the authority it rests on (user consent, workspace policy or product route) and a reference to it. Egress grants are
   not the capability permissions of step 6, and no read permission is an input of the decision.
5. The decision is durable in the `IEgressAuditSink`. An allowed decision whose record cannot be written is refused
   (`AuditUnavailable`), so nothing is authorized without its audit event; a refusal is audited best effort and never changes.

Every decision, allowed or refused, attempts one `EgressAuditRecord` write before it is returned (one attempt per decision; an allowed
decision whose write fails becomes the `AuditUnavailable` refusal, and that refusal is not written a second time). The record holds: kind, reason, time, the
complete actor chain, executor, capability, resource reference, scope, origin, device, correlation, the destination identity and
class, the data class, the authority and its reference, and the grant and allowlist generations. A write that times out may still
land in the sink after the caller was refused, so the durable log can show `Authorized` for a transfer that was refused (over-audit,
which is safe for the transfer); an audit adapter (PLT.44) must treat that pair as possible. The record carries classes, identities and
references only; no payload, content or secret, and the text of a malformed destination is not echoed.

Source failures fail closed: a classifier, allowlist or grant source that returns nothing, throws, or does not answer within
`EgressAuthorityOptions.StepTimeout` (default 15 s, at most 5 min) refuses with its `Unavailable` reason and an `Unknown` verdict.
Only the caller's own cancellation propagates. The audit write is bounded by the same timeout and is not cancelled by the caller.

Two integration shapes, both with no permissive default:

- **Pipeline step 8.** `EgressDataBoundary(authority, secretUseAuthorizer)` is an `IDataBoundaryAuthorizer`: egress answers come
  only from the authority and secret-use answers only from the host's own authorizer, whose egress answer is never consulted. The
  pipeline's step 8 stays a verdict (`Allowed`, `Denied`, or `Unknown` for an unavailable source); the specific egress reason is
  in the egress audit record. The step runs when the pipeline makes its service decision, so a decision that is allowed here
  and refused by a later pipeline step is still an audited authorization, not a transfer.
- **The send itself.** `TransferAsync(AuthorizedExecution ticket, destination, operation, ct)` decides again for every transfer
  (a revocation or an expiry is seen at the next one), refuses any destination other than the one the invocation declared, writes
  the audit record, and only then calls the owner's `EgressOperation` with a sealed `AuthorizedEgress` ticket (no public
  constructor or factory) naming the exact destination, classes and authority. The ticket proves one decision; it has no single-use
  or expiry state, so the send operation must use only the destination it names and not keep it for a later transfer. A refusal returns a typed failure with the
  registered code and the operation is never called.

Not provided here and not claimed:

- The real classifier, allowlist and grant stores and the audit sink adapter (the audit store is a separate project that Security
  does not reference; PLT.44) are ports the host implements. The attachment to a product's invocation pipeline is PLT.57; the
  context and artifact integration that sends data is APP.06.
- The authority does not intercept sockets. An owner operation that takes the `AuthorizedEgress` ticket cannot be called without a
  decision, but code that opens a connection by itself is not stopped, and it is for the sender to connect only to
  `ticket.Destination`, to resolve and pin the name, and to refuse a redirect to another origin. Name-based identity says nothing
  about which address answers.
- Whether a classifier labels content correctly, and whether a grant truly reflects the user's consent, are the owners' facts;
  the offline tests use fakes for every port.
- Effective risk (step 9) is not an input: the pipeline already raises risk for an external destination and automation.
- A grant has no origin or device constraint; a remote origin is judged by the pipeline's own steps.
