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
the failing step and a stable reason (`DecisionReasons`: 49 reasons, each belonging to exactly one step and mapped to a
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

Not provided here and not claimed: the real permission-grant store, product policy, trust evaluation (PLT.43), egress
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

### Validation actually run

Offline `ArcForges.Security.Tests` on Windows 11 with the pinned SDK 10.0.400: the refusal matrix (every reason of steps 1
to 11), step coverage, point profiles, bypass, execution, bookkeeping, service-decision, risk, approval, permission, bounds
and LocalRpc boundary tests. The last run against real launch authorities and launches (no child process and no OS stream).
The matrix proves a distinct stable code per reason and a refusal at the failing step through both `EvaluateAsync` and
`ExecuteAsync`. Timeout tests use the real clock.
