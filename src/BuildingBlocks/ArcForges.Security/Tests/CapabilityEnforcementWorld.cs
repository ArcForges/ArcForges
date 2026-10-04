// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Contracts.PublicApi.V1;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;
using ArcForges.Sdk.Contracts.V1;
using ArcForges.Security.Approvals;
using ArcForges.Security.CapabilityEnforcement;
using ArcForges.Security.Decisions;
using ArcForges.Security.Egress;
using ArcForges.Security.Leases;
using ArcForges.Security.Trust;
using Google.Protobuf;
using SdkInvocation = ArcForges.Sdk.Contracts.V1.Invocation;
using WireRevision = ArcForges.Contracts.Foundation.V1.Revision;

namespace ArcForges.Security.Tests;

/// <summary>The owner's typed result of the test capabilities.</summary>
internal sealed record EnforcedOwnerResult(string Text, WireRevision Revision);

/// <summary>The host's evidence source: a world's current answer, logged, and replaceable per test.</summary>
internal sealed class WorldEvidenceSource(CallLog log) : ICapabilityEvidenceSource
{
    internal Func<CapabilityRegistration, SdkInvocation, CancellationToken, ValueTask<CapabilityEvidence?>> Behavior { get; set; } =
        (_, _, _) => throw new InvalidOperationException("The world installs the default evidence.");

    private int _calls;

    internal int Calls => Volatile.Read(ref _calls);

    public ValueTask<CapabilityEvidence?> DescribeAsync(
        CapabilityRegistration capability,
        SdkInvocation invocation,
        CapabilityTarget target,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken)
    {
        _ = Interlocked.Increment(ref _calls);
        log.Add("evidence");
        return Behavior(capability, invocation, cancellationToken);
    }
}

/// <summary>The real availability provider, observed: it logs when it is asked and answers exactly as the provider does.</summary>
internal sealed class ObservedAvailability(ICapabilityProvider inner, CallLog log) : ICapabilityProvider
{
    public bool IsBoundToCapability(ActionKey actionKey, string capabilityKey) => inner.IsBoundToCapability(actionKey, capabilityKey);

    public ValueTask<Outcome<AvailabilityResult>> EvaluateAvailabilityAsync(
        ActionKey actionKey,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken = default)
    {
        log.Add("availability");
        return inner.EvaluateAvailabilityAsync(actionKey, context, cancellationToken);
    }
}

/// <summary>
/// A host-owned idempotency journal with the contract the invocation pipeline needs (reserve, reject a changed fingerprint, replay a
/// recorded outcome). It stands in for a durable store; an optional hook runs inside Begin, after authorization and before dispatch.
/// </summary>
internal sealed class WorldRecordStore(CallLog log) : IInvocationRecordStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, (ByteString Fingerprint, InvocationOutcome Outcome)> _completed = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, (string Command, ByteString Fingerprint)> _pending = [];
    private readonly List<InvocationOutcome> _outcomes = [];
    private int _begins;
    private int _completes;

    internal int BeginCalls => Volatile.Read(ref _begins);

    internal int CompleteCalls => Volatile.Read(ref _completes);

    internal IReadOnlyList<InvocationOutcome> Outcomes
    {
        get
        {
            lock (_gate)
            {
                return [.. _outcomes];
            }
        }
    }

    internal Func<Task>? BeforeDispatch { get; set; }

    public async ValueTask<Outcome<InvocationRecordClaim>> BeginAsync(
        ArcForges.Contracts.Foundation.V1.Id commandId,
        ByteString requestFingerprint,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = Interlocked.Increment(ref _begins);
        log.Add("record.begin");
        var command = commandId.Value.ToBase64();
        var reservation = Guid.NewGuid();
        lock (_gate)
        {
            if (_completed.TryGetValue(command, out var previous))
            {
                return previous.Fingerprint.Equals(requestFingerprint)
                    ? Outcome.Success(InvocationRecordClaim.ForReplay(previous.Outcome))
                    : Outcome.Failure<InvocationRecordClaim>(TypedFailure.Create("validation.invalid_request"));
            }

            _pending.Add(reservation, (command, requestFingerprint));
        }

        if (BeforeDispatch is { } hook)
        {
            await hook().ConfigureAwait(false);
        }

        return Outcome.Success(InvocationRecordClaim.ForExecution(reservation));
    }

    public ValueTask<Outcome<InvocationOutcome>> CompleteAsync(
        InvocationRecordClaim claim,
        InvocationOutcome outcome,
        CancellationToken cancellationToken)
    {
        _ = Interlocked.Increment(ref _completes);
        log.Add("record.complete");
        lock (_gate)
        {
            if (claim.Kind != InvocationRecordClaimKind.Execute || !_pending.Remove(claim.ReservationId, out var pending))
            {
                return ValueTask.FromResult(Outcome.Failure<InvocationOutcome>(TypedFailure.Create("internal.unexpected")));
            }

            _completed.Add(pending.Command, (pending.Fingerprint, outcome));
            _outcomes.Add(outcome);
            return ValueTask.FromResult(Outcome.Success(outcome));
        }
    }
}

internal sealed class WorldTrace(CallLog log) : IInvocationTraceSink
{
    private readonly Lock _gate = new();
    private readonly List<InvocationTraceRecord> _records = [];

    internal IReadOnlyList<InvocationTraceRecord> Records
    {
        get
        {
            lock (_gate)
            {
                return [.. _records];
            }
        }
    }

    public ValueTask<Outcome<bool>> WriteAsync(InvocationTraceRecord record, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _records.Add(record);
        }

        log.Add(record.Phase == InvocationTracePhase.Started ? "trace.started" : "trace.completed");
        return ValueTask.FromResult(Outcome.Success(true));
    }
}

/// <summary>
/// One product instance with the real invocation pipeline, the real decision pipeline, the real capability registry and availability
/// provider, the real trust evaluator, the real lease manager, the real egress authority and the real approval and step-up coordinators.
/// Only the facts and sinks that belong to other tasks are test doubles: the permission and policy sources, identity, scope, resource
/// and owner validators, the trust facts, the lease store, the egress allowlist, classifier, grants and audit sink, and the
/// decision record, audit, invocation record and trace sinks.
/// </summary>
internal sealed class EnforcementWorld
{
    internal const string ResourceId = "resource/42";
    internal const string ResourceRevision = "revision:7";
    internal const string GetSession = "IScopeOperations.GetSession";
    internal const string ListSessionsKey = "IScopeOperations.ListSessions";
    internal const string StartCapture = "IScopeOperations.StartCapture";
    internal const string AppendUserMessage = "IChatOperations.AppendUserMessage";
    internal const string Destination = "https://api.example.com";

    private readonly ActionKey _action;
    private readonly string _capability;
    private int _ownerRuns;

    internal EnforcementWorld(
        string capability = GetSession,
        AvailabilityFreshnessDisposition freshness = AvailabilityFreshnessDisposition.Current,
        DecisionPipelineOptions? options = null,
        ulong epoch = 1)
    {
        _capability = capability;
        Clock = new DecisionClock();
        Decisions = new DecisionHarness(clock: Clock);
        Leases = new LeaseHarness(clock: Clock);
        Registry = CapabilityRegistry.CreateInitial();
        Registration = Registry.Find(capability)!;
        var app = Registration.Owner.ProductApp!;
        Identity = new InstanceIdentity(
            new InstallationIdentity(app, new DeviceId(Guid.NewGuid()), new InstallationId(Guid.NewGuid())),
            new InstanceId(Guid.NewGuid()),
            epoch);
        Target = new CapabilityTarget(Identity, Registration.Descriptor, InstanceHealth.Ready, acceptsWork: true);
        _action = new ActionKey("test.action.enforced");

        Facts = new FakeTrustFacts();
        Classifier = new FakeClassifier(Log);
        Allowlist = new FakeAllowlist(Log);
        EgressGrants = new FakeEgressGrants(Log);
        EgressAudit = new FakeEgressAudit(Log);
        Decisions.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(Decisions.Grant(request));

        var egress = new EgressAuthority(Clock.Clock, Classifier, Allowlist, EgressGrants, EgressAudit);
        DecisionPipeline = new SecurityDecisionPipeline(
            new DecisionPipelineServices(
                Clock.Clock,
                new RegistryCapabilityCatalogue(Registry),
                Decisions.Policy,
                Decisions.Identity,
                Decisions.Scope,
                new TrustEvaluator(Facts),
                Decisions.Permissions,
                Decisions.Resources,
                new EgressDataBoundary(egress, Decisions.DataBoundary),
                Decisions.Approvals,
                Decisions.StepUp,
                Decisions.Sensitive,
                Decisions.Owner,
                Decisions.Recorder,
                Decisions.Audit,
                Leases.Manager),
            options);

        Evidence = new WorldEvidenceSource(Log) { Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(DefaultEvidence()) };
        Gate = new CapabilityEnforcementGate(DecisionPipeline, Evidence);

        var scope = new AvailabilityProviderScope(Identity, PrincipalKey, "session:enumeration-1");
        var asOf = Clock.UtcNow;
        var availability = new CapabilityAvailabilityProvider(
            Registry,
            [new ActionAvailabilityRegistration(new ActionDescriptor
            {
                Key = _action.Value,
                TitleKey = "test.action.enforced.title",
                AvailabilityRule = "capability.availability.v1",
                Capabilities = { capability },
            })],
            scope,
            new AvailabilityEvidenceSnapshot(scope, asOf, freshness, [AvailabilityRow(scope, asOf)]));
        Availability = new ObservedAvailability(availability, Log);

        ContextProvider = new ContextProvider<Google.Protobuf.WellKnownTypes.StringValue>(Identity, (_, _) =>
        {
            Log.Add("context.freeze");
            return ValueTask.FromResult<IReadOnlyList<Google.Protobuf.WellKnownTypes.StringValue>>(
                [new Google.Protobuf.WellKnownTypes.StringValue { Value = "invocation" }]);
        });
        AvailabilityContext = FrozenContextSnapshot.Freeze(
            Identity, [new Google.Protobuf.WellKnownTypes.StringValue { Value = "available" }], ContextSnapshotBudget.Default);
        Records = new WorldRecordStore(Log);
        Trace = new WorldTrace(Log);
        Pipeline = new CapabilityInvocationPipeline(
            Registry,
            Availability,
            [Binding()],
            Gate.AuthorizeAsync,
            Records,
            Trace);
    }

    internal DecisionClock Clock { get; }

    internal DecisionHarness Decisions { get; }

    internal LeaseHarness Leases { get; }

    internal CallLog Log => Decisions.Log;

    internal CapabilityRegistry Registry { get; }

    internal CapabilityRegistration Registration { get; }

    internal InstanceIdentity Identity { get; }

    internal CapabilityTarget Target { get; }

    internal FakeTrustFacts Facts { get; }

    internal FakeClassifier Classifier { get; }

    internal FakeAllowlist Allowlist { get; }

    internal FakeEgressGrants EgressGrants { get; }

    internal FakeEgressAudit EgressAudit { get; }

    internal SecurityDecisionPipeline DecisionPipeline { get; }

    internal WorldEvidenceSource Evidence { get; }

    internal CapabilityEnforcementGate Gate { get; }

    internal ObservedAvailability Availability { get; }

    internal ContextProvider<Google.Protobuf.WellKnownTypes.StringValue> ContextProvider { get; }

    internal FrozenContextSnapshot AvailabilityContext { get; }

    internal WorldRecordStore Records { get; }

    internal WorldTrace Trace { get; }

    internal CapabilityInvocationPipeline Pipeline { get; }

    /// <summary>How many times the owner's own operation ran.</summary>
    internal int OwnerRuns => Volatile.Read(ref _ownerRuns);

    internal AuthorizedExecution? LastTicket { get; private set; }

    /// <summary>What the owner's operation returns; a test replaces it to make the owner fail or be cancelled.</summary>
    internal Func<Outcome<EnforcedOwnerResult>> OwnerBehavior { get; set; } =
        () => Outcome.Success(new EnforcedOwnerResult("owner-result", new WireRevision { Value = 12 }));

    /// <summary>The owner's current revision of the resource: what step 11 compares the request's revision with.</summary>
    internal string CurrentRevision { get; set; } = ResourceRevision;

    internal string PrincipalKey { get; } = $"principal:{Guid.NewGuid():N}";

    internal static string CanonicalPrincipal(HumanPrincipal owner) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"principal:{owner.Realm.Value:N}/{owner.Id.Value:N}");

    internal ActorChain DirectChain() => Leases.DirectChain();

    internal ActorChain AgentChain() => Leases.ChainOf(Leases.Agent);

    internal ActorChain ExtensionChain() => Leases.ChainOf(Leases.Extension);

    /// <summary>The evidence of a direct (human-owner) invocation of the capability, with every optional field the capability needs.</summary>
    internal CapabilityEvidence DefaultEvidence(ActorChain? chain = null) => new(
        chain ?? DirectChain(),
        Leases.Scope,
        new ResourceReference(ResourceId, ResourceRevision),
        DecisionOrigin.Local,
        Decisions.Transport,
        egressDestination: Registration.Descriptor.Egress == "none" ? null : Destination);

    /// <summary>Makes the owner's validator compare the request's revision with <see cref="CurrentRevision"/>.</summary>
    internal void OwnerComparesRevision() => Decisions.Owner.Behavior = (validation, _) => ValueTask.FromResult(
        string.Equals(validation.Request.Resource.Revision, CurrentRevision, StringComparison.Ordinal)
            ? OwnerVerdict.Valid
            : OwnerVerdict.RevisionChanged);

    /// <summary>Allows exactly the destination the capability sends to, at workspace-content level.</summary>
    internal void PermitEgress(EgressDataClass dataClass = EgressDataClass.WorkspaceContent)
    {
        Classifier.Behavior = (_, _, _) => ValueTask.FromResult<EgressContentFacts?>(new EgressContentFacts(dataClass, true));
        Allowlist.Behavior = (scopeKey, destination, _) => ValueTask.FromResult<EgressAllowlistEntry?>(
            new EgressAllowlistEntry(scopeKey, destination, EgressDestinationClass.ThirdParty, EgressDataClass.WorkspaceContent, "allowlist-generation-1"));
        EgressGrants.Behavior = (request, destination, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>(
        [
            new EgressGrantRecord(
                "owner.egress",
                request.PrincipalKey,
                request.CapabilityKey,
                request.ScopeKey,
                destination,
                EgressGrantState.Granted,
                EgressDataClass.WorkspaceContent,
                EgressAuthorityKind.UserConsent,
                "consent-1",
                Clock.UtcNow - TimeSpan.FromHours(1),
                Clock.UtcNow + TimeSpan.FromHours(1),
                "grant-generation-1"),
        ]);
    }

    /// <summary>A new delegated lease for the agent of this world, covering this capability on the world's resource.</summary>
    internal async Task<CapabilityLease> IssueLeaseAsync(
        DelegatedActor? holder = null,
        string? capability = null,
        string resource = ResourceId,
        TimeSpan? lifetime = null) =>
        await Leases.IssueAsync(Leases.Request(
            holder: LeaseHarness.HolderOf(holder ?? Leases.Agent),
            capability: capability ?? _capability,
            resources: [resource],
            lifetime: lifetime ?? TimeSpan.FromMinutes(30)));

    internal SdkInvocation Invocation(
        string text = "argument",
        CapabilityLeaseId? lease = null,
        Guid? approval = null,
        Guid? command = null)
    {
        var request = new SdkInvocation
        {
            InvocationId = InvocationId.New().ToWire(),
            CommandId = UuidBoundary.ToWire(command ?? Guid.NewGuid()),
            Capability = _capability,
            Context = new FrozenContext { ProfileVersion = "profile.7", PermissionsVersion = "permission.12" },
            Arguments = new CapabilityArguments
            {
                SchemaId = Registration.Descriptor.RequestSchema,
                Value = new StructuredValue { Text = text },
            },
            ExpectedRev = new WireRevision { Value = 7 },
        };
        if (lease is { } id)
        {
            request.LeaseId = UuidBoundary.ToWire(id.Value);
        }

        if (approval is { } approvalId)
        {
            request.ApprovalId = UuidBoundary.ToWire(approvalId);
        }

        return request;
    }

    internal ValueTask<InvocationOutcome> InvokeAsync(
        SdkInvocation invocation,
        InstanceIdentity? capturedTarget = null,
        CancellationToken cancellationToken = default) =>
        Pipeline.InvokeAsync(
            invocation,
            _action,
            AvailabilityContext,
            [Target],
            [ContextProvider],
            capturedTarget ?? Identity,
            cancellationToken: cancellationToken);

    /// <summary>The binding every world uses: the owner's operation written against the ticket, enforced by the gate.</summary>
    private CapabilityInvocationBinding<string, EnforcedOwnerResult> Binding() => new(
        Registry,
        _capability,
        InvocationResultVersionKind.Revision,
        arguments => arguments.Value.ValueCase == StructuredValue.ValueOneofCase.Text
            ? Outcome.Success(arguments.Value.Text)
            : Outcome.Failure<string>(TypedFailure.Create("validation.invalid_request")),
        Gate.Enforce<string, EnforcedOwnerResult>((ticket, _, _, _, _, _) =>
        {
            Log.Add("owner-op");
            _ = Interlocked.Increment(ref _ownerRuns);
            LastTicket = ticket;
            return ValueTask.FromResult(OwnerBehavior());
        }),
        result => Outcome.Success(new CapabilityResult
        {
            SchemaId = Registration.Descriptor.ResponseSchema,
            Value = new StructuredValue { Text = result.Text },
        }),
        result => InvocationResultVersion.FromRevision(result.Revision));

    private AvailabilityEvidenceRecord AvailabilityRow(AvailabilityProviderScope scope, DateTimeOffset asOf) => new(
        _action,
        _capability,
        AvailabilityTargetKey.ForProductInstance(Identity),
        new AvailabilityTargetFacts(
            AvailabilityFactState.Yes,
            AvailabilityFactState.Yes,
            AvailabilityFactState.Yes,
            AvailabilityFactState.Yes,
            AvailabilityFactState.Yes,
            "2.4.0",
            "target.generation.1",
            asOf.AddMinutes(-1)),
        new AvailabilityPermissionEvidence(
            scope.Owner,
            scope.PrincipalKey,
            _capability,
            AvailabilityPermissionDisposition.Granted,
            "scope:current-user",
            ["constraint.owner"],
            asOf.AddHours(-1),
            asOf.AddHours(1),
            "permission.generation.12"),
        new AvailabilityEntitlementEvidence(_capability, AvailabilityEntitlementDisposition.Satisfied, "entitlement.satisfied", "com05.version.7", "com06.generation.3"),
        new AvailabilityPolicyEvidence(AvailabilityPolicyDisposition.Enabled, "test.policy-source", "test.policy.revision.4"));
}
