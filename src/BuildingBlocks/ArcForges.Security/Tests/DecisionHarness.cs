// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;
using ArcForges.Security.Approvals;
using ArcForges.Security.Decisions;
using Xunit;
using Instant = ArcForges.Foundation.Instant;

namespace ArcForges.Security.Tests;

/// <summary>A deterministic clock whose wall and monotonic sources move independently.</summary>
internal sealed class DecisionClock
{
    private readonly ManualTimeProvider _provider = new();

    internal DecisionClock() => Clock = new Clock(_provider);

    internal Clock Clock { get; }

    internal DateTimeOffset UtcNow => _provider.GetUtcNow();

    /// <summary>Moves both the wall clock and the monotonic clock.</summary>
    internal void Advance(TimeSpan duration) => _provider.Advance(duration, duration);

    /// <summary>Moves only the wall clock (an administrator or a sync step), forward or back.</summary>
    internal void StepWallClock(TimeSpan duration) => _provider.Advance(duration, TimeSpan.Zero);

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
        private long _timestamp;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override DateTimeOffset GetUtcNow() => _now;

        public override long GetTimestamp() => _timestamp;

        internal void Advance(TimeSpan wall, TimeSpan monotonic)
        {
            _now += wall;
            _timestamp = checked(_timestamp + monotonic.Ticks);
        }
    }
}

/// <summary>An ordered, thread-safe record of which source was consulted when.</summary>
internal sealed class CallLog
{
    private readonly ConcurrentQueue<string> _entries = new();

    internal void Add(string entry) => _entries.Enqueue(entry);

    internal IReadOnlyList<string> Entries => [.. _entries];

    internal int Count(string entry) => _entries.Count(item => item == entry);
}

internal sealed class FakeCatalogue(CallLog log) : ICapabilityCatalogue
{
    internal Func<string, CancellationToken, ValueTask<CapabilityDescriptor?>> Behavior { get; set; } = (_, _) => throw new InvalidOperationException();

    public ValueTask<CapabilityDescriptor?> FindAsync(string capabilityKey, CancellationToken cancellationToken)
    {
        log.Add("catalogue");
        return Behavior(capabilityKey, cancellationToken);
    }
}

internal sealed class FakePolicy(CallLog log) : IProductPolicy
{
    internal Func<DecisionRequest, CancellationToken, ValueTask<PolicyVerdict>> Behavior { get; set; } = (_, _) => ValueTask.FromResult(PolicyVerdict.Enabled);

    public ValueTask<PolicyVerdict> EvaluateAsync(DecisionRequest request, CancellationToken cancellationToken)
    {
        log.Add("policy");
        return Behavior(request, cancellationToken);
    }
}

internal sealed class FakeIdentity(CallLog log) : IActorIdentityVerifier
{
    internal Func<DecisionRequest, CancellationToken, ValueTask<ActorIdentityVerdict>> Behavior { get; set; } = (_, _) => ValueTask.FromResult(ActorIdentityVerdict.Authenticated);

    public ValueTask<ActorIdentityVerdict> VerifyAsync(DecisionRequest request, CancellationToken cancellationToken)
    {
        log.Add("identity");
        return Behavior(request, cancellationToken);
    }
}

internal sealed class FakeScope(CallLog log) : IScopeAuthority
{
    internal Func<DecisionRequest, CancellationToken, ValueTask<ScopeVerdict>> Behavior { get; set; } = (_, _) => ValueTask.FromResult(ScopeVerdict.Valid);

    public ValueTask<ScopeVerdict> ValidateAsync(DecisionRequest request, CancellationToken cancellationToken)
    {
        log.Add("scope");
        return Behavior(request, cancellationToken);
    }
}

internal sealed class FakeTrust(CallLog log) : ITrustEvaluator
{
    internal TransportBinding? LastBinding { get; private set; }

    internal Func<DecisionRequest, CancellationToken, ValueTask<TrustVerdict>> Behavior { get; set; } = (_, _) => ValueTask.FromResult(TrustVerdict.Verified);

    public ValueTask<TrustVerdict> EvaluateAsync(DecisionRequest request, TransportBinding? transport, CancellationToken cancellationToken)
    {
        log.Add("trust");
        LastBinding = transport;
        return Behavior(request, cancellationToken);
    }
}

internal sealed class FakePermissions(CallLog log) : IPermissionSource
{
    internal Func<DecisionRequest, CancellationToken, ValueTask<PermissionGrantRecord?>> Behavior { get; set; } = (_, _) => ValueTask.FromResult<PermissionGrantRecord?>(null);

    public ValueTask<PermissionGrantRecord?> FindAsync(DecisionRequest request, CancellationToken cancellationToken)
    {
        log.Add("permission");
        return Behavior(request, cancellationToken);
    }
}

internal sealed class FakeResources(CallLog log) : IResourceAuthorizer
{
    internal Func<DecisionRequest, CancellationToken, ValueTask<ResourceVerdict?>> Behavior { get; set; } =
        (_, _) => ValueTask.FromResult<ResourceVerdict?>(new ResourceVerdict(ResourceDisposition.Authorized, RiskFacts.None));

    public ValueTask<ResourceVerdict?> AuthorizeAsync(DecisionRequest request, CancellationToken cancellationToken)
    {
        log.Add("resource");
        return Behavior(request, cancellationToken);
    }
}

internal sealed class FakeDataBoundary(CallLog log) : IDataBoundaryAuthorizer
{
    internal string? LastDestination { get; private set; }

    internal Func<DecisionRequest, CancellationToken, ValueTask<BoundaryVerdict>> SecretBehavior { get; set; } = (_, _) => ValueTask.FromResult(BoundaryVerdict.Allowed);

    internal Func<DecisionRequest, string, CancellationToken, ValueTask<BoundaryVerdict>> EgressBehavior { get; set; } = (_, _, _) => ValueTask.FromResult(BoundaryVerdict.Allowed);

    public ValueTask<BoundaryVerdict> AuthorizeSecretUseAsync(DecisionRequest request, CancellationToken cancellationToken)
    {
        log.Add("secret");
        return SecretBehavior(request, cancellationToken);
    }

    public ValueTask<BoundaryVerdict> AuthorizeEgressAsync(DecisionRequest request, string destination, CancellationToken cancellationToken)
    {
        log.Add("egress");
        LastDestination = destination;
        return EgressBehavior(request, destination, cancellationToken);
    }
}

internal sealed class FakeOwnerValidator(CallLog log) : IOwnerValidator
{
    internal OwnerValidationRequest? Last { get; private set; }

    internal Func<OwnerValidationRequest, CancellationToken, ValueTask<OwnerVerdict>> Behavior { get; set; } = (_, _) => ValueTask.FromResult(OwnerVerdict.Valid);

    public ValueTask<OwnerVerdict> ValidateAsync(OwnerValidationRequest request, CancellationToken cancellationToken)
    {
        log.Add("owner");
        Last = request;
        return Behavior(request, cancellationToken);
    }
}

internal sealed class FakeRecorder(CallLog log) : IDecisionRecorder
{
    private readonly ConcurrentQueue<DecisionRecord> _records = new();

    internal IReadOnlyList<DecisionRecord> Records => [.. _records];

    internal Func<DecisionRecord, CancellationToken, ValueTask> Behavior { get; set; } = (_, _) => ValueTask.CompletedTask;

    public ValueTask RecordAsync(DecisionRecord record, CancellationToken cancellationToken)
    {
        log.Add("record");
        _records.Enqueue(record);
        return Behavior(record, cancellationToken);
    }
}

internal sealed class FakeAudit(CallLog log) : ISecurityAuditSink
{
    private readonly ConcurrentQueue<SecurityAuditRecord> _records = new();

    internal IReadOnlyList<SecurityAuditRecord> Records => [.. _records];

    internal Func<SecurityAuditRecord, CancellationToken, ValueTask> Behavior { get; set; } = (_, _) => ValueTask.CompletedTask;

    public ValueTask WriteAsync(SecurityAuditRecord record, CancellationToken cancellationToken)
    {
        log.Add("audit");
        _records.Enqueue(record);
        return Behavior(record, cancellationToken);
    }
}

internal sealed class FakeAuthenticator(Clock clock) : IStepUpAuthenticator
{
    public ValueTask<StepUpAuthentication?> AuthenticateAsync(StepUpChallenge challenge, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<StepUpAuthentication?>(new StepUpAuthentication(
            challenge.Subject, StepUpAuthenticationMethod.FreshPasskey, clock.GetCurrentInstant()));
}

internal sealed class FakePresence : ILocalPresenceVerifier
{
    internal bool Confirmed { get; set; } = true;

    public ValueTask<bool> ConfirmLocalPresenceAsync(StepUpChallenge challenge, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(Confirmed);
}

/// <summary>A transport session whose answer a test controls.</summary>
internal sealed class FakeTransport(CallLog log, TransportKind kind = TransportKind.InProcess) : ITransportSession
{
    internal TransportKind KindValue { get; set; } = kind;

    internal Func<CancellationToken, ValueTask<TransportVerdict>> Behavior { get; set; } =
        _ => ValueTask.FromResult(new TransportVerdict(TransportRefusal.None, new TransportBinding(TransportKind.InProcess, TransportAssurance.InProcessHost)));

    public TransportKind Kind => KindValue;

    public ValueTask<TransportVerdict> VerifyCurrentAsync(CancellationToken cancellationToken)
    {
        log.Add("transport");
        return Behavior(cancellationToken);
    }
}

/// <summary>The owner's operation: counts its calls and keeps the ticket it was given.</summary>
internal sealed class FakeOwnerOperation(CallLog log)
{
    private int _calls;

    internal int Calls => Volatile.Read(ref _calls);

    internal AuthorizedExecution? LastTicket { get; private set; }

    internal Func<AuthorizedExecution, CancellationToken, ValueTask<Outcome<string>>> Behavior { get; set; } =
        (_, _) => ValueTask.FromResult(Outcome.Success("done"));

    internal OwnerOperation<string> Operation => (ticket, token) =>
    {
        log.Add("owner-op");
        Interlocked.Increment(ref _calls);
        LastTicket = ticket;
        return Behavior(ticket, token);
    };
}

/// <summary>Everything a pipeline test needs: all sources and sinks as controllable fakes, real approval and step-up coordinators.</summary>
internal sealed class DecisionHarness
{
    internal const string DefaultCapability = "test.capability.read";

    internal DecisionHarness(string risk = "R1", string approval = "none", string egress = "none")
    {
        Descriptor = Describe(DefaultCapability, risk, approval, egress);
        Catalogue = new FakeCatalogue(Log) { Behavior = (_, _) => ValueTask.FromResult<CapabilityDescriptor?>(Descriptor) };
        Policy = new FakePolicy(Log);
        Identity = new FakeIdentity(Log);
        Scope = new FakeScope(Log);
        Trust = new FakeTrust(Log);
        Permissions = new FakePermissions(Log) { Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(Grant(request)) };
        Resources = new FakeResources(Log);
        DataBoundary = new FakeDataBoundary(Log);
        Owner = new FakeOwnerValidator(Log);
        Recorder = new FakeRecorder(Log);
        Audit = new FakeAudit(Log);
        Transport = new FakeTransport(Log);
        OwnerOperation = new FakeOwnerOperation(Log);
        Authenticator = new FakeAuthenticator(Clock.Clock);
        Presence = new FakePresence();
        ApprovalStore = new ApprovalCoordinatorTests.MemoryApprovalStore();
        Approvals = new ApprovalCoordinator(Clock.Clock, ApprovalStore);
        StepUp = new StepUpCoordinator(Clock.Clock, Authenticator, Presence);
    }

    internal DecisionClock Clock { get; } = new();

    internal CallLog Log { get; } = new();

    internal CapabilityDescriptor Descriptor { get; set; }

    internal FakeCatalogue Catalogue { get; }

    internal FakePolicy Policy { get; }

    internal FakeIdentity Identity { get; }

    internal FakeScope Scope { get; }

    internal FakeTrust Trust { get; }

    internal FakePermissions Permissions { get; }

    internal FakeResources Resources { get; }

    internal FakeDataBoundary DataBoundary { get; }

    internal FakeOwnerValidator Owner { get; }

    internal FakeRecorder Recorder { get; }

    internal FakeAudit Audit { get; }

    internal FakeTransport Transport { get; }

    internal FakeOwnerOperation OwnerOperation { get; }

    internal FakeAuthenticator Authenticator { get; }

    internal FakePresence Presence { get; }

    internal ApprovalCoordinatorTests.MemoryApprovalStore ApprovalStore { get; }

    internal ApprovalCoordinator Approvals { get; }

    internal StepUpCoordinator StepUp { get; }

    internal DecisionPipelineServices Services() => new(
        Clock.Clock, Catalogue, Policy, Identity, Scope, Trust, Permissions, Resources, DataBoundary,
        Approvals, StepUp, Owner, Recorder, Audit);

    internal SecurityDecisionPipeline Pipeline(DecisionPipelineOptions? options = null) => new(Services(), options);

    internal RequestBuilder Request() => new(this);

    internal static CapabilityDescriptor Describe(string key, string risk, string approval, string egress) => new()
    {
        Key = key,
        Version = "1",
        Risk = risk,
        Approval = approval,
        Egress = egress,
    };

    internal PermissionGrantRecord Grant(
        DecisionRequest request,
        PermissionGrantState state = PermissionGrantState.Granted,
        IEnumerable<string>? constraints = null,
        TimeSpan? validFromOffset = null,
        TimeSpan? validUntilOffset = null) =>
        new(
            "owner.test",
            request.PrincipalKey,
            request.CapabilityKey,
            request.ScopeKey,
            state,
            constraints ?? [],
            Clock.UtcNow + (validFromOffset ?? TimeSpan.FromHours(-1)),
            Clock.UtcNow + (validUntilOffset ?? TimeSpan.FromHours(1)),
            "generation-1");

    internal static ActorChain Chain(params ActorKind[] kinds) => new(
        new HumanPrincipal(new RealmId(Guid.NewGuid()), new UserId(Guid.NewGuid()), HumanIdentityKind.CloudUser),
        new DeviceId(Guid.NewGuid()),
        new InstallationId(Guid.NewGuid()),
        SessionId.New(),
        new InstanceId(Guid.NewGuid()),
        kinds.Select(kind => new DelegatedActor(kind, Guid.NewGuid(), new InstanceId(Guid.NewGuid()), "owned.software/1")));

    internal static string Sha(char digit = 'A') => new(digit, 64);

    /// <summary>Approves a request exactly as presented and returns the approval identity.</summary>
    internal async Task<Guid> ApproveAsync(
        DecisionRequest request,
        RiskLevel risk,
        ApprovalOrigin origin = ApprovalOrigin.Local,
        TimeSpan? lifetime = null,
        HumanPrincipal? decidedBy = null)
    {
        var intent = new ApprovalIntent(
            Guid.NewGuid(), request.CommandId, request.Actors.Owner, request.CapabilityKey, request.Resource.Id,
            request.Resource.Revision, request.EffectSha256, risk);
        _ = Value(await Approvals.RequestAsync(intent, lifetime ?? TimeSpan.FromMinutes(5), TestContext.Current.CancellationToken));
        _ = Value(await Approvals.DecideAsync(
            intent.ApprovalId,
            new ApprovalDecisionRequest(Guid.NewGuid(), ApprovalDecisionKind.Approve, decidedBy ?? request.Actors.Owner, request.Actors.Device, origin, "reviewed"),
            TestContext.Current.CancellationToken));
        return intent.ApprovalId;
    }

    /// <summary>Completes a step-up for the request's owner, command and operation at the risk the descriptor and facts give.</summary>
    internal async Task<StepUpProof> ProofAsync(DecisionRequest request, SensitiveOperation operation, RiskLevel assessed)
    {
        var assessment = AssessmentOf(assessed);
        var challenge = StepUp.CreateChallenge(request.Actors.Owner, request.CommandId, operation, assessment, TimeSpan.FromMinutes(2));
        return Value(await StepUp.CompleteAsync(challenge, TestContext.Current.CancellationToken));
    }

    internal static RiskAssessment AssessmentOf(RiskLevel level) => RiskModel.Assess(
        Describe("assessment.helper", level.ToString(), "none", "none"),
        new RiskContext(RiskScope.SingleOperation, RiskTarget.Ordinary, RiskReversibility.Reversible, RiskEgress.None, ActorKind.None, false, true, false));

    internal static T Value<T>(Outcome<T> outcome)
    {
        Assert.True(outcome.TryGetValue(out var value), outcome.TryGetFailure(out var failure) ? failure!.Code : "Expected success.");
        return value!;
    }

    internal static string FailureCode<T>(Outcome<T> outcome)
    {
        Assert.True(outcome.TryGetFailure(out var failure), "Expected a failure.");
        return failure!.Code;
    }

    internal static Instant InstantOf(DateTimeOffset value) => Instant.FromDateTimeOffset(value);
}

/// <summary>Builds one request with defaults that pass every step of a read-only capability.</summary>
internal sealed class RequestBuilder
{
    private readonly DecisionHarness _harness;

    internal RequestBuilder(DecisionHarness harness)
    {
        _harness = harness;
        Actors = DecisionHarness.Chain();
        Scope = new DecisionScope(Actors.Owner.Realm, new WorkspaceId(Guid.NewGuid()));
        Transport = harness.Transport;
    }

    internal ActorChain Actors { get; set; }

    internal string Capability { get; set; } = DecisionHarness.DefaultCapability;

    internal DecisionScope Scope { get; set; }

    internal CommandId CommandId { get; set; } = new(Guid.NewGuid());

    internal ResourceReference Resource { get; set; } = new("resource/42", "revision:7");

    internal string Effect { get; set; } = DecisionHarness.Sha();

    internal DecisionOrigin Origin { get; set; } = DecisionOrigin.Local;

    internal ITransportSession Transport { get; set; }

    internal RiskFacts? Facts { get; set; }

    internal string? EgressDestination { get; set; }

    internal string? SecretUseKey { get; set; }

    internal Guid? ApprovalId { get; set; }

    internal StepUpProof? Proof { get; set; }

    internal SensitiveOperation Operation { get; set; }

    internal RequestBuilder WithActors(params ActorKind[] kinds)
    {
        Actors = DecisionHarness.Chain(kinds);
        Scope = new DecisionScope(Actors.Owner.Realm, Scope.Workspace);
        return this;
    }

    internal DecisionRequest Build() => new(
        Actors, Capability, Scope, CommandId, Resource, Effect, Origin, Transport, Facts, EgressDestination,
        SecretUseKey, ApprovalId, Proof, Operation);

    public static implicit operator DecisionRequest(RequestBuilder builder) => builder.Build();
}
