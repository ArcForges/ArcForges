// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Security.Decisions;
using ArcForges.Security.Leases;
using Xunit;
using Instant = ArcForges.Foundation.Instant;

namespace ArcForges.Security.Tests;

/// <summary>
/// An in-memory lease store with the contract of a durable one: insert-if-absent, compare-and-swap on the version, and only forward
/// transitions. It throws on a replacement a correct manager never makes, so a manager that tries to widen, extend or revive a lease
/// fails the test that did it. Failures can be injected per operation.
/// </summary>
internal sealed class MemoryLeaseStore : ILeaseStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<CapabilityLeaseId, CapabilityLease> _leases = [];

    internal bool FailReads { get; set; }

    internal bool FailCreates { get; set; }

    internal bool FailReplaces { get; set; }

    /// <summary>Makes every replacement lose its compare-and-swap, as if a competing writer always won.</summary>
    internal bool ConflictReplaces { get; set; }

    internal int Reads { get; private set; }

    internal int Replaces { get; private set; }

    internal IReadOnlyList<CapabilityLease> All
    {
        get
        {
            lock (_gate)
            {
                return [.. _leases.Values];
            }
        }
    }

    internal CapabilityLease? Peek(CapabilityLeaseId id)
    {
        lock (_gate)
        {
            return _leases.GetValueOrDefault(id);
        }
    }

    /// <summary>Stores a snapshot as is, bypassing every rule (for arranging a state a test needs).</summary>
    internal void Seed(CapabilityLease lease)
    {
        lock (_gate)
        {
            _leases[lease.Id] = lease;
        }
    }

    public ValueTask<CapabilityLease?> ReadAsync(CapabilityLeaseId id, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            Reads++;
            if (FailReads)
            {
                throw new InvalidOperationException("lease store offline");
            }

            return ValueTask.FromResult(_leases.GetValueOrDefault(id));
        }
    }

    public ValueTask<bool> TryCreateAsync(CapabilityLease lease, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (FailCreates)
            {
                throw new InvalidOperationException("lease store offline");
            }

            Assert.Equal(LeaseState.Active, lease.State);
            Assert.Equal(1, lease.Version);
            return ValueTask.FromResult(_leases.TryAdd(lease.Id, lease));
        }
    }

    public ValueTask<bool> TryReplaceAsync(CapabilityLeaseId id, long expectedVersion, CapabilityLease replacement, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (FailReplaces)
            {
                throw new InvalidOperationException("lease store offline");
            }

            if (ConflictReplaces || !_leases.TryGetValue(id, out var current) || current.Version != expectedVersion)
            {
                return ValueTask.FromResult(false);
            }

            AssertLegal(current, replacement);
            _leases[id] = replacement;
            Replaces++;
            return ValueTask.FromResult(true);
        }
    }

    public ValueTask<IReadOnlyList<CapabilityLease>> ListUnsettledAsync(TaskId? task, Instant? dueAt, int limit, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            IReadOnlyList<CapabilityLease> result =
            [
                .. _leases.Values
                    .Where(lease => task is null || lease.Task == task)
                    .Where(lease => lease.State == LeaseState.Active
                        ? dueAt is null || lease.ExpiresAt <= dueAt
                        : !lease.EndEventRecorded)
                    .OrderBy(lease => lease.IssuedAt.UnixSeconds).ThenBy(lease => lease.Id.Value)
                    .Take(limit),
            ];
            return ValueTask.FromResult(result);
        }
    }

    internal static void AssertLegal(CapabilityLease current, CapabilityLease replacement)
    {
        Assert.Equal(current.Version + 1, replacement.Version);
        Assert.Equal(current.Id, replacement.Id);
        Assert.Equal(current.Owner, replacement.Owner);
        Assert.Equal(current.Scope, replacement.Scope);
        Assert.Equal(current.Task, replacement.Task);
        Assert.Equal(current.Holder, replacement.Holder);
        Assert.Equal(current.CapabilityKey, replacement.CapabilityKey);
        Assert.Equal(current.ResourceIds, replacement.ResourceIds);
        Assert.Equal(current.EffectiveRisk, replacement.EffectiveRisk);
        Assert.Equal(current.Origin, replacement.Origin);
        Assert.Equal(current.Basis, replacement.Basis);
        Assert.Same(current.IssuedBy, replacement.IssuedBy);
        Assert.Equal(current.IssuedAt, replacement.IssuedAt);
        Assert.Equal(current.ExpiresAt, replacement.ExpiresAt);
        if (current.State == LeaseState.Active)
        {
            Assert.NotEqual(LeaseState.Active, replacement.State);
            Assert.False(replacement.EndEventRecorded);
        }
        else
        {
            Assert.Equal(current.State, replacement.State);
            Assert.False(current.EndEventRecorded);
            Assert.True(replacement.EndEventRecorded);
            Assert.Equal(current.EndedAt, replacement.EndedAt);
            Assert.Equal(current.RevocationReason, replacement.RevocationReason);
        }
    }
}

/// <summary>The sink of lifecycle facts a test controls. It records every fact written and can fail or block.</summary>
internal sealed class RecordingLeaseSink : ILeaseEventSink
{
    private readonly Lock _gate = new();
    private readonly List<CapabilityLeaseEvent> _events = [];

    internal bool Fail { get; set; }

    internal Func<CapabilityLeaseEvent, CancellationToken, ValueTask>? Behavior { get; set; }

    internal IReadOnlyList<CapabilityLeaseEvent> Events
    {
        get
        {
            lock (_gate)
            {
                return [.. _events];
            }
        }
    }

    internal IReadOnlyList<LeaseEventKind> Kinds => [.. Events.Select(item => item.Kind)];

    public async ValueTask WriteAsync(CapabilityLeaseEvent leaseEvent, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Fail)
        {
            throw new InvalidOperationException("audit offline");
        }

        if (Behavior is { } behavior)
        {
            await behavior(leaseEvent, cancellationToken).ConfigureAwait(false);
        }

        lock (_gate)
        {
            _events.Add(leaseEvent);
        }
    }
}

/// <summary>The delegator's own permission, which bounds every lease. By default a grant that lasts from an hour ago to two hours ahead.</summary>
internal sealed class FakeCeilings(DecisionClock clock) : ILeaseCeilingSource
{
    internal int Calls { get; private set; }

    internal Func<string, string, string, PermissionGrantRecord?>? Override { get; set; }

    internal PermissionGrantState State { get; set; } = PermissionGrantState.Granted;

    internal IReadOnlyList<string> Constraints { get; set; } = [];

    internal TimeSpan From { get; set; } = TimeSpan.FromHours(-1);

    internal TimeSpan Until { get; set; } = TimeSpan.FromHours(2);

    public ValueTask<PermissionGrantRecord?> FindAsync(string principalKey, string capabilityKey, string scopeKey, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        if (Override is { } custom)
        {
            return ValueTask.FromResult(custom(principalKey, capabilityKey, scopeKey));
        }

        return ValueTask.FromResult<PermissionGrantRecord?>(new PermissionGrantRecord(
            "owner.test", principalKey, capabilityKey, scopeKey, State, Constraints, clock.UtcNow + From, clock.UtcNow + Until, "generation-1"));
    }
}

/// <summary>A delegator, a delegated extension and everything needed to issue and use one lease.</summary>
internal sealed class LeaseHarness
{
    internal const string Capability = DecisionHarness.DefaultCapability;
    internal const string ResourceId = "resource/42";

    internal LeaseHarness(LeaseOptions? options = null, DecisionClock? clock = null)
    {
        Clock = clock ?? new DecisionClock();
        Owner = new HumanPrincipal(new RealmId(Guid.NewGuid()), new UserId(Guid.NewGuid()), HumanIdentityKind.CloudUser);
        Scope = new DecisionScope(Owner.Realm, new WorkspaceId(Guid.NewGuid()));
        Device = new DeviceId(Guid.NewGuid());
        Installation = new InstallationId(Guid.NewGuid());
        Caller = new InstanceId(Guid.NewGuid());
        Task = TaskId.New();
        Extension = new DelegatedActor(ActorKind.Extension, Guid.NewGuid(), new InstanceId(Guid.NewGuid()), "owned.extension/1");
        Agent = new DelegatedActor(ActorKind.Agent, Guid.NewGuid(), new InstanceId(Guid.NewGuid()), "owned.agent/1");
        Ceilings = new FakeCeilings(Clock);
        Manager = new CapabilityLeaseManager(Clock.Clock, Store, Sink, Ceilings, options);
    }

    internal DecisionClock Clock { get; }

    internal MemoryLeaseStore Store { get; } = new();

    internal RecordingLeaseSink Sink { get; } = new();

    internal FakeCeilings Ceilings { get; }

    internal CapabilityLeaseManager Manager { get; }

    internal HumanPrincipal Owner { get; }

    internal DecisionScope Scope { get; }

    internal DeviceId Device { get; }

    internal InstallationId Installation { get; }

    internal InstanceId Caller { get; }

    internal TaskId Task { get; }

    internal DelegatedActor Extension { get; }

    internal DelegatedActor Agent { get; }

    internal Instant Now => DecisionHarness.InstantOf(Clock.UtcNow);

    internal ActorChain DirectChain() => new(Owner, Device, Installation, SessionId.New(), Caller, []);

    internal ActorChain ChainOf(params DelegatedActor[] actors) => new(Owner, Device, Installation, SessionId.New(), Caller, actors);

    internal static LeaseHolder HolderOf(DelegatedActor actor) => new(actor.Kind, actor.ActorId);

    /// <summary>The same lease as a later snapshot in a terminal state, built through the public constructor.</summary>
    internal static CapabilityLease Ended(CapabilityLease lease, LeaseState state, Instant endedAt, LeaseRevocationReason reason = LeaseRevocationReason.None, bool recorded = false) => new(
        lease.Id, lease.Owner, lease.Scope, lease.Task, lease.Holder, lease.CapabilityKey, lease.ResourceIds, lease.EffectiveRisk, lease.Origin,
        lease.Basis, lease.IssuedBy, lease.IssuedAt, lease.ExpiresAt, state, lease.Version + 1, endedAt, reason, recorded);

    internal static DelegatedActor Actor(ActorKind kind) => new(kind, Guid.NewGuid(), new InstanceId(Guid.NewGuid()), "owned.software/1");

    internal LeaseRequest Request(
        ActorChain? issuedBy = null,
        DecisionScope? scope = null,
        TaskId? task = null,
        LeaseHolder? holder = null,
        string capability = Capability,
        IEnumerable<string>? resources = null,
        DecisionOrigin origin = DecisionOrigin.Local,
        TimeSpan? lifetime = null,
        RiskLevel risk = RiskLevel.R1,
        LeaseIssueBasis basis = LeaseIssueBasis.UserApproved) => new(
        issuedBy ?? DirectChain(),
        scope ?? Scope,
        task ?? Task,
        holder ?? HolderOf(Extension),
        capability,
        resources ?? [ResourceId],
        risk,
        origin,
        basis,
        lifetime ?? TimeSpan.FromMinutes(30));

    internal async Task<CapabilityLease> IssueAsync(LeaseRequest? request = null)
    {
        var result = await Manager.IssueAsync(request ?? Request(), TestContext.Current.CancellationToken);
        Assert.True(result.Issued, result.Refusal.ToString());
        return result.Lease!;
    }

    /// <summary>The use of a lease by the extension this harness delegated to, on the harness resource.</summary>
    internal LeaseUse Use(CapabilityLease lease, DelegatedActor? actor = null, string? capability = null, string? resource = null, DecisionScope? scope = null, HumanPrincipal? owner = null) => new(
        lease.Id,
        owner ?? Owner,
        scope ?? Scope,
        HolderOf(actor ?? Extension),
        capability ?? Capability,
        resource ?? ResourceId);

    internal ValueTask<LeaseUseVerdict> ValidateAsync(LeaseUse use) => Manager.ValidateAsync(use, TestContext.Current.CancellationToken);
}
