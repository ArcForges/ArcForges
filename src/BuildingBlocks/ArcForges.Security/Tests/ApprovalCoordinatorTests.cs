// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Approvals;
using Xunit;

namespace ArcForges.Security.Tests;

public sealed class ApprovalCoordinatorTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(2);

    [Fact]
    public async Task PendingApprovalExpiresAtExactBoundaryAndCannotBeDecided()
    {
        var clock = new TestClock();
        var store = new MemoryApprovalStore();
        var coordinator = new ApprovalCoordinator(clock.Clock, store);
        var intent = Intent();

        var created = Value(await coordinator.RequestAsync(intent, Lifetime, TestContext.Current.CancellationToken));
        Assert.True(created.Applied);
        Assert.Equal(ApprovalState.Pending, created.Snapshot.State);
        Assert.Equal(clock.Clock.GetCurrentInstant(), created.Snapshot.RequestedAt);
        Assert.Equal(ApprovalCoordinator.MaximumLifetime, TimeSpan.FromMinutes(10));
        Assert.Equal("validation.invalid_request", Failure(await coordinator.RequestAsync(Intent(),
            ApprovalCoordinator.MaximumLifetime + TimeSpan.FromTicks(1), TestContext.Current.CancellationToken)));

        clock.Advance(Lifetime);
        var expired = Value(await coordinator.GetAsync(intent.ApprovalId, TestContext.Current.CancellationToken));
        Assert.Equal(ApprovalState.Expired, expired.State);
        Assert.Equal(expired.ExpiresAt, expired.ResolvedAt);

        var decision = Decision(intent.Owner, ApprovalDecisionKind.Approve);
        Assert.Equal("perm.approval_expired", Failure(await coordinator.DecideAsync(intent.ApprovalId, decision,
            TestContext.Current.CancellationToken)));
        Assert.Equal(ApprovalState.Expired, (await store.ReadAsync(intent.ApprovalId,
            TestContext.Current.CancellationToken))!.State);
    }

    [Fact]
    public async Task DuplicateRequestDoesNotExtendExpiryOrChangeTheActionBinding()
    {
        var clock = new TestClock();
        var store = new MemoryApprovalStore();
        var coordinator = new ApprovalCoordinator(clock.Clock, store);
        var intent = Intent();
        var first = Value(await coordinator.RequestAsync(intent, Lifetime, TestContext.Current.CancellationToken)).Snapshot;
        clock.Advance(TimeSpan.FromSeconds(30));

        var duplicate = Value(await coordinator.RequestAsync(intent, TimeSpan.FromMinutes(5), TestContext.Current.CancellationToken));
        Assert.False(duplicate.Applied);
        Assert.Equal(first.ExpiresAt, duplicate.Snapshot.ExpiresAt);
        Assert.Equal(first.RequestedAt, duplicate.Snapshot.RequestedAt);

        var changedEffect = new ApprovalIntent(intent.ApprovalId, intent.CommandId, intent.Owner,
            intent.OperationId, intent.TargetResourceId, intent.TargetRevision, new string('C', 64), intent.EffectiveRisk);
        Assert.Equal("validation.invalid_request", Failure(await coordinator.RequestAsync(changedEffect, Lifetime,
            TestContext.Current.CancellationToken)));
        Assert.Equal(first.EffectSha256, (await store.ReadAsync(intent.ApprovalId,
            TestContext.Current.CancellationToken))!.EffectSha256);
    }

    [Fact]
    public async Task SameDecisionIsIdempotentAndConflictingDuplicateCannotReplaceIt()
    {
        var clock = new TestClock();
        var store = new MemoryApprovalStore();
        var coordinator = new ApprovalCoordinator(clock.Clock, store);
        var intent = Intent();
        _ = Value(await coordinator.RequestAsync(intent, Lifetime, TestContext.Current.CancellationToken));
        var approve = Decision(intent.Owner, ApprovalDecisionKind.Approve);

        var applied = Value(await coordinator.DecideAsync(intent.ApprovalId, approve, TestContext.Current.CancellationToken));
        var duplicate = Value(await coordinator.DecideAsync(intent.ApprovalId, approve, TestContext.Current.CancellationToken));
        Assert.True(applied.Applied);
        Assert.False(duplicate.Applied);
        Assert.Equal(ApprovalState.Approved, duplicate.Snapshot.State);
        Assert.Equal(2, duplicate.Snapshot.Version);
        Assert.Equal(approve.DecidedBy, duplicate.Snapshot.Decision!.DecidedBy);
        Assert.Equal(approve.Device, duplicate.Snapshot.Decision.Device);
        Assert.Equal(ApprovalOrigin.Local, duplicate.Snapshot.Decision.Origin);
        Assert.Equal(clock.Clock.GetCurrentInstant(), duplicate.Snapshot.Decision.DecidedAt);
        Assert.Equal("reviewed exact action", duplicate.Snapshot.Decision.Reason);

        var conflicting = Decision(intent.Owner, ApprovalDecisionKind.Deny);
        Assert.Equal("perm.approval_required", Failure(await coordinator.DecideAsync(intent.ApprovalId, conflicting,
            TestContext.Current.CancellationToken)));
        Assert.Equal(approve.DecisionId, (await store.ReadAsync(intent.ApprovalId,
            TestContext.Current.CancellationToken))!.Decision!.DecisionId);
    }

    [Fact]
    public async Task ApprovalAfterCancellationIsRefusedAndCancellationReplayDoesNotChangeState()
    {
        var clock = new TestClock();
        var store = new MemoryApprovalStore();
        var coordinator = new ApprovalCoordinator(clock.Clock, store);
        var intent = Intent();
        _ = Value(await coordinator.RequestAsync(intent, Lifetime, TestContext.Current.CancellationToken));

        var cancelled = Value(await coordinator.CancelAsync(intent.ApprovalId, intent.Owner, TestContext.Current.CancellationToken));
        var duplicateCancel = Value(await coordinator.CancelAsync(intent.ApprovalId, intent.Owner, TestContext.Current.CancellationToken));
        Assert.True(cancelled.Applied);
        Assert.False(duplicateCancel.Applied);
        Assert.Equal(ApprovalState.Cancelled, duplicateCancel.Snapshot.State);
        Assert.Equal(intent.Owner, duplicateCancel.Snapshot.CancelledBy);

        Assert.Equal("perm.approval_required", Failure(await coordinator.DecideAsync(intent.ApprovalId,
            Decision(intent.Owner, ApprovalDecisionKind.Approve), TestContext.Current.CancellationToken)));
        Assert.Equal(ApprovalState.Cancelled, (await store.ReadAsync(intent.ApprovalId,
            TestContext.Current.CancellationToken))!.State);
    }

    [Fact]
    public async Task OnlyOriginalRequesterCanCancel()
    {
        var clock = new TestClock();
        var store = new MemoryApprovalStore();
        var coordinator = new ApprovalCoordinator(clock.Clock, store);
        var intent = Intent();
        _ = Value(await coordinator.RequestAsync(intent, Lifetime, TestContext.Current.CancellationToken));

        Assert.Equal("perm.capability_denied", Failure(await coordinator.CancelAsync(intent.ApprovalId, Principal(),
            TestContext.Current.CancellationToken)));
        Assert.Equal(ApprovalState.Pending, (await store.ReadAsync(intent.ApprovalId,
            TestContext.Current.CancellationToken))!.State);
    }

    [Fact]
    public async Task ConcurrentConflictingDecisionsHaveExactlyOneWinner()
    {
        var clock = new TestClock();
        var store = new MemoryApprovalStore();
        var coordinator = new ApprovalCoordinator(clock.Clock, store);
        var intent = Intent();
        _ = Value(await coordinator.RequestAsync(intent, Lifetime, TestContext.Current.CancellationToken));

        var outcomes = await Task.WhenAll(
            coordinator.DecideAsync(intent.ApprovalId, Decision(intent.Owner, ApprovalDecisionKind.Approve),
                TestContext.Current.CancellationToken).AsTask(),
            coordinator.DecideAsync(intent.ApprovalId, Decision(intent.Owner, ApprovalDecisionKind.Deny),
                TestContext.Current.CancellationToken).AsTask());

        Assert.Single(outcomes, outcome => outcome.TryGetValue(out var value) && value.Applied);
        var final = (await store.ReadAsync(intent.ApprovalId, TestContext.Current.CancellationToken))!;
        Assert.Contains(final.State, new[] { ApprovalState.Approved, ApprovalState.Denied });
        Assert.Equal(2, final.Version);
    }

    [Fact]
    public async Task ApprovalStoreContractUsesInsertAndVersionCompareAndSwap()
    {
        var clock = new TestClock();
        var store = new MemoryApprovalStore();
        var intent = Intent();
        var requestedAt = clock.Clock.GetCurrentInstant();
        var expiresAt = new Instant(requestedAt.UnixSeconds + 60, requestedAt.Nanoseconds);
        var pending = new ApprovalSnapshot(intent.ApprovalId, intent.CommandId, intent.Owner,
            intent.OperationId, intent.TargetResourceId, intent.TargetRevision, intent.EffectSha256,
            intent.EffectiveRisk, requestedAt, expiresAt, ApprovalState.Pending, version: 1);

        Assert.True(await ((IApprovalStore)store).TryCreatePendingAsync(pending, TestContext.Current.CancellationToken));
        Assert.False(await ((IApprovalStore)store).TryCreatePendingAsync(pending, TestContext.Current.CancellationToken));

        var decision = new ApprovalDecision(Guid.NewGuid(), ApprovalDecisionKind.Approve, intent.Owner,
            new DeviceId(Guid.NewGuid()), ApprovalOrigin.Local, requestedAt, "exact action checked");
        var approved = new ApprovalSnapshot(intent.ApprovalId, intent.CommandId, intent.Owner,
            intent.OperationId, intent.TargetResourceId, intent.TargetRevision, intent.EffectSha256,
            intent.EffectiveRisk, requestedAt, expiresAt, ApprovalState.Approved, version: 2,
            resolvedAt: requestedAt, decision: decision);

        Assert.True(await ((IApprovalStore)store).TryResolveAsync(intent.ApprovalId, expectedVersion: 1, resolved: approved,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await ((IApprovalStore)store).TryResolveAsync(intent.ApprovalId, expectedVersion: 1, resolved: approved,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(ApprovalState.Approved, (await ((IApprovalStore)store).ReadAsync(intent.ApprovalId,
            TestContext.Current.CancellationToken))!.State);
    }

    private static ApprovalIntent Intent() => new(Guid.NewGuid(), new CommandId(Guid.NewGuid()), Principal(),
        "account.security.change-email", "account/email", "revision:7", new string('A', 64), RiskLevel.R3);

    private static ApprovalDecisionRequest Decision(HumanPrincipal actor, ApprovalDecisionKind kind) =>
        new(Guid.NewGuid(), kind, actor, new DeviceId(Guid.NewGuid()), ApprovalOrigin.Local, "reviewed exact action");

    private static HumanPrincipal Principal() => new(new RealmId(Guid.NewGuid()),
        new UserId(Guid.NewGuid()), HumanIdentityKind.LocalHuman);

    private static T Value<T>(Outcome<T> outcome)
    {
        Assert.True(outcome.TryGetValue(out var value), outcome.TryGetFailure(out var failure) ? failure!.Code : "Expected a successful outcome.");
        return value!;
    }

    private static string Failure<T>(Outcome<T> outcome)
    {
        Assert.True(outcome.TryGetFailure(out var failure), "Expected a refusal outcome.");
        return failure!.Code;
    }

    internal sealed class MemoryApprovalStore : IApprovalStore
    {
        private readonly Dictionary<Guid, ApprovalSnapshot> entries = [];
        private readonly object gate = new();

        public ValueTask<ApprovalSnapshot?> ReadAsync(Guid approvalId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate)
            {
                entries.TryGetValue(approvalId, out var snapshot);
                return ValueTask.FromResult(snapshot);
            }
        }

        public ValueTask<bool> TryCreatePendingAsync(ApprovalSnapshot snapshot, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (snapshot.State != ApprovalState.Pending || snapshot.Version != 1 || entries.ContainsKey(snapshot.ApprovalId))
                {
                    return ValueTask.FromResult(false);
                }

                entries.Add(snapshot.ApprovalId, snapshot);
                return ValueTask.FromResult(true);
            }
        }

        public ValueTask<bool> TryResolveAsync(Guid approvalId, long expectedVersion, ApprovalSnapshot resolved,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (!entries.TryGetValue(approvalId, out var current) || current.State != ApprovalState.Pending ||
                    current.Version != expectedVersion || resolved.Version != expectedVersion + 1 ||
                    resolved.ApprovalId != approvalId || resolved.State is not (ApprovalState.Approved or
                        ApprovalState.Denied or ApprovalState.Cancelled or ApprovalState.Expired) ||
                    current.CommandId != resolved.CommandId || current.Owner != resolved.Owner ||
                    current.OperationId != resolved.OperationId || current.TargetResourceId != resolved.TargetResourceId ||
                    current.TargetRevision != resolved.TargetRevision || current.EffectSha256 != resolved.EffectSha256 ||
                    current.EffectiveRisk != resolved.EffectiveRisk || current.RequestedAt != resolved.RequestedAt ||
                    current.ExpiresAt != resolved.ExpiresAt)
                {
                    return ValueTask.FromResult(false);
                }

                entries[approvalId] = resolved;
                return ValueTask.FromResult(true);
            }
        }
    }

    private sealed class TestClock
    {
        private readonly ManualTimeProvider provider = new();

        internal TestClock() => Clock = new Clock(provider);

        internal Clock Clock { get; }

        internal void Advance(TimeSpan duration) => provider.Advance(duration);
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset now = new(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
        private long timestamp;

        public override DateTimeOffset GetUtcNow() => now;
        public override long GetTimestamp() => timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        internal void Advance(TimeSpan duration)
        {
            now += duration;
            timestamp = checked(timestamp + duration.Ticks);
        }
    }
}
