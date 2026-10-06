// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Security.Audit;
using ArcForges.Security.Decisions;
using ArcForges.Security.Egress;
using ArcForges.Security.Leases;
using ArcForges.Foundation.Errors;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>Component composition over an actual audit file; host permission facts and the lease store remain explicit fixtures.</summary>
public sealed class CapabilityAuditCompositionTests
{
    [Fact]
    public async Task EgressAndEveryLeaseLifecycleUseOneDurableOwnerAuditStore()
    {
        var h = new EgressHarness();
        var request = h.Request();
        using var fixture = new CompositionStore(request.Actors);
        var authority = new EgressAuthority(h.Decisions.Clock.Clock, h.Classifier, h.Allowlist, h.Grants,
            new EgressAuditSink(new EgressDecisionAuditAdapter(fixture.Store, fixture.Software)));
        h.Allowlist.Behavior = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(EgressHarness.Entry(request));
        h.Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>([h.Grant(request)]);
        Assert.True((await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken)).Allowed);
        h.Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>([]);
        Assert.False((await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken)).Allowed);

        var leases = new LeaseHarness(clock: h.Decisions.Clock);
        var manager = new CapabilityLeaseManager(leases.Clock.Clock, leases.Store,
            new CapabilityLeaseEventAuditSink(new CapabilityLeaseAuditAdapter(fixture.Store), fixture.Software), leases.Ceilings);
        LeaseRequest IssueRequest(TimeSpan? lifetime = null) => leases.Request(
            issuedBy: request.Actors, scope: request.Scope, capability: request.CapabilityKey, lifetime: lifetime);
        var revoked = await manager.IssueAsync(IssueRequest(), TestContext.Current.CancellationToken);
        Assert.True(revoked.Issued);
        _ = await manager.RevokeAsync(revoked.Lease!.Id, request.Actors.Owner, LeaseRevocationReason.OwnerRevoked,
            TestContext.Current.CancellationToken);
        var expired = await manager.IssueAsync(IssueRequest(TimeSpan.FromSeconds(1)), TestContext.Current.CancellationToken);
        Assert.True(expired.Issued);
        leases.Clock.Advance(TimeSpan.FromSeconds(2));
        _ = await manager.ExpireDueAsync(TestContext.Current.CancellationToken);
        var ended = await manager.IssueAsync(IssueRequest(), TestContext.Current.CancellationToken);
        Assert.True(ended.Issued);
        _ = await manager.EndTaskAsync(leases.Task, TestContext.Current.CancellationToken);

        var rows = fixture.Read();
        Assert.Equal(8, rows.Count);
        Assert.Contains(rows, row => row.Event.EventType == AuditEventType.DataEgressAuthorized);
        Assert.Contains(rows, row => row.Event.EventType == AuditEventType.DataEgressDenied);
        Assert.Equal(3, rows.Count(row => row.Event.EventType == AuditEventType.CapabilityLeaseIssued));
        Assert.Contains(rows, row => row.Event.Resource.Id == revoked.Lease.Id.Value && row.Event.EventType == AuditEventType.CapabilityLeaseRevoked);
        Assert.Contains(rows, row => row.Event.Resource.Id == expired.Lease!.Id.Value && row.Event.EventType == AuditEventType.CapabilityLeaseExpired);
        Assert.Contains(rows, row => row.Event.Resource.Id == ended.Lease!.Id.Value && row.Event.EventType == AuditEventType.CapabilityLeaseTaskEnded);
        using var reopened = fixture.Reopen();
        Assert.Equal(rows.Select(row => row.IntegritySha256), fixture.Read(reopened).Select(row => row.IntegritySha256));
        Assert.Equal(0, new AuditRetentionRunner(reopened, request.Actors, fixture.Software)
            .RunOnce(TestContext.Current.CancellationToken).PurgedCount);
    }

    [Fact]
    public async Task DisposedDurableAuditFailsClosedForEgressAndLeaseIssue()
    {
        var h = new EgressHarness();
        var request = h.Request();
        using var fixture = new CompositionStore(request.Actors);
        h.Allowlist.Behavior = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(EgressHarness.Entry(request));
        h.Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>([h.Grant(request)]);
        var authority = new EgressAuthority(h.Decisions.Clock.Clock, h.Classifier, h.Allowlist, h.Grants,
            new EgressAuditSink(new EgressDecisionAuditAdapter(fixture.Store, fixture.Software)));
        var leases = new LeaseHarness(clock: h.Decisions.Clock);
        var manager = new CapabilityLeaseManager(leases.Clock.Clock, leases.Store,
            new CapabilityLeaseEventAuditSink(new CapabilityLeaseAuditAdapter(fixture.Store), fixture.Software), leases.Ceilings);
        fixture.Store.Dispose();
        var transfer = await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);
        Assert.False(transfer.Allowed);
        Assert.Equal(EgressReason.AuditUnavailable, transfer.Reason);
        var issue = await manager.IssueAsync(leases.Request(issuedBy: request.Actors, scope: request.Scope), TestContext.Current.CancellationToken);
        Assert.False(issue.Issued);
        Assert.Equal(LeaseIssueRefusal.AuditUnavailable, issue.Refusal);
        using var reopened = fixture.Reopen();
        Assert.Empty(fixture.Read(reopened));
    }

    [Fact]
    public async Task TransferCannotSendWhenItsDurableAuditFails()
    {
        var h = new EgressHarness();
        var request = await h.ApprovedRequestAsync();
        h.Permit(request);
        var execution = await h.Pipeline().ExecuteAsync(request, h.Decisions.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(ExecutionStatus.Succeeded, execution.Status);
        using var fixture = new CompositionStore(request.Actors);
        var authority = new EgressAuthority(h.Decisions.Clock.Clock, h.Classifier, h.Allowlist, h.Grants,
            new EgressAuditSink(new EgressDecisionAuditAdapter(fixture.Store, fixture.Software)));
        fixture.Store.Dispose();
        var sends = 0;
        var transfer = await authority.TransferAsync(h.Decisions.OwnerOperation.LastTicket!, EgressHarness.Destination,
            (_, _) =>
            {
                sends++;
                return ValueTask.FromResult(Outcome.Success("sent"));
            }, TestContext.Current.CancellationToken);
        Assert.False(transfer.OperationRan);
        Assert.Equal(0, sends);
        Assert.Equal(EgressReason.AuditUnavailable, transfer.Decision.Reason);
        Assert.Equal("resource.unavailable", DecisionHarness.FailureCode(transfer.Result));
    }

    [Fact]
    public async Task ConcurrentAuditWritesPersistAndCancelledIntakeWritesNothing()
    {
        var h = new EgressHarness();
        var request = h.Request();
        using var fixture = new CompositionStore(request.Actors);
        var sink = new EgressAuditSink(new EgressDecisionAuditAdapter(fixture.Store, fixture.Software));
        var authority = new EgressAuthority(h.Decisions.Clock.Clock, h.Classifier, h.Allowlist, h.Grants, sink);
        h.Allowlist.Behavior = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(EgressHarness.Entry(request));
        h.Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>([h.Grant(request)]);
        var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(async () =>
            await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken),
            TestContext.Current.CancellationToken)));
        Assert.All(results, result => Assert.True(result.Allowed));
        var rows = fixture.Read();
        Assert.Equal(12, rows.Count);
        Assert.Equal(12, rows.Select(row => row.Sequence).Distinct().Count());
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await sink.WriteAsync(results[0].Audit, cancelled.Token));
        Assert.Equal(12, fixture.Read().Count);
        using var reopened = fixture.Reopen();
        Assert.Equal(rows.Select(row => row.EventId), fixture.Read(reopened).Select(row => row.EventId));
    }

    [Fact]
    public async Task AnUnsettledLeaseEndRetriesIntoTheRealAuditAndNeverRevivesTheLease()
    {
        var h = new LeaseHarness();
        var chain = h.DirectChain();
        using var fixture = new CompositionStore(chain);
        var durableSink = new CapabilityLeaseEventAuditSink(new CapabilityLeaseAuditAdapter(fixture.Store), fixture.Software);
        var sink = new RecordingLeaseSink
        {
            Behavior = (value, cancellationToken) => durableSink.WriteAsync(value, cancellationToken),
        };
        var manager = new CapabilityLeaseManager(h.Clock.Clock, h.Store, sink, h.Ceilings);
        var issued = await manager.IssueAsync(h.Request(issuedBy: chain), TestContext.Current.CancellationToken);
        Assert.True(issued.Issued);
        sink.Fail = true;
        _ = await manager.RevokeAsync(issued.Lease!.Id, h.Owner, LeaseRevocationReason.OwnerRevoked,
            TestContext.Current.CancellationToken);
        Assert.Equal(LeaseUseVerdict.Revoked, await manager.ValidateAsync(h.Use(issued.Lease), TestContext.Current.CancellationToken));
        Assert.Single(fixture.Read());
        sink.Fail = false;
        _ = await manager.ExpireDueAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, fixture.Read().Count);
        Assert.Equal(LeaseUseVerdict.Revoked, await manager.ValidateAsync(h.Use(issued.Lease), TestContext.Current.CancellationToken));
        _ = await manager.ExpireDueAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, fixture.Read().Count);
    }

    private sealed class CompositionStore : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "arcforges-plt57-" + Guid.NewGuid().ToString("N"));
        private readonly ActorChain actors;
        private readonly AuditRetentionPolicy policy = new(Guid.NewGuid(), 30);

        internal CompositionStore(ActorChain actors)
        {
            this.actors = actors;
            Store = Reopen();
        }

        internal AuditStore Store { get; }
        internal AuditSoftwareIdentity Software { get; } = new("arcscope.desktop/1");
        internal AuditStore Reopen() => new(Path.Combine(directory, "audit.db"), actors.Owner.Realm, actors.Owner.Id, policy);
        internal IReadOnlyList<AuditEventRecord> Read(AuditStore? store = null) =>
            (store ?? Store).Query(new AuditQuery(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), 100));

        public void Dispose()
        {
            Store.Dispose();
            Directory.Delete(directory, recursive: true);
        }
    }
}
