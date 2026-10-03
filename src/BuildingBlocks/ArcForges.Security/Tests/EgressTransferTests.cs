// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Decisions;
using ArcForges.Security.Egress;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>The guarded transfer route: a send operation is reachable only with a fresh, audited egress decision for the declared destination.</summary>
public sealed class EgressTransferTests
{
    private static async Task<AuthorizedExecution> TicketAsync(EgressHarness h, DecisionRequest request)
    {
        h.Permit(request);
        var execution = await h.Pipeline().ExecuteAsync(request, h.Decisions.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(ExecutionStatus.Succeeded, execution.Status);
        return h.Decisions.OwnerOperation.LastTicket!;
    }

    private static EgressOperation<string> Send(List<string> log, Func<AuthorizedEgress, Outcome<string>>? result = null) => (ticket, _) =>
    {
        log.Add(ticket.Destination.Origin);
        return ValueTask.FromResult(result?.Invoke(ticket) ?? Outcome.Success("sent"));
    };

    [Fact]
    public async Task TheSendOperationRunsOnlyAfterAnAllowedAndAuditedDecisionAndGetsItsFacts()
    {
        var h = new EgressHarness();
        var request = await h.ApprovedRequestAsync();
        var ticket = await TicketAsync(h, request);
        var sent = new List<string>();
        AuthorizedEgress? captured = null;
        h.Audit.Behavior = (_, _) =>
        {
            Assert.Empty(sent);
            return ValueTask.CompletedTask;
        };

        var transfer = await h.Authority().TransferAsync(
            ticket,
            EgressHarness.Destination,
            (egress, _) =>
            {
                captured = egress;
                h.Log.Add("send");
                sent.Add(egress.Destination.Origin);
                return ValueTask.FromResult(Outcome.Success("sent"));
            },
            TestContext.Current.CancellationToken);

        Assert.True(transfer.OperationRan);
        Assert.Equal("sent", DecisionHarness.Value(transfer.Result));
        Assert.True(transfer.Decision.Allowed);
        Assert.Equal(["https://api.example.com"], sent);
        Assert.NotNull(captured);
        Assert.Equal("https://api.example.com", captured.Destination.Origin);
        Assert.Equal(EgressDataClass.WorkspaceContent, captured.DataClass);
        Assert.Equal(EgressDestinationClass.ThirdParty, captured.DestinationClass);
        Assert.Equal(EgressAuthorityKind.UserConsent, captured.Authority);
        Assert.Equal("consent-1", captured.AuthorityReference);
        Assert.Same(transfer.Decision, captured.Decision);
        var entries = h.Log.Entries;
        Assert.True(entries.ToList().LastIndexOf("egress-audit") < entries.ToList().IndexOf("send"));
    }

    [Fact]
    public async Task ARefusalIsATypedFailureAndTheSendOperationIsNeverCalled()
    {
        var h = new EgressHarness();
        var ticket = await TicketAsync(h, await h.ApprovedRequestAsync());
        var sent = new List<string>();
        h.Grants.Behavior = (_, _, _) => EgressScenarios.Grants();

        var transfer = await h.Authority().TransferAsync(ticket, EgressHarness.Destination, Send(sent), TestContext.Current.CancellationToken);

        Assert.False(transfer.OperationRan);
        Assert.Empty(sent);
        Assert.Equal(EgressReason.NoGrant, transfer.Decision.Reason);
        Assert.Equal("perm.egress_denied", DecisionHarness.FailureCode(transfer.Result));
        Assert.Equal(EgressAuditKind.Refused, h.Audit.Records[^1].Kind);
    }

    [Fact]
    public async Task AnUnavailableSourceIsAnUnavailableFailureAndNothingIsSent()
    {
        var h = new EgressHarness();
        var ticket = await TicketAsync(h, await h.ApprovedRequestAsync());
        var sent = new List<string>();
        h.Classifier.Behavior = (_, _, _) => throw new InvalidOperationException("down");

        var transfer = await h.Authority().TransferAsync(ticket, EgressHarness.Destination, Send(sent), TestContext.Current.CancellationToken);

        Assert.False(transfer.OperationRan);
        Assert.Empty(sent);
        Assert.Equal("resource.unavailable", DecisionHarness.FailureCode(transfer.Result));
    }

    [Fact]
    public async Task EveryTransferIsItsOwnDecisionSoARevocationOrExpiryIsSeenAtTheNextOne()
    {
        var h = new EgressHarness();
        var request = await h.ApprovedRequestAsync();
        var ticket = await TicketAsync(h, request);
        var authority = h.Authority();
        var sent = new List<string>();
        var before = h.Audit.Records.Count;

        var first = await authority.TransferAsync(ticket, EgressHarness.Destination, Send(sent), TestContext.Current.CancellationToken);
        h.Decisions.Clock.Advance(TimeSpan.FromHours(2));
        var second = await authority.TransferAsync(ticket, EgressHarness.Destination, Send(sent), TestContext.Current.CancellationToken);

        Assert.True(first.OperationRan);
        Assert.False(second.OperationRan);
        Assert.Equal(EgressReason.GrantOutsideLifetime, second.Decision.Reason);
        Assert.Single(sent);
        Assert.Equal(before + 2, h.Audit.Records.Count);
        Assert.NotSame(first.Decision, second.Decision);

        h.Grants.Behavior = (_, _, _) => EgressScenarios.Grants(h.Grant(request, state: EgressGrantState.Denied));
        var third = await authority.TransferAsync(ticket, EgressHarness.Destination, Send(sent), TestContext.Current.CancellationToken);
        Assert.Equal(EgressReason.GrantExplicitlyDenied, third.Decision.Reason);
        Assert.Single(sent);
    }

    [Fact]
    public async Task ATransferCannotGoToAnyDestinationOtherThanTheOneTheInvocationDeclared()
    {
        var h = new EgressHarness();
        var request = await h.ApprovedRequestAsync();
        var ticket = await TicketAsync(h, request);
        // Both the allowlist and the grant source would admit any destination, so only the declared-destination check can refuse.
        h.Allowlist.Behavior = (_, identity, _) => ValueTask.FromResult<EgressAllowlistEntry?>(EgressHarness.Entry(request, identity.Origin));
        h.Grants.Behavior = (_, identity, _) => EgressScenarios.Grants(h.Grant(request, identity.Origin));
        var sent = new List<string>();

        var other = await h.Authority().TransferAsync(ticket, "https://other.example.com", Send(sent), TestContext.Current.CancellationToken);
        var sibling = await h.Authority().TransferAsync(ticket, "https://api.example.com:8443", Send(sent), TestContext.Current.CancellationToken);
        var declared = await h.Authority().TransferAsync(ticket, "https://API.example.com/", Send(sent), TestContext.Current.CancellationToken);

        Assert.Equal(EgressReason.DestinationNotDeclared, other.Decision.Reason);
        Assert.Equal(EgressReason.DestinationNotDeclared, sibling.Decision.Reason);
        Assert.True(declared.OperationRan);
        Assert.Equal(["https://api.example.com"], sent);
    }

    [Fact]
    public async Task TheOperationsOwnFailureIsPassedThroughAndItsExceptionsPropagate()
    {
        var h = new EgressHarness();
        var ticket = await TicketAsync(h, await h.ApprovedRequestAsync());
        var authority = h.Authority();

        var failed = await authority.TransferAsync(
            ticket,
            EgressHarness.Destination,
            (_, _) => ValueTask.FromResult(Outcome.Failure<string>(TypedFailure.Create("dependency.unavailable"))),
            TestContext.Current.CancellationToken);

        Assert.True(failed.OperationRan);
        Assert.True(failed.Decision.Allowed);
        Assert.Equal("dependency.unavailable", DecisionHarness.FailureCode(failed.Result));

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await authority.TransferAsync<string>(
            ticket,
            EgressHarness.Destination,
            (_, _) => throw new InvalidOperationException("send failed"),
            TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ACancelledCallerStopsBeforeTheSendOperationEvenAfterAnAuthorizedDecision()
    {
        var h = new EgressHarness();
        var ticket = await TicketAsync(h, await h.ApprovedRequestAsync());
        using var cancel = new CancellationTokenSource();
        h.Audit.Behavior = async (_, _) => await cancel.CancelAsync();
        var sent = new List<string>();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await h.Authority().TransferAsync(ticket, EgressHarness.Destination, Send(sent), cancel.Token));

        Assert.Empty(sent);
        Assert.Equal(EgressAuditKind.Authorized, h.Audit.Records[^1].Kind);
    }

    [Fact]
    public async Task AuditFailureStopsTheTransferBeforeTheSendOperation()
    {
        var h = new EgressHarness();
        var ticket = await TicketAsync(h, await h.ApprovedRequestAsync());
        h.Audit.Behavior = (_, _) => throw new InvalidOperationException("sink down");
        var sent = new List<string>();

        var transfer = await h.Authority().TransferAsync(ticket, EgressHarness.Destination, Send(sent), TestContext.Current.CancellationToken);

        Assert.False(transfer.OperationRan);
        Assert.Empty(sent);
        Assert.Equal(EgressReason.AuditUnavailable, transfer.Decision.Reason);
        Assert.Equal("resource.unavailable", DecisionHarness.FailureCode(transfer.Result));
    }

    [Fact]
    public async Task NullArgumentsAreRefused()
    {
        var h = new EgressHarness();
        var request = await h.ApprovedRequestAsync();
        var ticket = await TicketAsync(h, request);
        var authority = h.Authority();
        EgressOperation<string> operation = (_, _) => ValueTask.FromResult(Outcome.Success("sent"));

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await authority.TransferAsync<string>(null!, EgressHarness.Destination, operation, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await authority.TransferAsync<string>(ticket, null!, operation, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await authority.TransferAsync<string>(ticket, EgressHarness.Destination, null!, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await authority.DecideAsync(null!, EgressHarness.Destination, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await authority.DecideAsync(request, null!, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void TheEgressTicketAndTheDecisionHaveNoPublicConstructorSoOnlyTheAuthorityMakesThem()
    {
        AssertSealedWithoutPublicConstructor<AuthorizedEgress>();
        AssertSealedWithoutPublicConstructor<EgressDecision>();
        AssertSealedWithoutPublicConstructor<EgressTransfer<string>>();
    }

    private static void AssertSealedWithoutPublicConstructor<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>()
    {
        Assert.True(typeof(T).IsSealed);
        Assert.Empty(typeof(T).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }
}
