// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using ArcForges.Security.Decisions;
using ArcForges.Security.Egress;

namespace ArcForges.Security.Tests;

internal sealed class FakeClassifier(CallLog log) : IEgressContentClassifier
{
    internal Func<DecisionRequest, EgressDestinationIdentity, CancellationToken, ValueTask<EgressContentFacts?>> Behavior { get; set; } =
        (_, _, _) => ValueTask.FromResult<EgressContentFacts?>(new EgressContentFacts(EgressDataClass.WorkspaceContent, true));

    public ValueTask<EgressContentFacts?> ClassifyAsync(DecisionRequest request, EgressDestinationIdentity destination, CancellationToken cancellationToken)
    {
        log.Add("egress-classify");
        return Behavior(request, destination, cancellationToken);
    }
}

internal sealed class FakeAllowlist(CallLog log) : IEgressAllowlist
{
    internal Func<string, EgressDestinationIdentity, CancellationToken, ValueTask<EgressAllowlistEntry?>> Behavior { get; set; } =
        (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(null);

    public ValueTask<EgressAllowlistEntry?> FindAsync(string scopeKey, EgressDestinationIdentity destination, CancellationToken cancellationToken)
    {
        log.Add("egress-allowlist");
        return Behavior(scopeKey, destination, cancellationToken);
    }
}

internal sealed class FakeEgressGrants(CallLog log) : IEgressGrantSource
{
    internal Func<DecisionRequest, EgressDestinationIdentity, CancellationToken, ValueTask<IReadOnlyList<EgressGrantRecord>>> Behavior { get; set; } =
        (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>([]);

    public ValueTask<IReadOnlyList<EgressGrantRecord>> FindAsync(DecisionRequest request, EgressDestinationIdentity destination, CancellationToken cancellationToken)
    {
        log.Add("egress-grants");
        return Behavior(request, destination, cancellationToken);
    }
}

internal sealed class FakeEgressAudit(CallLog log) : IEgressAuditSink
{
    private readonly ConcurrentQueue<EgressAuditRecord> _records = new();

    internal IReadOnlyList<EgressAuditRecord> Records => [.. _records];

    internal CancellationToken LastToken { get; private set; }

    internal Func<EgressAuditRecord, CancellationToken, ValueTask> Behavior { get; set; } = (_, _) => ValueTask.CompletedTask;

    public ValueTask WriteAsync(EgressAuditRecord record, CancellationToken cancellationToken)
    {
        log.Add("egress-audit");
        LastToken = cancellationToken;
        _records.Enqueue(record);
        return Behavior(record, cancellationToken);
    }
}

/// <summary>
/// Everything an egress test needs on top of the decision harness: controllable classifier, allowlist, grant source and audit sink, the
/// real authority, and a real pipeline whose data-boundary port is the real egress adapter.
/// </summary>
internal sealed class EgressHarness
{
    internal const string Destination = "https://api.example.com";

    internal EgressHarness(string capabilityEgress = "external")
    {
        Decisions = new DecisionHarness(egress: capabilityEgress);
        Classifier = new FakeClassifier(Log);
        Allowlist = new FakeAllowlist(Log);
        Grants = new FakeEgressGrants(Log);
        Audit = new FakeEgressAudit(Log);
    }

    internal DecisionHarness Decisions { get; }

    internal CallLog Log => Decisions.Log;

    internal FakeClassifier Classifier { get; }

    internal FakeAllowlist Allowlist { get; }

    internal FakeEgressGrants Grants { get; }

    internal FakeEgressAudit Audit { get; }

    internal DateTimeOffset Now => Decisions.Clock.UtcNow;

    internal EgressAuthority Authority(EgressAuthorityOptions? options = null) =>
        new(Decisions.Clock.Clock, Classifier, Allowlist, Grants, Audit, options);

    internal SecurityDecisionPipeline Pipeline(EgressAuthority? authority = null, DecisionPipelineOptions? options = null)
    {
        var services = Decisions.Services();
        var boundary = new EgressDataBoundary(authority ?? Authority(), Decisions.DataBoundary);
        return new SecurityDecisionPipeline(
            new DecisionPipelineServices(
                services.Clock, services.Catalogue, services.Policy, services.Identity, services.Scope, services.Trust, services.Permissions,
                services.Resources, boundary, services.Approvals, services.StepUp, services.SensitiveOperations, services.Owner, services.Recorder, services.Audit),
            options);
    }

    internal DecisionRequest Request(string? destination = Destination)
    {
        var builder = Decisions.Request();
        builder.EgressDestination = destination;
        return builder.Build();
    }

    /// <summary>A request approved exactly as presented at the risk external egress implies, as the pipeline needs to reach its last step.</summary>
    internal async Task<DecisionRequest> ApprovedRequestAsync(string? destination = Destination)
    {
        var builder = Decisions.Request();
        builder.EgressDestination = destination;
        var approval = await Decisions.ApproveAsync(builder.Build(), RiskLevel.R3);
        builder.ApprovalId = approval;
        return builder.Build();
    }

    internal static EgressAllowlistEntry Entry(
        DecisionRequest request,
        string destination = Destination,
        EgressDestinationClass destinationClass = EgressDestinationClass.ThirdParty,
        EgressDataClass max = EgressDataClass.WorkspaceContent,
        string? scopeKey = null) =>
        new(scopeKey ?? request.ScopeKey, EgressDestinationIdentity.Parse(destination), destinationClass, max, "allowlist-generation-1");

    internal EgressGrantRecord Grant(
        DecisionRequest request,
        string destination = Destination,
        EgressGrantState state = EgressGrantState.Granted,
        EgressDataClass max = EgressDataClass.WorkspaceContent,
        EgressAuthorityKind authority = EgressAuthorityKind.UserConsent,
        string reference = "consent-1",
        TimeSpan? validFromOffset = null,
        TimeSpan? validUntilOffset = null,
        string? principalKey = null,
        string? capabilityKey = null,
        string? scopeKey = null,
        string issuer = "owner.egress") =>
        new(
            issuer,
            principalKey ?? request.PrincipalKey,
            capabilityKey ?? request.CapabilityKey,
            scopeKey ?? request.ScopeKey,
            EgressDestinationIdentity.Parse(destination),
            state,
            max,
            authority,
            reference,
            Now + (validFromOffset ?? TimeSpan.FromHours(-1)),
            Now + (validUntilOffset ?? TimeSpan.FromHours(1)),
            "grant-generation-1");

    /// <summary>Makes the allowlist and the grant source admit exactly this request's destination, with the given limits.</summary>
    internal EgressHarness Permit(
        DecisionRequest request,
        EgressDestinationClass destinationClass = EgressDestinationClass.ThirdParty,
        EgressDataClass allowlistMax = EgressDataClass.WorkspaceContent,
        EgressDataClass grantMax = EgressDataClass.WorkspaceContent)
    {
        // The records are built now, so a later move of the clock ages them like stored facts rather than rebuilding them as current.
        var entry = Entry(request, destinationClass: destinationClass, max: allowlistMax);
        var grant = Grant(request, max: grantMax);
        Allowlist.Behavior = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(entry);
        Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>([grant]);
        return this;
    }

    internal EgressHarness Classify(EgressDataClass dataClass, bool aiEligible = true)
    {
        Classifier.Behavior = (_, _, _) => ValueTask.FromResult<EgressContentFacts?>(new EgressContentFacts(dataClass, aiEligible));
        return this;
    }
}
