// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Security.Decisions;
using ArcForges.Security.Egress;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>
/// The egress authority behind the real pipeline's data-boundary step: read access alone never authorizes egress, and secret use and
/// egress stay two separate authorizations.
/// </summary>
public sealed class EgressPipelineTests
{
    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, false)]
    public async Task ReadAccessAloneNeverAuthorizesEgressAndEgressAloneNeverAuthorizesTheCapability(bool readGranted, bool egressGranted, bool expectedAllowed)
    {
        var h = new EgressHarness();
        var request = await h.ApprovedRequestAsync();
        if (!readGranted)
        {
            h.Decisions.Permissions.Behavior = (_, _) => ValueTask.FromResult<PermissionGrantRecord?>(null);
        }

        if (egressGranted)
        {
            h.Permit(request);
        }

        var decision = await h.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        Assert.Equal(expectedAllowed, decision.Allowed);
        if (readGranted && !egressGranted)
        {
            Assert.Equal(DecisionStep.DataBoundary, decision.FailedStep);
            Assert.Equal(DecisionReason.S08EgressDenied, decision.Reason);
            Assert.Equal("perm.egress_denied", decision.RegisteredCode);
            Assert.Equal(StepDisposition.Passed, decision.Steps[(int)DecisionStep.CapabilityPermission - 1].Disposition);
            Assert.Equal(EgressReason.NotAllowlisted, Assert.Single(h.Audit.Records).Reason);
        }

        if (!readGranted)
        {
            Assert.Equal(DecisionStep.CapabilityPermission, decision.FailedStep);
            Assert.Equal(0, h.Log.Count("egress-classify"));
            Assert.Equal(0, h.Log.Count("egress-grants"));
            Assert.Empty(h.Audit.Records);
        }

        if (expectedAllowed)
        {
            Assert.Equal(StepDisposition.Passed, decision.Steps[(int)DecisionStep.DataBoundary - 1].Disposition);
            Assert.Equal(EgressAuditKind.Authorized, Assert.Single(h.Audit.Records).Kind);
        }
    }

    [Fact]
    public async Task AReadGrantForTheCapabilityIsNotAnEgressGrantForAnyDestination()
    {
        var h = new EgressHarness();
        var request = await h.ApprovedRequestAsync();
        h.Allowlist.Behavior = (_, identity, _) => ValueTask.FromResult<EgressAllowlistEntry?>(EgressHarness.Entry(request, identity.Origin));
        h.Grants.Behavior = (_, _, _) => EgressScenarios.Grants();

        var decision = await h.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        Assert.Equal(DecisionReason.S08EgressDenied, decision.Reason);
        Assert.Equal(EgressReason.NoGrant, Assert.Single(h.Audit.Records).Reason);
    }

    [Fact]
    public async Task AnEgressDeniedByTheEgressSourcesStopsTheOwnerOperationAndIsAuditedByBothTheEgressAndThePipelineSinks()
    {
        var h = new EgressHarness();
        var request = await h.ApprovedRequestAsync();

        var execution = await h.Pipeline().ExecuteAsync(request, h.Decisions.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.Refused, execution.Status);
        Assert.Equal(0, h.Decisions.OwnerOperation.Calls);
        Assert.Equal(DecisionReason.S08EgressDenied, execution.Decision.Reason);
        Assert.Equal(EgressAuditKind.Refused, Assert.Single(h.Audit.Records).Kind);
        var pipelineAudit = Assert.Single(h.Decisions.Audit.Records);
        Assert.Equal(SecurityAuditKind.Refused, pipelineAudit.Kind);
        Assert.Equal(DecisionStep.DataBoundary, pipelineAudit.FailedStep);
    }

    [Fact]
    public async Task AnAllowedEgressReachesTheOwnerOperationAndIsAuditedBeforeIt()
    {
        var h = new EgressHarness();
        var request = await h.ApprovedRequestAsync();
        h.Permit(request);

        var execution = await h.Pipeline().ExecuteAsync(request, h.Decisions.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.Succeeded, execution.Status);
        Assert.Equal(1, h.Decisions.OwnerOperation.Calls);
        Assert.Equal(EgressAuditKind.Authorized, Assert.Single(h.Audit.Records).Kind);
        var entries = h.Log.Entries.ToList();
        Assert.True(entries.IndexOf("egress-audit") < entries.IndexOf("owner-op"));
    }

    [Fact]
    public async Task AnOwnedContentCapabilityStillNeedsItsOwnEgressDecision()
    {
        var h = new EgressHarness("ownedContent");
        var request = h.Request();

        var refused = await h.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        Assert.Equal(DecisionReason.S08EgressDenied, refused.Reason);

        h.Permit(request);
        var allowed = await h.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        Assert.True(allowed.Allowed);
        Assert.Equal(StepDisposition.Passed, allowed.Steps[(int)DecisionStep.DataBoundary - 1].Disposition);
    }

    [Fact]
    public async Task ADestinationOnACapabilityThatDeclaresNoEgressIsRefusedWithoutAskingTheEgressSources()
    {
        var h = new EgressHarness("none");
        var request = h.Request();
        h.Permit(request);

        var decision = await h.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        Assert.Equal(DecisionReason.S08EgressNotDeclared, decision.Reason);
        Assert.Equal(0, h.Log.Count("egress-classify"));
        Assert.Empty(h.Audit.Records);
    }

    [Fact]
    public async Task AnUnavailableEgressSourceRefusesTheStepAsUnavailable()
    {
        var h = new EgressHarness();
        var request = await h.ApprovedRequestAsync();
        h.Permit(request);
        h.Classifier.Behavior = (_, _, _) => throw new InvalidOperationException("classifier down");

        var decision = await h.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        Assert.Equal(DecisionReason.S08Unavailable, decision.Reason);
        Assert.Equal("resource.unavailable", decision.RegisteredCode);
    }

    [Fact]
    public async Task ASecretUseAuthorizationNeverAuthorizesAnEgressAndItsOwnEgressAnswerIsNeverConsulted()
    {
        var h = new EgressHarness();
        var builder = h.Decisions.Request();
        builder.EgressDestination = EgressHarness.Destination;
        builder.SecretUseKey = "secret.key.1";
        var request = builder.Build();
        builder.ApprovalId = await h.Decisions.ApproveAsync(request, RiskLevel.R3);
        request = builder.Build();
        h.Decisions.DataBoundary.SecretBehavior = (_, _) => ValueTask.FromResult(BoundaryVerdict.Allowed);
        h.Decisions.DataBoundary.EgressBehavior = (_, _, _) => ValueTask.FromResult(BoundaryVerdict.Allowed);

        var decision = await h.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        Assert.Equal(DecisionReason.S08EgressDenied, decision.Reason);
        Assert.Equal(1, h.Log.Count("secret"));
        Assert.Equal(0, h.Log.Count("egress"));
        Assert.Equal(1, h.Log.Count("egress-classify"));
    }

    [Fact]
    public async Task AnEgressPermissionNeverAuthorizesTheSecretUse()
    {
        var h = new EgressHarness();
        var builder = h.Decisions.Request();
        builder.EgressDestination = EgressHarness.Destination;
        builder.SecretUseKey = "secret.key.1";
        var request = builder.Build();
        builder.ApprovalId = await h.Decisions.ApproveAsync(request, RiskLevel.R3);
        request = builder.Build();
        h.Permit(request);
        h.Decisions.DataBoundary.SecretBehavior = (_, _) => ValueTask.FromResult(BoundaryVerdict.Denied);

        var denied = await h.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        Assert.Equal(DecisionReason.S08SecretUseDenied, denied.Reason);
        Assert.Equal(0, h.Log.Count("egress-classify"));

        h.Decisions.DataBoundary.SecretBehavior = (_, _) => ValueTask.FromResult(BoundaryVerdict.Allowed);
        var allowed = await h.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        Assert.True(allowed.Allowed);
        var entries = h.Log.Entries.ToList();
        Assert.True(entries.LastIndexOf("secret") < entries.LastIndexOf("egress-classify"));
    }

    [Fact]
    public async Task TheBoundaryAdapterRefusesMissingDependencies()
    {
        var h = new EgressHarness();
        Assert.Throws<ArgumentNullException>(() => new EgressDataBoundary(null!, h.Decisions.DataBoundary));
        Assert.Throws<ArgumentNullException>(() => new EgressDataBoundary(h.Authority(), null!));
        var adapter = new EgressDataBoundary(h.Authority(), h.Decisions.DataBoundary);
        var request = h.Request();

        Assert.Equal(BoundaryVerdict.Allowed, await adapter.AuthorizeSecretUseAsync(request, TestContext.Current.CancellationToken));
        Assert.Equal(1, h.Log.Count("secret"));
        Assert.Equal(BoundaryVerdict.Denied, await adapter.AuthorizeEgressAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken));
        Assert.Equal(0, h.Log.Count("egress"));
    }
}
