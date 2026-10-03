// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation;
using ArcForges.Security.Approvals;
using ArcForges.Security.Decisions;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>
/// The pipeline's bounds on its sources and sinks, run against the real clock: a source that never answers refuses its step and is
/// cancelled, a slow one that answers in time does not, and the constructors refuse missing parts and unbounded options.
/// </summary>
public sealed class DecisionBoundsTests
{
    private static DecisionPipelineOptions Short => new() { StepTimeout = TimeSpan.FromMilliseconds(200) };

    [Fact(Timeout = 60_000)]
    public async Task ASourceThatNeverAnswersRefusesItsStepAndIsCancelled()
    {
        var harness = new DecisionHarness();
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Policy.Behavior = async (_, token) =>
        {
            await using var registration = token.Register(() => cancelled.TrySetResult());
            await Task.Delay(Timeout.Infinite, token);
            return PolicyVerdict.Enabled;
        };

        var decision = await harness.Pipeline(Short).EvaluateAsync(EnforcementPoint.ServiceDecision, harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.False(decision.Allowed);
        Assert.Equal(DecisionStep.ProductPolicy, decision.FailedStep);
        Assert.Equal(DecisionReason.S02Unavailable, decision.Reason);
        Assert.Equal("resource.unavailable", decision.RegisteredCode);
        await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken);
        Assert.Equal(["catalogue", "policy", "audit"], harness.Log.Entries);
    }

    [Fact(Timeout = 60_000)]
    public async Task ASourceThatIgnoresItsTokenIsStillBoundedAndALateFailureIsObserved()
    {
        var harness = new DecisionHarness();
        var release = new TaskCompletionSource<PolicyVerdict>(TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Policy.Behavior = (_, _) => new ValueTask<PolicyVerdict>(release.Task);

        var decision = await harness.Pipeline(Short).EvaluateAsync(EnforcementPoint.ServiceDecision, harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.Equal(DecisionReason.S02Unavailable, decision.Reason);
        release.SetException(new InvalidOperationException("late failure"));
        await Task.Yield();
    }

    [Fact(Timeout = 60_000)]
    public async Task ASlowSourceThatAnswersInTimeIsNotRefused()
    {
        var harness = new DecisionHarness();
        harness.Policy.Behavior = async (_, token) =>
        {
            await Task.Delay(TimeSpan.FromMilliseconds(40), token);
            return PolicyVerdict.Enabled;
        };

        var decision = await harness.Pipeline(new DecisionPipelineOptions { StepTimeout = TimeSpan.FromSeconds(30) })
            .EvaluateAsync(EnforcementPoint.ServiceDecision, harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.True(decision.Allowed);
    }

    [Fact(Timeout = 60_000)]
    public async Task ASinkThatNeverAnswersFailsItsBookkeepingStepAndTheOtherSinkStillRuns()
    {
        var harness = new DecisionHarness();
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Recorder.Behavior = async (_, token) =>
        {
            await using var registration = token.Register(() => cancelled.TrySetResult());
            await Task.Delay(Timeout.Infinite, token);
        };

        var execution = await harness.Pipeline(Short).ExecuteAsync(harness.Request().Build(), harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.BookkeepingFailed, execution.Status);
        Assert.Equal(DecisionReason.S13RecordFailed, execution.Decision.Steps[12].Reason);
        Assert.Equal(StepDisposition.Passed, execution.Decision.Steps[13].Disposition);
        await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken);
        Assert.Single(harness.Audit.Records);
    }

    [Fact(Timeout = 60_000)]
    public async Task ASinkThatIgnoresItsTokenIsStillBoundedAndFailsItsBookkeepingStep()
    {
        var harness = new DecisionHarness();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Recorder.Behavior = (_, _) => new ValueTask(release.Task);

        var execution = await harness.Pipeline(Short).ExecuteAsync(harness.Request().Build(), harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.BookkeepingFailed, execution.Status);
        Assert.Equal(DecisionReason.S13RecordFailed, execution.Decision.Steps[12].Reason);
        release.SetException(new InvalidOperationException("late failure"));
        await Task.Yield();
    }

    [Fact(Timeout = 60_000)]
    public async Task AnAuditSinkThatNeverAnswersLeavesARefusalRefusedAndReportsTheFailure()
    {
        var harness = new DecisionHarness();
        harness.Audit.Behavior = async (_, token) => await Task.Delay(Timeout.Infinite, token);
        harness.Policy.Behavior = (_, _) => ValueTask.FromResult(PolicyVerdict.Disabled);

        var decision = await harness.Pipeline(Short).EvaluateAsync(EnforcementPoint.ServiceDecision, harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.Equal(DecisionReason.S02PolicyDisabled, decision.Reason);
        Assert.Equal(DecisionAuditStatus.Failed, decision.Audit);
        Assert.Equal(DecisionReason.S14AuditFailed, decision.Steps[13].Reason);
    }

    [Fact]
    public void OptionsDefaultToBoundedValuesAndRefuseUnboundedOnes()
    {
        var defaults = new DecisionPipelineOptions();
        Assert.Equal(TimeSpan.FromSeconds(15), defaults.StepTimeout);
        Assert.Equal(TimeSpan.FromSeconds(60), defaults.ServiceDecisionLifetime);
        var harness = new DecisionHarness();
        var services = harness.Services();
        _ = new SecurityDecisionPipeline(services);
        _ = new SecurityDecisionPipeline(services, new DecisionPipelineOptions { StepTimeout = TimeSpan.FromMinutes(5), ServiceDecisionLifetime = TimeSpan.FromMinutes(10) });
        _ = new SecurityDecisionPipeline(services, new DecisionPipelineOptions { StepTimeout = TimeSpan.FromTicks(1), ServiceDecisionLifetime = TimeSpan.FromTicks(1) });
        _ = Assert.Throws<ArgumentNullException>(() => new SecurityDecisionPipeline(null!));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new SecurityDecisionPipeline(services, new DecisionPipelineOptions { StepTimeout = TimeSpan.Zero }));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new SecurityDecisionPipeline(services, new DecisionPipelineOptions { StepTimeout = TimeSpan.FromTicks(-1) }));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new SecurityDecisionPipeline(services, new DecisionPipelineOptions { StepTimeout = TimeSpan.FromMinutes(5) + TimeSpan.FromTicks(1) }));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new SecurityDecisionPipeline(services, new DecisionPipelineOptions { ServiceDecisionLifetime = TimeSpan.Zero }));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new SecurityDecisionPipeline(services, new DecisionPipelineOptions { ServiceDecisionLifetime = TimeSpan.FromMinutes(10) + TimeSpan.FromTicks(1) }));
    }

    [Fact]
    public void EverySourceAndSinkIsRequired()
    {
        var h = new DecisionHarness();
        var clock = h.Clock.Clock;
        DecisionPipelineServices Make(
            IClock? c = null, ICapabilityCatalogue? catalogue = null, IProductPolicy? policy = null, IActorIdentityVerifier? identity = null,
            IScopeAuthority? scope = null, ITrustEvaluator? trust = null, IPermissionSource? permissions = null, IResourceAuthorizer? resources = null,
            IDataBoundaryAuthorizer? boundary = null, ApprovalCoordinator? approvals = null, StepUpCoordinator? stepUp = null,
            ISensitiveOperationSource? sensitive = null, IOwnerValidator? owner = null, IDecisionRecorder? recorder = null, ISecurityAuditSink? audit = null) =>
            new(c ?? clock, catalogue ?? h.Catalogue, policy ?? h.Policy, identity ?? h.Identity, scope ?? h.Scope, trust ?? h.Trust,
                permissions ?? h.Permissions, resources ?? h.Resources, boundary ?? h.DataBoundary, approvals ?? h.Approvals,
                stepUp ?? h.StepUp, sensitive ?? h.Sensitive, owner ?? h.Owner, recorder ?? h.Recorder, audit ?? h.Audit);

        var whole = Make();
        Assert.Same(clock, whole.Clock);
        Assert.Same(h.Catalogue, whole.Catalogue);
        Assert.Same(h.Policy, whole.Policy);
        Assert.Same(h.Identity, whole.Identity);
        Assert.Same(h.Scope, whole.Scope);
        Assert.Same(h.Trust, whole.Trust);
        Assert.Same(h.Permissions, whole.Permissions);
        Assert.Same(h.Resources, whole.Resources);
        Assert.Same(h.DataBoundary, whole.DataBoundary);
        Assert.Same(h.Approvals, whole.Approvals);
        Assert.Same(h.StepUp, whole.StepUp);
        Assert.Same(h.Sensitive, whole.Sensitive);
        Assert.Same(h.Owner, whole.Owner);
        Assert.Same(h.Recorder, whole.Recorder);
        Assert.Same(h.Audit, whole.Audit);

        Assert.Equal("clock", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(null!, h.Catalogue, h.Policy, h.Identity, h.Scope, h.Trust, h.Permissions, h.Resources, h.DataBoundary, h.Approvals, h.StepUp, h.Sensitive, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("catalogue", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, null!, h.Policy, h.Identity, h.Scope, h.Trust, h.Permissions, h.Resources, h.DataBoundary, h.Approvals, h.StepUp, h.Sensitive, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("policy", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, null!, h.Identity, h.Scope, h.Trust, h.Permissions, h.Resources, h.DataBoundary, h.Approvals, h.StepUp, h.Sensitive, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("identity", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, null!, h.Scope, h.Trust, h.Permissions, h.Resources, h.DataBoundary, h.Approvals, h.StepUp, h.Sensitive, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("scope", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, h.Identity, null!, h.Trust, h.Permissions, h.Resources, h.DataBoundary, h.Approvals, h.StepUp, h.Sensitive, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("trust", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, h.Identity, h.Scope, null!, h.Permissions, h.Resources, h.DataBoundary, h.Approvals, h.StepUp, h.Sensitive, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("permissions", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, h.Identity, h.Scope, h.Trust, null!, h.Resources, h.DataBoundary, h.Approvals, h.StepUp, h.Sensitive, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("resources", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, h.Identity, h.Scope, h.Trust, h.Permissions, null!, h.DataBoundary, h.Approvals, h.StepUp, h.Sensitive, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("dataBoundary", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, h.Identity, h.Scope, h.Trust, h.Permissions, h.Resources, null!, h.Approvals, h.StepUp, h.Sensitive, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("approvals", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, h.Identity, h.Scope, h.Trust, h.Permissions, h.Resources, h.DataBoundary, null!, h.StepUp, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("stepUp", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, h.Identity, h.Scope, h.Trust, h.Permissions, h.Resources, h.DataBoundary, h.Approvals, null!, h.Sensitive, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("sensitiveOperations", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, h.Identity, h.Scope, h.Trust, h.Permissions, h.Resources, h.DataBoundary, h.Approvals, h.StepUp, null!, h.Owner, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("owner", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, h.Identity, h.Scope, h.Trust, h.Permissions, h.Resources, h.DataBoundary, h.Approvals, h.StepUp, h.Sensitive, null!, h.Recorder, h.Audit)).ParamName);
        Assert.Equal("recorder", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, h.Identity, h.Scope, h.Trust, h.Permissions, h.Resources, h.DataBoundary, h.Approvals, h.StepUp, h.Sensitive, h.Owner, null!, h.Audit)).ParamName);
        Assert.Equal("audit", Assert.Throws<ArgumentNullException>(() => new DecisionPipelineServices(clock, h.Catalogue, h.Policy, h.Identity, h.Scope, h.Trust, h.Permissions, h.Resources, h.DataBoundary, h.Approvals, h.StepUp, h.Sensitive, h.Owner, h.Recorder, null!)).ParamName);
    }

    [Fact]
    public async Task TheInProcessTransportAuthenticatesNobodyAndSaysSo()
    {
        var session = TransportSessions.InProcess;
        Assert.Equal(TransportKind.InProcess, session.Kind);
        var verdict = await session.VerifyCurrentAsync(TestContext.Current.CancellationToken);
        Assert.Equal(TransportRefusal.None, verdict.Refusal);
        Assert.Equal(TransportKind.InProcess, verdict.Binding!.Kind);
        Assert.Equal(TransportAssurance.InProcessHost, verdict.Binding.Assurance);
        Assert.Null(verdict.Binding.LaunchId);
        Assert.Null(verdict.Binding.BoundCallerInstance);
        Assert.Same(session, TransportSessions.InProcess);
    }

    [Fact]
    public void TransportBindingsRefuseAnUnnamedKindOrAssuranceAndBoundTheirText()
    {
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new TransportBinding(TransportKind.None, TransportAssurance.InProcessHost));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new TransportBinding((TransportKind)8, TransportAssurance.InProcessHost));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new TransportBinding(TransportKind.InProcess, TransportAssurance.None));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new TransportBinding(TransportKind.InProcess, (TransportAssurance)8));
        _ = Assert.Throws<ArgumentException>(() => new TransportBinding(TransportKind.LocalRpcChild, TransportAssurance.LaunchClaimWithSecretProof, slot: ""));
        _ = Assert.Throws<ArgumentException>(() => new TransportBinding(TransportKind.LocalRpcChild, TransportAssurance.LaunchClaimWithSecretProof, slot: new string('s', 65)));
        _ = Assert.Throws<ArgumentException>(() => new TransportBinding(TransportKind.LocalRpcChild, TransportAssurance.LaunchClaimWithSecretProof, childKind: new string('c', 65)));
        _ = Assert.Throws<ArgumentException>(() => new TransportBinding(TransportKind.LocalRpcChild, TransportAssurance.LaunchClaimWithSecretProof, buildId: new string('b', 65)));
        var binding = new TransportBinding(TransportKind.LocalRpcChild, TransportAssurance.LaunchClaimWithSecretProof, Guid.NewGuid(), "slot", 3, "Connector", "build-1");
        Assert.Equal(3UL, binding.Epoch);
        Assert.Equal("Connector", binding.ChildKind);
        Assert.Equal("build-1", binding.BuildId);
        Assert.Equal("slot", binding.Slot);
    }
}
