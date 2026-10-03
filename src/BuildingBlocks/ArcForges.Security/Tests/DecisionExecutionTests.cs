// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Decisions;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>The owner's execution, the result record and audit steps, and the service decision's single-use, freshness and identity checks.</summary>
public sealed class DecisionExecutionTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(30);

    private static DecisionPipelineOptions Options => new() { ServiceDecisionLifetime = Lifetime };

    [Fact]
    public async Task AnOwnerFailureIsReportedWithItsRegisteredCodeRecordedAndAudited()
    {
        var harness = new DecisionHarness();
        harness.OwnerOperation.Behavior = (_, _) => ValueTask.FromResult(Outcome.Failure<string>(TypedFailure.Create("state.not_found")));
        var request = harness.Request().Build();

        var execution = await harness.Pipeline().ExecuteAsync(request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.OwnerFailed, execution.Status);
        Assert.Equal("state.not_found", DecisionHarness.FailureCode(execution.Result));
        Assert.Same(execution.OwnerResult, execution.Result);
        Assert.Equal(EffectCertainty.DidNotHappen, execution.Effect);
        Assert.True(execution.Decision.Allowed);
        Assert.Equal(StepDisposition.Refused, execution.Decision.Steps[11].Disposition);
        Assert.Equal(DecisionReason.S12OwnerFailed, execution.Decision.Steps[11].Reason);
        Assert.Equal(StepDisposition.Passed, execution.Decision.Steps[12].Disposition);
        Assert.Equal(StepDisposition.Passed, execution.Decision.Steps[13].Disposition);
        Assert.Equal(DecisionStep.None, execution.Decision.FailedStep);
        var record = Assert.Single(harness.Recorder.Records);
        Assert.Equal(DecisionResultKind.Failure, record.Result);
        Assert.Equal("state.not_found", record.FailureCode);
        Assert.Equal(EffectCertainty.DidNotHappen, record.Effect);
        var audit = Assert.Single(harness.Audit.Records);
        Assert.Equal(SecurityAuditKind.OwnerFailed, audit.Kind);
        Assert.Equal("decision.s12.owner_failed", audit.ReasonCode);
        Assert.Equal("state.not_found", audit.RegisteredCode);
        Assert.Equal(DecisionStep.None, audit.FailedStep);
        Assert.Equal(EffectCertainty.DidNotHappen, audit.Effect);
    }

    [Fact]
    public async Task AnOwnerFailureWithAnUnregisteredCodeBecomesTheGenericUnknownEffectFailure()
    {
        var harness = new DecisionHarness();
        harness.OwnerOperation.Behavior = (_, _) => ValueTask.FromResult(Outcome.Failure<string>(
            TypedFailure.FromWire(new ArcError { Code = "future.unregistered", Category = ErrorCategory.Execution, Effect = EffectCertainty.Happened })));

        var execution = await harness.Pipeline().ExecuteAsync(harness.Request().Build(), harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.OwnerFailed, execution.Status);
        Assert.Equal("internal.unexpected", DecisionHarness.FailureCode(execution.Result));
        Assert.Equal(EffectCertainty.Unknown, execution.Effect);
        Assert.Equal("internal.unexpected", harness.Recorder.Records.Single().FailureCode);
        Assert.Equal("internal.unexpected", harness.Audit.Records.Single().RegisteredCode);
    }

    [Theory]
    [InlineData(EffectCertainty.DidNotHappen)]
    [InlineData(EffectCertainty.Happened)]
    [InlineData(EffectCertainty.Unknown)]
    public async Task AnOwnerCancellationKeepsTheEffectCertaintyTheOwnerReported(EffectCertainty effect)
    {
        var harness = new DecisionHarness();
        harness.OwnerOperation.Behavior = (_, _) => ValueTask.FromResult(Outcome.Cancelled<string>(effect));

        var execution = await harness.Pipeline().ExecuteAsync(harness.Request().Build(), harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.OwnerCancelled, execution.Status);
        Assert.Equal(OutcomeKind.Cancelled, execution.Result.Kind);
        Assert.Equal(effect, execution.Effect);
        Assert.Equal(DecisionResultKind.Cancelled, harness.Recorder.Records.Single().Result);
        Assert.Equal(effect, harness.Recorder.Records.Single().Effect);
        var audit = harness.Audit.Records.Single();
        Assert.Equal(SecurityAuditKind.OwnerCancelled, audit.Kind);
        Assert.Equal("decision.s12.owner_failed", audit.ReasonCode);
        Assert.Equal(string.Empty, audit.RegisteredCode);
        Assert.Equal(effect, audit.Effect);
    }

    [Fact]
    public async Task AnOwnerThatThrowsHasAnUnknownEffectAndACancelledOwnerIsReportedCancelled()
    {
        var thrown = new DecisionHarness();
        thrown.OwnerOperation.Behavior = (_, _) => throw new InvalidOperationException("owner crashed");
        var failed = await thrown.Pipeline().ExecuteAsync(thrown.Request().Build(), thrown.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(ExecutionStatus.OwnerFailed, failed.Status);
        Assert.Equal("internal.unexpected", DecisionHarness.FailureCode(failed.Result));
        Assert.Equal(EffectCertainty.Unknown, failed.Effect);

        var cancelled = new DecisionHarness();
        cancelled.OwnerOperation.Behavior = (_, _) => throw new OperationCanceledException();
        var result = await cancelled.Pipeline().ExecuteAsync(cancelled.Request().Build(), cancelled.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(ExecutionStatus.OwnerCancelled, result.Status);
        Assert.Equal(EffectCertainty.Unknown, result.Effect);
        Assert.Equal(DecisionResultKind.Cancelled, cancelled.Recorder.Records.Single().Result);

        var empty = new DecisionHarness();
        empty.OwnerOperation.Behavior = (_, _) => ValueTask.FromResult<Outcome<string>>(null!);
        var nothing = await empty.Pipeline().ExecuteAsync(empty.Request().Build(), empty.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(ExecutionStatus.OwnerFailed, nothing.Status);
        Assert.Equal("internal.unexpected", DecisionHarness.FailureCode(nothing.Result));
    }

    [Fact]
    public async Task AFailedResultRecordIsReportedAsHappenedAndTheAuditStillRuns()
    {
        var harness = new DecisionHarness();
        harness.Recorder.Behavior = (_, _) => throw new InvalidOperationException("journal full");

        var execution = await harness.Pipeline().ExecuteAsync(harness.Request().Build(), harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.BookkeepingFailed, execution.Status);
        Assert.Equal(EffectCertainty.Happened, execution.Effect);
        Assert.Equal(1, harness.OwnerOperation.Calls);
        Assert.True(execution.Result.TryGetFailure(out var failure));
        Assert.Equal("internal.unexpected", failure.Code);
        Assert.Equal(EffectCertainty.Happened, failure.Effect);
        Assert.True(execution.OwnerResult!.TryGetValue(out var value));
        Assert.Equal("done", value);
        Assert.Equal(StepDisposition.Refused, execution.Decision.Steps[12].Disposition);
        Assert.Equal(DecisionReason.S13RecordFailed, execution.Decision.Steps[12].Reason);
        Assert.Equal(StepDisposition.Passed, execution.Decision.Steps[13].Disposition);
        Assert.Equal(DecisionAuditStatus.Written, execution.Decision.Audit);
        Assert.True(execution.Decision.Allowed);
        Assert.Single(harness.Audit.Records);
    }

    [Fact]
    public async Task AFailedAuditWriteIsReportedAsHappenedAndTheRecordIsKept()
    {
        var harness = new DecisionHarness();
        harness.Audit.Behavior = (_, _) => throw new InvalidOperationException("audit store closed");

        var execution = await harness.Pipeline().ExecuteAsync(harness.Request().Build(), harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.BookkeepingFailed, execution.Status);
        Assert.Equal(EffectCertainty.Happened, execution.Effect);
        Assert.True(execution.Result.TryGetFailure(out var failure));
        Assert.Equal(EffectCertainty.Happened, failure.Effect);
        Assert.Equal(StepDisposition.Passed, execution.Decision.Steps[12].Disposition);
        Assert.Equal(StepDisposition.Refused, execution.Decision.Steps[13].Disposition);
        Assert.Equal(DecisionReason.S14AuditFailed, execution.Decision.Steps[13].Reason);
        Assert.Equal(DecisionAuditStatus.Failed, execution.Decision.Audit);
        Assert.Single(harness.Recorder.Records);
    }

    [Fact]
    public async Task BookkeepingFailureAfterAnOwnerFailureKeepsTheOwnersFailureVisible()
    {
        var harness = new DecisionHarness();
        harness.OwnerOperation.Behavior = (_, _) => ValueTask.FromResult(Outcome.Failure<string>(TypedFailure.Create("state.gone")));
        harness.Recorder.Behavior = (_, _) => throw new InvalidOperationException("journal full");
        harness.Audit.Behavior = (_, _) => throw new InvalidOperationException("audit closed");

        var execution = await harness.Pipeline().ExecuteAsync(harness.Request().Build(), harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.BookkeepingFailed, execution.Status);
        Assert.Equal("state.gone", DecisionHarness.FailureCode(execution.Result));
        Assert.Equal(DecisionReason.S13RecordFailed, execution.Decision.Steps[12].Reason);
        Assert.Equal(DecisionReason.S14AuditFailed, execution.Decision.Steps[13].Reason);
    }

    [Fact]
    public async Task ABrokenAuditSinkNeverChangesARefusalAndIsReported()
    {
        var harness = new DecisionHarness();
        harness.Audit.Behavior = (_, _) => throw new InvalidOperationException("audit closed");
        harness.Policy.Behavior = (_, _) => ValueTask.FromResult(PolicyVerdict.Disabled);

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.False(decision.Allowed);
        Assert.Equal(DecisionStep.ProductPolicy, decision.FailedStep);
        Assert.Equal(DecisionReason.S02PolicyDisabled, decision.Reason);
        Assert.Equal(DecisionAuditStatus.Failed, decision.Audit);
        Assert.Equal(StepDisposition.Refused, decision.Steps[13].Disposition);
        Assert.Equal(DecisionReason.S14AuditFailed, decision.Steps[13].Reason);
    }

    [Fact]
    public async Task BookkeepingIsNotCancelledByTheCallersCancellationAfterTheOwnerRan()
    {
        var harness = new DecisionHarness();
        using var cancel = new CancellationTokenSource();
        harness.OwnerOperation.Behavior = async (_, _) =>
        {
            await cancel.CancelAsync();
            return Outcome.Success("done");
        };
        var recorderToken = new List<bool>();
        var auditToken = new List<bool>();
        harness.Recorder.Behavior = (_, token) =>
        {
            recorderToken.Add(token.IsCancellationRequested);
            return ValueTask.CompletedTask;
        };
        harness.Audit.Behavior = (_, token) =>
        {
            auditToken.Add(token.IsCancellationRequested);
            return ValueTask.CompletedTask;
        };

        var execution = await harness.Pipeline().ExecuteAsync(harness.Request().Build(), harness.OwnerOperation.Operation, cancel.Token);

        Assert.Equal(ExecutionStatus.Succeeded, execution.Status);
        Assert.Equal([false], recorderToken);
        Assert.Equal([false], auditToken);
    }

    [Fact]
    public async Task CancellationBeforeTheOwnerRunsPropagatesAndRunsNoOwner()
    {
        var harness = new DecisionHarness();
        using var cancel = new CancellationTokenSource();
        // The owner's validation has already answered when the caller cancels, so only the check before the owner operation can see it.
        harness.Owner.Behavior = (_, _) =>
        {
#pragma warning disable CA1849 // The cancellation must happen synchronously, before the answer is returned.
            cancel.Cancel();
#pragma warning restore CA1849
            return ValueTask.FromResult(OwnerVerdict.Valid);
        };

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await harness.Pipeline().ExecuteAsync(harness.Request().Build(), harness.OwnerOperation.Operation, cancel.Token));

        Assert.Equal(0, harness.OwnerOperation.Calls);
        Assert.Empty(harness.Recorder.Records);
    }

    [Fact]
    public async Task ACallersCancellationDuringASourcePropagatesInsteadOfBecomingARefusal()
    {
        var harness = new DecisionHarness();
        using var cancel = new CancellationTokenSource();
        harness.Policy.Behavior = async (_, token) =>
        {
            await cancel.CancelAsync();
            await Task.Delay(Timeout.Infinite, token);
            return PolicyVerdict.Enabled;
        };

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, harness.Request().Build(), cancel.Token));

        Assert.Empty(harness.Audit.Records);
    }

    [Fact]
    public async Task AServiceDecisionContinuesToTheOwnerOnceWithTheSameRequest()
    {
        var harness = new DecisionHarness();
        var pipeline = harness.Pipeline(Options);
        var request = harness.Request().Build();
        var service = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);
        Assert.True(service.Allowed);

        var first = await pipeline.ExecuteDecidedAsync(service, request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        var second = await pipeline.ExecuteDecidedAsync(service, request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.Succeeded, first.Status);
        Assert.Equal(ExecutionStatus.Refused, second.Status);
        Assert.Equal(DecisionReason.S11ServiceDecisionInvalid, second.Decision.Reason);
        Assert.Equal("perm.capability_denied", DecisionHarness.FailureCode(second.Result));
        Assert.Equal(1, harness.OwnerOperation.Calls);
        Assert.Equal(1, harness.Owner.Last is null ? 0 : harness.Log.Count("owner"));
        Assert.Equal(2, harness.Audit.Records.Count);
        var audit = harness.Audit.Records[1];
        Assert.Equal(SecurityAuditKind.Refused, audit.Kind);
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, audit.Point);
        Assert.Equal(DecisionStep.OwnerValidation, audit.FailedStep);
        Assert.Equal("decision.s11.service_decision_invalid", audit.ReasonCode);
    }

    [Fact]
    public async Task ADecisionIsNotSpentByAPresentationThatFailsAnotherCheck()
    {
        var harness = new DecisionHarness();
        var pipeline = harness.Pipeline(Options);
        var request = harness.Request().Build();
        var other = harness.Request().Build();
        var service = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        var wrong = await pipeline.ExecuteDecidedAsync(service, other, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(DecisionReason.S11ServiceDecisionInvalid, wrong.Decision.Reason);
        Assert.Equal(StepDisposition.NotRun, wrong.Decision.Steps[0].Disposition);
        Assert.Equal(0, harness.OwnerOperation.Calls);

        var right = await pipeline.ExecuteDecidedAsync(service, request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(ExecutionStatus.Succeeded, right.Status);
    }

    [Fact]
    public async Task ARefusedOrForeignServiceDecisionIsNeverContinued()
    {
        var harness = new DecisionHarness();
        var pipeline = harness.Pipeline(Options);
        var foreignPipeline = harness.Pipeline(Options);
        var request = harness.Request().Build();

        harness.Policy.Behavior = (_, _) => ValueTask.FromResult(PolicyVerdict.Disabled);
        var refused = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);
        harness.Policy.Behavior = (_, _) => ValueTask.FromResult(PolicyVerdict.Enabled);
        var foreign = await foreignPipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        var fromRefused = await pipeline.ExecuteDecidedAsync(refused, request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        var fromForeign = await pipeline.ExecuteDecidedAsync(foreign, request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(DecisionReason.S11ServiceDecisionInvalid, fromRefused.Decision.Reason);
        Assert.Equal(DecisionReason.S11ServiceDecisionInvalid, fromForeign.Decision.Reason);
        Assert.Equal(0, harness.OwnerOperation.Calls);
        Assert.Equal(0, harness.Log.Count("owner"));
        Assert.All(fromForeign.Decision.Steps.Take(10), step => Assert.Equal(StepDisposition.NotRun, step.Disposition));
    }

    [Fact]
    public async Task AServiceDecisionIsStaleAtExactlyItsLifetimeOnTheMonotonicClock()
    {
        var harness = new DecisionHarness();
        var pipeline = harness.Pipeline(Options);
        var request = harness.Request().Build();
        var fresh = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);
        var stale = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        harness.Clock.Advance(Lifetime - TimeSpan.FromTicks(1));
        var justInTime = await pipeline.ExecuteDecidedAsync(fresh, request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        harness.Clock.Advance(TimeSpan.FromTicks(1));
        var late = await pipeline.ExecuteDecidedAsync(stale, request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.Succeeded, justInTime.Status);
        Assert.Equal(ExecutionStatus.Refused, late.Status);
        Assert.Equal(DecisionReason.S11ServiceDecisionStale, late.Decision.Reason);
        Assert.Equal("decision.s11.service_decision_stale", late.Decision.ReasonCode);
        Assert.Equal("perm.capability_denied", late.Decision.RegisteredCode);
        Assert.All(late.Decision.Steps.Take(10), step => Assert.True(step.Disposition is StepDisposition.Passed or StepDisposition.NotRequired));
        Assert.Equal(1, harness.OwnerOperation.Calls);
    }

    [Fact]
    public async Task AWallClockStepBackNeverExtendsAServiceDecisionAndAStepForwardShortensIt()
    {
        var back = new DecisionHarness();
        var backPipeline = back.Pipeline(Options);
        var backRequest = back.Request().Build();
        var backDecision = await backPipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, backRequest, TestContext.Current.CancellationToken);
        back.Clock.Advance(Lifetime);
        back.Clock.StepWallClock(-Lifetime);
        var afterStepBack = await backPipeline.ExecuteDecidedAsync(backDecision, backRequest, back.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(DecisionReason.S11ServiceDecisionStale, afterStepBack.Decision.Reason);

        var forward = new DecisionHarness();
        var forwardPipeline = forward.Pipeline(Options);
        var forwardRequest = forward.Request().Build();
        var forwardDecision = await forwardPipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, forwardRequest, TestContext.Current.CancellationToken);
        forward.Clock.StepWallClock(Lifetime);
        var afterStepForward = await forwardPipeline.ExecuteDecidedAsync(forwardDecision, forwardRequest, forward.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(DecisionReason.S11ServiceDecisionStale, afterStepForward.Decision.Reason);
        Assert.Equal(0, back.OwnerOperation.Calls + forward.OwnerOperation.Calls);
    }

    [Fact]
    public async Task OnlyOneOfManyConcurrentContinuationsOfOneDecisionRuns()
    {
        var harness = new DecisionHarness();
        var pipeline = harness.Pipeline(Options);
        var request = harness.Request().Build();
        var service = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        var runs = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ => Task.Run(
            async () => await pipeline.ExecuteDecidedAsync(service, request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken),
            TestContext.Current.CancellationToken)));

        Assert.Equal(1, runs.Count(run => run.Status == ExecutionStatus.Succeeded));
        Assert.Equal(23, runs.Count(run => run.Decision.Reason == DecisionReason.S11ServiceDecisionInvalid));
        Assert.Equal(1, harness.OwnerOperation.Calls);
        Assert.Equal(1, harness.Log.Count("owner"));
    }

    [Fact]
    public async Task OneInstanceServesManyConcurrentRequestsWithoutSharingState()
    {
        var harness = new DecisionHarness();
        var pipeline = harness.Pipeline();

        var runs = await Task.WhenAll(Enumerable.Range(0, 40).Select(_ => Task.Run(async () =>
        {
            var request = harness.Request().Build();
            return await pipeline.ExecuteAsync(request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        }, TestContext.Current.CancellationToken)));

        Assert.All(runs, run => Assert.Equal(ExecutionStatus.Succeeded, run.Status));
        Assert.Equal(40, harness.OwnerOperation.Calls);
        Assert.Equal(40, harness.Recorder.Records.Count);
        Assert.Equal(40, harness.Audit.Records.Count);
        Assert.Equal(40, harness.Audit.Records.Select(record => record.Correlation).Distinct().Count());
    }

    [Fact]
    public async Task TheOwnersValidationReceivesTheRequestRiskAndServiceDecision()
    {
        var harness = new DecisionHarness("R2");
        var request = harness.Request().Build();

        var execution = await harness.Pipeline().ExecuteAsync(request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.Succeeded, execution.Status);
        var seen = harness.Owner.Last!;
        Assert.Same(request, seen.Request);
        Assert.Equal(RiskLevel.R2, seen.Risk!.EffectiveRisk);
        Assert.Equal(EnforcementPoint.ServiceDecision, seen.ServiceDecision!.Point);
        Assert.Same(seen.ServiceDecision.Risk, seen.Risk);
    }

    [Fact]
    public async Task AnOwnerRefusalAfterAnAllowedServiceDecisionStillRunsNothingElse()
    {
        var harness = new DecisionHarness();
        harness.Owner.Behavior = (_, _) => ValueTask.FromResult(OwnerVerdict.RevisionChanged);

        var execution = await harness.Pipeline().ExecuteAsync(harness.Request().Build(), harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.Refused, execution.Status);
        Assert.Equal(DecisionReason.S11OwnerRevisionChanged, execution.Decision.Reason);
        Assert.Equal("conflict.revision_mismatch", DecisionHarness.FailureCode(execution.Result));
        Assert.Equal(EffectCertainty.DidNotHappen, execution.Effect);
        Assert.All(execution.Decision.Steps.Take(10), step => Assert.True(step.Disposition is StepDisposition.Passed or StepDisposition.NotRequired));
        Assert.Equal(0, harness.OwnerOperation.Calls);
        Assert.Empty(harness.Recorder.Records);
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, harness.Audit.Records.Single().Point);
    }

    [Fact]
    public async Task AuthorizationOutcomeMapsServiceAndOwnerDecisionsAndRefusesEarlierPoints()
    {
        var harness = new DecisionHarness();
        var pipeline = harness.Pipeline();
        var request = harness.Request().Build();

        var allowed = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);
        Assert.True(allowed.ToAuthorizationOutcome().TryGetValue(out var yes));
        Assert.True(yes);
        var owner = await pipeline.EvaluateAsync(EnforcementPoint.OwnerFinalValidation, request, TestContext.Current.CancellationToken);
        Assert.True(owner.ToAuthorizationOutcome().TryGetValue(out var ownerYes));
        Assert.True(ownerYes);

        harness.Resources.Behavior = (_, _) => ValueTask.FromResult<ResourceVerdict?>(new ResourceVerdict(ResourceDisposition.Denied, RiskFacts.None));
        var refused = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);
        Assert.Equal("perm.resource_denied", DecisionHarness.FailureCode(refused.ToAuthorizationOutcome()));

        harness.Owner.Behavior = (_, _) => ValueTask.FromResult(OwnerVerdict.Refused);
        var ownerRefused = await pipeline.EvaluateAsync(EnforcementPoint.OwnerFinalValidation, request, TestContext.Current.CancellationToken);
        Assert.Equal("perm.resource_denied", DecisionHarness.FailureCode(ownerRefused.ToAuthorizationOutcome()));

        foreach (var point in new[] { EnforcementPoint.CallerPreCheck, EnforcementPoint.TransportBoundary })
        {
            var early = await pipeline.EvaluateAsync(point, request, TestContext.Current.CancellationToken);
            _ = Assert.Throws<InvalidOperationException>(() => early.ToAuthorizationOutcome());
        }
    }
}
