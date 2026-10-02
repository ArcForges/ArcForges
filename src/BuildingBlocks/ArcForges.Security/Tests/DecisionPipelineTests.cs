// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Approvals;
using ArcForges.Security.Decisions;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>Step coverage, the steps each enforcement point owns, and the bypass proof.</summary>
public sealed class DecisionPipelineTests
{
    private static readonly string[] FullRoute =
        ["catalogue", "policy", "transport", "identity", "scope", "trust", "permission", "resource", "owner", "owner-op", "record", "audit"];

    [Fact]
    public async Task EveryOfTheFourteenStepsRunsInOrderForAnAllowedExecution()
    {
        var harness = new DecisionHarness();
        var request = harness.Request().Build();

        var execution = await harness.Pipeline().ExecuteAsync(request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.Succeeded, execution.Status);
        Assert.Equal(EffectCertainty.Happened, execution.Effect);
        Assert.Equal("done", Assert.IsType<string>(ValueOf(execution.Result)));
        Assert.Equal(FullRoute, harness.Log.Entries);
        var decision = execution.Decision;
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, decision.Point);
        Assert.True(decision.Allowed);
        Assert.True(decision.IsAuthority);
        Assert.Equal(DecisionStep.None, decision.FailedStep);
        Assert.Equal(DecisionReason.None, decision.Reason);
        Assert.Equal(string.Empty, decision.ReasonCode);
        Assert.Equal(string.Empty, decision.RegisteredCode);
        Assert.Equal(DecisionAuditStatus.Written, decision.Audit);
        Assert.Equal(14, decision.Steps.Count);
        var expected = new[]
        {
            StepDisposition.Passed, StepDisposition.Passed, StepDisposition.Passed, StepDisposition.Passed, StepDisposition.Passed,
            StepDisposition.Passed, StepDisposition.Passed, StepDisposition.NotRequired, StepDisposition.Passed, StepDisposition.NotRequired,
            StepDisposition.Passed, StepDisposition.Passed, StepDisposition.Passed, StepDisposition.Passed,
        };
        for (var index = 0; index < 14; index++)
        {
            Assert.Equal((DecisionStep)(index + 1), decision.Steps[index].Step);
            Assert.Equal(expected[index], decision.Steps[index].Disposition);
            Assert.Equal(DecisionReason.None, decision.Steps[index].Reason);
        }

        Assert.Equal(RiskLevel.R1, decision.Risk!.EffectiveRisk);
        Assert.Equal(PermissionDisposition.Granted, decision.Permission!.Disposition);
        Assert.Equal(TransportKind.InProcess, decision.Transport!.Kind);

        var record = Assert.Single(harness.Recorder.Records);
        Assert.Equal(request.CommandId, record.CommandId);
        Assert.Equal(DecisionHarness.DefaultCapability, record.CapabilityKey);
        Assert.Equal(request.Resource, record.Resource);
        Assert.Equal(RiskLevel.R1, record.EffectiveRisk);
        Assert.Equal(DecisionResultKind.Success, record.Result);
        Assert.Null(record.FailureCode);
        Assert.Equal(EffectCertainty.Happened, record.Effect);
        Assert.Equal(harness.Clock.Clock.GetCurrentInstant(), record.RecordedAt);

        var audit = Assert.Single(harness.Audit.Records);
        Assert.Equal(SecurityAuditKind.Executed, audit.Kind);
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, audit.Point);
        Assert.Equal(DecisionStep.None, audit.FailedStep);
        Assert.Equal(string.Empty, audit.ReasonCode);
        Assert.Equal(string.Empty, audit.RegisteredCode);
        Assert.Equal(harness.Clock.Clock.GetCurrentInstant(), audit.OccurredAt);
        Assert.Same(request.Actors, audit.Actors);
        Assert.Equal(request.Actors.CallerInstance, audit.Executor);
        Assert.Null(audit.SoftwareIdentity);
        Assert.Equal(DecisionHarness.DefaultCapability, audit.CapabilityKey);
        Assert.Equal(request.Resource, audit.Resource);
        Assert.Equal(RiskLevel.R1, audit.EffectiveRisk);
        Assert.Equal(DecisionOrigin.Local, audit.Origin);
        Assert.Equal(request.Actors.Device, audit.Device);
        Assert.Equal(request.Scope, audit.Scope);
        Assert.Equal(request.CommandId, audit.Correlation);
        Assert.Equal(EffectCertainty.Happened, audit.Effect);
    }

    [Fact]
    public async Task AnEscalatedRequestAlsoRunsTheDataBoundaryAndApprovalAndStepUpSteps()
    {
        var harness = new DecisionHarness();
        harness.Descriptor = DecisionHarness.Describe(DecisionHarness.DefaultCapability, "R2", "perOperation", "ownedContent");
        var builder = harness.Request().WithActors(ActorKind.Agent);
        builder.EgressDestination = "owned.helper/1";
        builder.SecretUseKey = "secret-ref-1";
        builder.Operation = SensitiveOperation.ChangeEmail;
        builder.ApprovalId = await harness.ApproveAsync(builder.Build(), RiskLevel.R2);
        builder.Proof = await harness.ProofAsync(builder.Build(), SensitiveOperation.ChangeEmail, RiskLevel.R2);
        var request = builder.Build();

        var execution = await harness.Pipeline().ExecuteAsync(request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.Succeeded, execution.Status);
        Assert.Equal(
            ["catalogue", "policy", "transport", "identity", "scope", "trust", "permission", "resource", "secret", "egress", "owner", "owner-op", "record", "audit"],
            harness.Log.Entries);
        Assert.Equal(StepDisposition.Passed, execution.Decision.Steps[7].Disposition);
        Assert.Equal(StepDisposition.Passed, execution.Decision.Steps[9].Disposition);
        Assert.Equal("owned.helper/1", harness.DataBoundary.LastDestination);
        Assert.Equal(RiskLevel.R2, execution.Decision.Risk!.EffectiveRisk);
        Assert.Equal(request.Actors.Actors[0].Executor, Assert.Single(harness.Audit.Records).Executor);
        Assert.Equal("owned.software/1", Assert.Single(harness.Audit.Records).SoftwareIdentity);

        // The step-up proof was spent by the decision.
        Assert.False(harness.StepUp.TryConsume(request.StepUpProof!, request.Actors.Owner, request.CommandId, SensitiveOperation.ChangeEmail, DecisionHarness.AssessmentOf(RiskLevel.R2)));
    }

    [Fact]
    public async Task TheCallerPreCheckRunsOnlyItsStepsIsAdvisoryAndWritesNothing()
    {
        var harness = new DecisionHarness();

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.CallerPreCheck, harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.Equal(EnforcementPoint.CallerPreCheck, decision.Point);
        Assert.True(decision.Allowed);
        Assert.False(decision.IsAuthority);
        Assert.Equal(["catalogue", "policy", "transport", "identity", "scope", "trust", "permission"], harness.Log.Entries);
        AssertRan(decision, 1, 2, 3, 4, 5, 6, 9);
        Assert.NotNull(decision.Permission);
        Assert.Equal(PermissionDisposition.Granted, decision.Permission.Disposition);
        Assert.NotNull(decision.Risk);
        Assert.Equal(DecisionAuditStatus.NotDue, decision.Audit);
        Assert.Empty(harness.Audit.Records);
    }

    [Fact]
    public async Task ARefusedCallerPreCheckIsNotAuditedButNamesItsStep()
    {
        var harness = new DecisionHarness();
        harness.Policy.Behavior = (_, _) => ValueTask.FromResult(PolicyVerdict.Disabled);

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.CallerPreCheck, harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.False(decision.Allowed);
        Assert.False(decision.IsAuthority);
        Assert.Equal(DecisionStep.ProductPolicy, decision.FailedStep);
        Assert.Equal(DecisionReason.S02PolicyDisabled, decision.Reason);
        Assert.Equal(DecisionAuditStatus.NotDue, decision.Audit);
        Assert.Empty(harness.Audit.Records);
        Assert.Equal(StepDisposition.NotRun, decision.Steps[13].Disposition);
    }

    [Fact]
    public async Task TheTransportBoundaryRunsActorIdentityAndSoftwareTrustAndNothingElse()
    {
        var harness = new DecisionHarness();

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.TransportBoundary, harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.Equal(EnforcementPoint.TransportBoundary, decision.Point);
        Assert.True(decision.Allowed);
        Assert.True(decision.IsAuthority);
        Assert.Equal(["transport", "identity", "trust"], harness.Log.Entries);
        AssertRan(decision, 3, 5);
        Assert.NotNull(decision.Transport);
        Assert.Same(decision.Transport, harness.Trust.LastBinding);
        Assert.Null(decision.Risk);
        Assert.Null(decision.Permission);
        Assert.Equal(DecisionAuditStatus.NotDue, decision.Audit);
    }

    [Fact]
    public async Task ARefusedTransportBoundaryIsAudited()
    {
        var harness = new DecisionHarness();
        harness.Transport.Behavior = _ => ValueTask.FromResult(new TransportVerdict(TransportRefusal.Revoked, null));

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.TransportBoundary, harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.False(decision.Allowed);
        Assert.Equal(DecisionReason.S03TransportRefused, decision.Reason);
        Assert.Equal(DecisionAuditStatus.Written, decision.Audit);
        var audit = Assert.Single(harness.Audit.Records);
        Assert.Equal(EnforcementPoint.TransportBoundary, audit.Point);
        Assert.Equal(DecisionStep.ActorIdentity, audit.FailedStep);
        Assert.Equal(["transport", "audit"], harness.Log.Entries);
    }

    [Fact]
    public async Task TheServiceDecisionRunsTenStepsAndDoesNotRunTheOwnerOrExecute()
    {
        var harness = new DecisionHarness();

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.Equal(EnforcementPoint.ServiceDecision, decision.Point);
        Assert.True(decision.Allowed);
        Assert.True(decision.IsAuthority);
        Assert.Equal(FullRoute.Take(8), harness.Log.Entries);
        AssertRan(decision, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        Assert.Equal(StepDisposition.NotRequired, decision.Steps[7].Disposition);
        Assert.Equal(StepDisposition.NotRequired, decision.Steps[9].Disposition);
        Assert.Equal(DecisionAuditStatus.NotDue, decision.Audit);
        Assert.Empty(harness.Audit.Records);
        Assert.Equal(0, harness.OwnerOperation.Calls);
    }

    [Fact]
    public async Task TheOwnerPointRunsOnlyTheOwnersFinalValidationAndAuditsItsRefusal()
    {
        var harness = new DecisionHarness();
        var request = harness.Request().Build();

        var allowed = await harness.Pipeline().EvaluateAsync(EnforcementPoint.OwnerFinalValidation, request, TestContext.Current.CancellationToken);

        Assert.True(allowed.Allowed);
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, allowed.Point);
        Assert.Equal(["owner"], harness.Log.Entries);
        AssertRan(allowed, 11);
        Assert.Same(request, harness.Owner.Last!.Request);
        Assert.Null(harness.Owner.Last.Risk);
        Assert.Null(harness.Owner.Last.ServiceDecision);
        Assert.Empty(harness.Audit.Records);

        harness.Owner.Behavior = (_, _) => ValueTask.FromResult(OwnerVerdict.Refused);
        var refused = await harness.Pipeline().EvaluateAsync(EnforcementPoint.OwnerFinalValidation, request, TestContext.Current.CancellationToken);
        Assert.False(refused.Allowed);
        Assert.Equal(DecisionStep.OwnerValidation, refused.FailedStep);
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, Assert.Single(harness.Audit.Records).Point);
    }

    [Fact]
    public void EachPointOwnsAnOrderedSetOfDecisionSteps()
    {
        Assert.Equal(
            [DecisionStep.CapabilityExists, DecisionStep.ProductPolicy, DecisionStep.ActorIdentity, DecisionStep.ScopeValid, DecisionStep.TrustEligible, DecisionStep.CapabilityPermission, DecisionStep.EffectiveRisk],
            DecisionProfiles.StepsFor(EnforcementPoint.CallerPreCheck));
        Assert.Equal([DecisionStep.ActorIdentity, DecisionStep.TrustEligible], DecisionProfiles.StepsFor(EnforcementPoint.TransportBoundary));
        Assert.Equal(Enumerable.Range(1, 10).Select(value => (DecisionStep)value), DecisionProfiles.StepsFor(EnforcementPoint.ServiceDecision));
        Assert.Equal([DecisionStep.OwnerValidation], DecisionProfiles.StepsFor(EnforcementPoint.OwnerFinalValidation));
        foreach (var point in new[] { EnforcementPoint.CallerPreCheck, EnforcementPoint.TransportBoundary, EnforcementPoint.ServiceDecision, EnforcementPoint.OwnerFinalValidation })
        {
            var steps = DecisionProfiles.StepsFor(point);
            Assert.Equal(steps.OrderBy(step => (int)step), steps);
            Assert.All(steps, step => Assert.True(step <= DecisionStep.OwnerValidation));
            if (steps.Contains(DecisionStep.EffectiveRisk))
            {
                // Risk needs the catalogue's descriptor and the package trust that raises it.
                Assert.Contains(DecisionStep.CapabilityExists, steps);
                Assert.Contains(DecisionStep.TrustEligible, steps);
            }
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => DecisionProfiles.StepsFor(EnforcementPoint.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => DecisionProfiles.StepsFor((EnforcementPoint)9));
    }

    [Fact]
    public async Task InvalidPointsAndMissingArgumentsAreProgrammingErrors()
    {
        var harness = new DecisionHarness();
        var pipeline = harness.Pipeline();
        var request = harness.Request().Build();
        _ = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await pipeline.EvaluateAsync(EnforcementPoint.None, request, TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await pipeline.EvaluateAsync((EnforcementPoint)7, request, TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, null!, TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await pipeline.ExecuteAsync<string>(null!, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await pipeline.ExecuteAsync<string>(request, null!, TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await pipeline.ExecuteDecidedAsync<string>(null!, request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await pipeline.ProjectPermissionAsync(null!, TestContext.Current.CancellationToken));
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, cancelled.Token));
        Assert.Empty(harness.Log.Entries);
    }

    [Fact]
    [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "This offline test inspects the assembly's own public surface by reflection and is never trimmed.")]
    [UnconditionalSuppressMessage("Trimming", "IL2075", Justification = "This offline test inspects the assembly's own public surface by reflection and is never trimmed.")]
    public async Task TheExecutionTicketCannotBeMadeOrObtainedOutsideThePipeline()
    {
        var ticketType = typeof(AuthorizedExecution);
        Assert.True(ticketType.IsSealed);
        Assert.Empty(ticketType.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(ticketType.GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance), constructor => constructor.IsFamily || constructor.IsFamilyOrAssembly || constructor.IsPublic);
        Assert.Empty(ticketType.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.DoesNotContain(ticketType.GetProperties(BindingFlags.Public | BindingFlags.Instance), property => property.SetMethod is { IsPublic: true });
        Assert.Empty(ticketType.GetFields(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static));
        Assert.False(ticketType.IsAssignableTo(typeof(System.Runtime.Serialization.ISerializable)));

        // No public member of the assembly returns, exposes or builds a ticket; the only place that names it is the owner operation's parameter.
        var offenders = new List<string>();
        foreach (var type in ticketType.Assembly.GetExportedTypes().Where(type => type != ticketType))
        {
            foreach (var member in type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                var exposed = member switch
                {
                    MethodBase method when typeof(Delegate).IsAssignableFrom(type) => [],
                    MethodInfo method => new[] { method.ReturnType },
                    PropertyInfo property => [property.PropertyType],
                    FieldInfo field => [field.FieldType],
                    _ => [],
                };
                if (exposed.Any(Mentions))
                {
                    offenders.Add(type.FullName + "." + member.Name);
                }
            }
        }

        Assert.Empty(offenders);

        // The only route that hands one out passes it to the owner operation, and only after the owner validated.
        var harness = new DecisionHarness();
        var request = harness.Request().Build();
        var execution = await harness.Pipeline().ExecuteAsync(request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(ExecutionStatus.Succeeded, execution.Status);
        var ticket = harness.OwnerOperation.LastTicket!;
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, ticket.Decision.Point);
        Assert.True(ticket.Decision.Allowed);
        for (var index = 0; index < 11; index++)
        {
            Assert.True(ticket.Decision.Steps[index].Disposition is StepDisposition.Passed or StepDisposition.NotRequired);
        }

        for (var index = 11; index < 14; index++)
        {
            Assert.Equal(StepDisposition.NotRun, ticket.Decision.Steps[index].Disposition);
        }

        Assert.Same(request.Actors, ticket.Actors);
        Assert.Equal(DecisionHarness.DefaultCapability, ticket.CapabilityKey);
        Assert.Equal(request.Resource, ticket.Resource);
        Assert.Equal(RiskLevel.R1, ticket.Risk.EffectiveRisk);
        Assert.NotSame(ticket.Decision, execution.Decision);
    }

    [Fact]
    public async Task TheOwnerOperationRunsAfterTheOwnersValidationAndNeverBefore()
    {
        var harness = new DecisionHarness();
        harness.Owner.Behavior = async (_, token) =>
        {
            await Task.Yield();
            Assert.Equal(0, harness.OwnerOperation.Calls);
            return OwnerVerdict.Valid;
        };

        var request = harness.Request().Build();
        var execution = await harness.Pipeline().ExecuteAsync(request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.Succeeded, execution.Status);
        Assert.True(harness.Log.Entries.ToList().IndexOf("owner") < harness.Log.Entries.ToList().IndexOf("owner-op"));
        Assert.Equal(1, harness.OwnerOperation.Calls);
        var validation = harness.Owner.Last!;
        Assert.Same(request, validation.Request);
        Assert.Equal(EnforcementPoint.ServiceDecision, validation.ServiceDecision!.Point);
        Assert.Equal(RiskLevel.R1, validation.Risk!.EffectiveRisk);
    }

    [Fact]
    public async Task OneAllowedServiceDecisionAtAnEarlierPointNeverAuthorizesTheOwnersOperation()
    {
        // Only a decision from this pipeline's service point can continue to execution; earlier points cannot.
        var harness = new DecisionHarness();
        var pipeline = harness.Pipeline();
        var request = harness.Request().Build();
        foreach (var point in new[] { EnforcementPoint.CallerPreCheck, EnforcementPoint.TransportBoundary, EnforcementPoint.OwnerFinalValidation })
        {
            var early = await pipeline.EvaluateAsync(point, request, TestContext.Current.CancellationToken);
            Assert.True(early.Allowed);
            var execution = await pipeline.ExecuteDecidedAsync(early, request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);
            Assert.Equal(ExecutionStatus.Refused, execution.Status);
            Assert.Equal(DecisionReason.S11ServiceDecisionInvalid, execution.Decision.Reason);
        }

        Assert.Equal(0, harness.OwnerOperation.Calls);
    }

    private static object? ValueOf<T>(Outcome<T> outcome)
    {
        Assert.True(outcome.TryGetValue(out var value));
        return value;
    }

    private static bool Mentions(Type type) =>
        type == typeof(AuthorizedExecution) || type.IsGenericType && type.GetGenericArguments().Any(Mentions)
        || type.HasElementType && type.GetElementType() is { } element && Mentions(element);

    private static void AssertRan(SecurityDecision decision, params int[] steps)
    {
        for (var index = 0; index < 14; index++)
        {
            var disposition = decision.Steps[index].Disposition;
            if (steps.Contains(index + 1))
            {
                Assert.True(disposition is StepDisposition.Passed or StepDisposition.NotRequired, $"step {index + 1} should have run");
            }
            else
            {
                Assert.Equal(StepDisposition.NotRun, disposition);
            }
        }
    }
}
