// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Security.Approvals;
using ArcForges.Security.Decisions;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>Effective risk across the actor chain, resource and trust facts, and the approval, step-up and presence requirements that follow from it.</summary>
public sealed class DecisionRiskAndApprovalTests
{
    private const string Capability = DecisionHarness.DefaultCapability;

    private static async Task<SecurityDecision> PreCheckAsync(DecisionHarness harness, DecisionRequest request) =>
        await harness.Pipeline().EvaluateAsync(EnforcementPoint.CallerPreCheck, request, TestContext.Current.CancellationToken);

    private static async Task<SecurityDecision> ServiceAsync(DecisionHarness harness, DecisionRequest request) =>
        await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

    [Fact]
    public async Task TheMostSevereActorOfTheChainDecidesWhateverItsPosition()
    {
        foreach (var kinds in new[] { new[] { ActorKind.Extension, ActorKind.Agent }, [ActorKind.Agent, ActorKind.Extension], [ActorKind.Agent, ActorKind.Agent, ActorKind.Extension] })
        {
            var harness = new DecisionHarness();
            var decision = await PreCheckAsync(harness, harness.Request().WithActors(kinds).Build());

            Assert.Equal(RiskLevel.R3, decision.Risk!.EffectiveRisk);
            Assert.Contains(decision.Risk.Adjustments, adjustment => adjustment.Modifier == RiskModifier.ExtensionActor);
        }
    }

    [Fact]
    public async Task EqualActorRisksKeepTheFirstActorsExplanation()
    {
        var harness = new DecisionHarness();

        var decision = await PreCheckAsync(harness, harness.Request().WithActors(ActorKind.Automation, ActorKind.Agent).Build());

        Assert.Equal(RiskLevel.R2, decision.Risk!.EffectiveRisk);
        Assert.Contains(decision.Risk.Adjustments, adjustment => adjustment.Modifier == RiskModifier.AutomationActor);
        Assert.DoesNotContain(decision.Risk.Adjustments, adjustment => adjustment.Modifier == RiskModifier.AgentActor);
    }

    [Fact]
    public async Task ADirectHumanActionHasNoActorFloorAndTheBaselineIsNeverLowered()
    {
        var harness = new DecisionHarness("R3", "perOperation");

        var decision = await ServiceAsync(harness, harness.Request().Build());

        Assert.Equal(RiskLevel.R3, decision.Risk!.CapabilityRisk);
        Assert.Equal(RiskLevel.R3, decision.Risk.EffectiveRisk);
        Assert.Empty(decision.Risk.Adjustments);
    }

    [Fact]
    public async Task AutomationWithExternalEgressIsCriticalEvenBeforeTheDataBoundaryStepRuns()
    {
        var harness = new DecisionHarness();
        harness.Descriptor = DecisionHarness.Describe(Capability, "R1", "none", "webSearch");

        var decision = await PreCheckAsync(harness, harness.Request().WithActors(ActorKind.Automation).Build());

        Assert.Equal(RiskLevel.R4, decision.Risk!.EffectiveRisk);
        Assert.Contains(decision.Risk.Adjustments, adjustment => adjustment.Modifier == RiskModifier.ExternalEgress);
        Assert.Contains(decision.Risk.Adjustments, adjustment => adjustment.Modifier == RiskModifier.AutomationWithExternalEgress);
    }

    [Theory]
    [InlineData("none", false)]
    [InlineData("ownedContent", false)]
    [InlineData("webSearch", true)]
    [InlineData("some-new-destination-class", true)]
    public async Task OnlyEgressBeyondTheOwnedBoundaryRaisesRisk(string egress, bool raises)
    {
        var harness = new DecisionHarness();
        harness.Descriptor = DecisionHarness.Describe(Capability, "R1", "none", egress);

        var decision = await PreCheckAsync(harness, harness.Request().Build());

        Assert.Equal(raises, decision.Risk!.Adjustments.Any(adjustment => adjustment.Modifier == RiskModifier.ExternalEgress));
        Assert.Equal(raises ? RiskLevel.R3 : RiskLevel.R1, decision.Risk.EffectiveRisk);
    }

    [Fact]
    public async Task ADescriptorThatDeclaresNoEgressPostureIsTreatedAsExternal()
    {
        var harness = new DecisionHarness();
        harness.Descriptor = new CapabilityDescriptor { Key = Capability, Risk = "R1", Approval = "none" };

        var decision = await PreCheckAsync(harness, harness.Request().Build());

        Assert.Equal(RiskLevel.R3, decision.Risk!.EffectiveRisk);
        Assert.Contains(decision.Risk.Adjustments, adjustment => adjustment.Modifier == RiskModifier.ExternalEgress);
    }

    [Fact]
    public async Task ARemoteOriginRaisesRiskToTheRemoteFloor()
    {
        var harness = new DecisionHarness();
        var builder = harness.Request();
        builder.Origin = DecisionOrigin.Remote;

        var decision = await PreCheckAsync(harness, builder.Build());

        Assert.Equal(RiskLevel.R3, decision.Risk!.EffectiveRisk);
        Assert.Contains(decision.Risk.Adjustments, adjustment => adjustment.Modifier == RiskModifier.RemoteOrigin);
    }

    [Theory]
    [InlineData(TrustVerdict.Verified, false, RiskLevel.R1)]
    [InlineData(TrustVerdict.Unverified, true, RiskLevel.R3)]
    public async Task AnUnverifiedPackageRaisesRiskAndAVerifiedOneDoesNot(TrustVerdict verdict, bool raises, RiskLevel effective)
    {
        var harness = new DecisionHarness();
        harness.Trust.Behavior = (_, _) => ValueTask.FromResult(verdict);

        var decision = await PreCheckAsync(harness, harness.Request().Build());

        Assert.True(decision.Allowed);
        Assert.Equal(raises, decision.Risk!.Adjustments.Any(adjustment => adjustment.Modifier == RiskModifier.UnverifiedPackage));
        Assert.Equal(effective, decision.Risk.EffectiveRisk);
    }

    [Fact]
    public async Task DeclaredAndOwnerEstablishedFactsAreCombinedAndCanOnlyRaiseRisk()
    {
        var harness = new DecisionHarness();
        harness.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
        var builder = harness.Request();
        builder.Facts = new RiskFacts(RiskScope.Bulk, RiskTarget.Ordinary, RiskReversibility.Reversible, false);
        harness.Resources.Behavior = (_, _) => ValueTask.FromResult<ResourceVerdict?>(new ResourceVerdict(
            ResourceDisposition.Authorized, new RiskFacts(RiskScope.SingleOperation, RiskTarget.SensitiveResource, RiskReversibility.Irreversible, true)));

        var decision = await ServiceAsync(harness, builder.Build());

        var modifiers = decision.Risk!.Adjustments.Select(adjustment => adjustment.Modifier).ToArray();
        Assert.Contains(RiskModifier.BulkScope, modifiers);
        Assert.Contains(RiskModifier.SensitiveResource, modifiers);
        Assert.Contains(RiskModifier.IrreversibleEffect, modifiers);
        Assert.Contains(RiskModifier.LargeDataVolume, modifiers);
        Assert.Equal(RiskLevel.R4, decision.Risk.EffectiveRisk);
        Assert.Equal(DecisionReason.S10ApprovalRequired, decision.Reason);

        // An owner that reports less severe facts cannot lower what the caller declared.
        var lowered = new DecisionHarness();
        lowered.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
        var loweredBuilder = lowered.Request();
        loweredBuilder.Facts = new RiskFacts(RiskScope.Bulk, RiskTarget.SensitiveResource, RiskReversibility.Irreversible, true);
        var loweredDecision = await ServiceAsync(lowered, loweredBuilder.Build());
        Assert.Equal(RiskLevel.R4, loweredDecision.Risk!.EffectiveRisk);
        Assert.Equal(4, loweredDecision.Risk.Adjustments.Count(adjustment => adjustment.Modifier is RiskModifier.BulkScope or RiskModifier.SensitiveResource or RiskModifier.IrreversibleEffect or RiskModifier.LargeDataVolume));
    }

    [Fact]
    public async Task TheDescriptorIsReadOnceSoALaterChangeToTheCataloguesCopyCannotLowerRisk()
    {
        var harness = new DecisionHarness("R3", "perOperation");
        harness.Policy.Behavior = (_, _) =>
        {
            harness.Descriptor.Risk = "R0";
            harness.Descriptor.Approval = "none";
            return ValueTask.FromResult(PolicyVerdict.Enabled);
        };

        var decision = await ServiceAsync(harness, harness.Request().Build());

        Assert.Equal(RiskLevel.R3, decision.Risk!.CapabilityRisk);
        Assert.Equal(DecisionReason.S10ApprovalRequired, decision.Reason);
    }

    [Fact]
    public async Task AnApprovedActionPassesTheApprovalStep()
    {
        var harness = new DecisionHarness("R1", "perOperation");
        var builder = harness.Request();
        builder.ApprovalId = await harness.ApproveAsync(builder.Build(), RiskLevel.R1);

        var decision = await ServiceAsync(harness, builder.Build());

        Assert.True(decision.Allowed);
        Assert.Equal(StepDisposition.Passed, decision.Steps[9].Disposition);
    }

    [Fact]
    public async Task AnApprovalIsUsableUntilTheInstantBeforeItsExpiry()
    {
        var harness = new DecisionHarness("R1", "perOperation");
        var builder = harness.Request();
        builder.ApprovalId = await harness.ApproveAsync(builder.Build(), RiskLevel.R1, lifetime: TimeSpan.FromMinutes(5));
        harness.Clock.Advance(TimeSpan.FromMinutes(5) - TimeSpan.FromTicks(1));

        var decision = await ServiceAsync(harness, builder.Build());

        Assert.True(decision.Allowed);
    }

    [Fact]
    public async Task ARemoteRequestMayUseARemoteApprovalBelowTheHighestRisk()
    {
        var harness = new DecisionHarness("R1", "perOperation");
        var builder = harness.Request();
        builder.Origin = DecisionOrigin.Remote;
        builder.ApprovalId = await harness.ApproveAsync(builder.Build(), RiskLevel.R3, origin: ApprovalOrigin.Remote);

        var decision = await ServiceAsync(harness, builder.Build());

        Assert.True(decision.Allowed);
        Assert.Equal(RiskLevel.R3, decision.Risk!.EffectiveRisk);
    }

    [Fact]
    public async Task TheHighestRiskPassesOnlyWithAnApprovalAFreshStepUpAndLocalPresenceAndSpendsTheProof()
    {
        var harness = new DecisionHarness("R4", "none");
        var builder = harness.Request();
        builder.Operation = SensitiveOperation.DeleteAccount;
        builder.ApprovalId = await harness.ApproveAsync(builder.Build(), RiskLevel.R4);
        builder.Proof = await harness.ProofAsync(builder.Build(), SensitiveOperation.DeleteAccount, RiskLevel.R4);
        var request = builder.Build();
        Assert.True(request.StepUpProof!.LocalPresenceConfirmed);

        var first = await ServiceAsync(harness, request);
        var second = await ServiceAsync(harness, request);

        Assert.True(first.Allowed);
        Assert.Equal(StepDisposition.Passed, first.Steps[9].Disposition);
        Assert.Equal(DecisionReason.S10StepUpInvalid, second.Reason);
    }

    [Fact]
    public async Task AnEnumeratedOperationNeedsAStepUpEvenWhenNoApprovalIsRequired()
    {
        var harness = new DecisionHarness();
        var builder = harness.Request();
        builder.Operation = SensitiveOperation.ChangeEmail;
        builder.Proof = await harness.ProofAsync(builder.Build(), SensitiveOperation.ChangeEmail, RiskLevel.R1);

        var decision = await ServiceAsync(harness, builder.Build());

        Assert.True(decision.Allowed);
        Assert.Equal(StepDisposition.Passed, decision.Steps[9].Disposition);
    }

    [Fact]
    public async Task AProofIsSpentOnlyAfterEveryOtherRequirementOfTheStepHolds()
    {
        var harness = new DecisionHarness("R1", "perOperation");
        var builder = harness.Request();
        builder.Operation = SensitiveOperation.ChangeEmail;
        builder.ApprovalId = await harness.ApproveAsync(builder.Build(), RiskLevel.R1);
        var proof = await harness.ProofAsync(builder.Build(), SensitiveOperation.ChangeEmail, RiskLevel.R1);
        builder.Proof = proof;
        builder.Effect = DecisionHarness.Sha('C');
        var request = builder.Build();

        var refused = await ServiceAsync(harness, request);

        Assert.Equal(DecisionReason.S10ApprovalMismatch, refused.Reason);
        Assert.True(harness.StepUp.TryConsume(proof, request.Actors.Owner, request.CommandId, SensitiveOperation.ChangeEmail, DecisionHarness.AssessmentOf(RiskLevel.R1)));
    }

    [Fact]
    public async Task AnUnneededApprovalAndAnUnneededProofAreIgnoredAndNeverRead()
    {
        var harness = new DecisionHarness();
        var builder = harness.Request();
        var proof = await harness.ProofAsync(builder.Build(), SensitiveOperation.ChangeEmail, RiskLevel.R1);
        builder.ApprovalId = Guid.NewGuid();
        builder.Proof = proof;
        harness.ApprovalStore.FailReads = true;
        var request = builder.Build();

        var decision = await ServiceAsync(harness, request);

        Assert.True(decision.Allowed);
        Assert.Equal(StepDisposition.NotRequired, decision.Steps[9].Disposition);
        Assert.True(harness.StepUp.TryConsume(proof, request.Actors.Owner, request.CommandId, SensitiveOperation.ChangeEmail, DecisionHarness.AssessmentOf(RiskLevel.R1)));
    }

    [Fact]
    public async Task AProofThatWasSpentBeforeTheOwnerRefusedStaysSpent()
    {
        var harness = new DecisionHarness();
        var builder = harness.Request();
        builder.Operation = SensitiveOperation.ChangeEmail;
        builder.Proof = await harness.ProofAsync(builder.Build(), SensitiveOperation.ChangeEmail, RiskLevel.R1);
        var request = builder.Build();
        harness.Owner.Behavior = (_, _) => ValueTask.FromResult(OwnerVerdict.Refused);

        var execution = await harness.Pipeline().ExecuteAsync(request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.Refused, execution.Status);
        Assert.False(harness.StepUp.TryConsume(request.StepUpProof!, request.Actors.Owner, request.CommandId, SensitiveOperation.ChangeEmail, DecisionHarness.AssessmentOf(RiskLevel.R1)));
    }

    [Fact]
    public async Task TheCallerPreCheckNeverReadsApprovalsOrSpendsAProof()
    {
        var harness = new DecisionHarness("R1", "perOperation");
        var builder = harness.Request();
        builder.Operation = SensitiveOperation.ChangeEmail;
        var proof = await harness.ProofAsync(builder.Build(), SensitiveOperation.ChangeEmail, RiskLevel.R1);
        builder.Proof = proof;
        builder.ApprovalId = await harness.ApproveAsync(builder.Build(), RiskLevel.R1);
        harness.ApprovalStore.FailReads = true;
        var request = builder.Build();

        var decision = await PreCheckAsync(harness, request);

        Assert.True(decision.Allowed);
        Assert.True(harness.StepUp.TryConsume(proof, request.Actors.Owner, request.CommandId, SensitiveOperation.ChangeEmail, DecisionHarness.AssessmentOf(RiskLevel.R1)));
    }
}
