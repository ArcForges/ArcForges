// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using Xunit;

namespace ArcForges.Security.Tests;

public sealed class RiskModelTests
{
    [Fact]
    public void ClassifiesEveryRuntimeModifierCombinationAndExplainsItsRaises()
    {
        var contexts = AllContexts().ToArray();
        Assert.Equal(640, contexts.Length);

        foreach (var context in contexts)
        {
            foreach (var baseline in Enum.GetValues<RiskLevel>())
            {
                var actual = RiskModel.Assess(Descriptor(baseline), context);
                var (expectedRisk, expectedAdjustments) = Expected(context, baseline);

                Assert.Equal(baseline, actual.CapabilityRisk);
                Assert.Equal(expectedRisk, actual.EffectiveRisk);
                Assert.Equal(expectedAdjustments, actual.Adjustments);
            }
        }
    }

    [Fact]
    public void AddingAnyRuntimeModifierNeverLowersEffectiveRisk()
    {
        foreach (var context in AllContexts())
        {
            foreach (var baseline in Enum.GetValues<RiskLevel>())
            {
                var original = RiskModel.Assess(Descriptor(baseline), context).EffectiveRisk;

                if (!context.IsRemoteOrigin)
                {
                    AssertNotLowered(context with { IsRemoteOrigin = true });
                }

                if (context.Scope == RiskScope.SingleOperation)
                {
                    AssertNotLowered(context with { Scope = RiskScope.Bulk });
                }

                if (context.Target == RiskTarget.Ordinary)
                {
                    AssertNotLowered(context with { Target = RiskTarget.SensitiveResource });
                }

                if (context.Reversibility == RiskReversibility.Reversible)
                {
                    AssertNotLowered(context with { Reversibility = RiskReversibility.Irreversible });
                }

                if (context.Egress == RiskEgress.None)
                {
                    AssertNotLowered(context with { Egress = RiskEgress.External });
                }

                if (context.IsPackageVerified)
                {
                    AssertNotLowered(context with { IsPackageVerified = false });
                }

                if (!context.IsLargeDataVolume)
                {
                    AssertNotLowered(context with { IsLargeDataVolume = true });
                }

                if (context.ActorKind == ActorKind.None)
                {
                    foreach (var actorKind in Enum.GetValues<ActorKind>().Where(kind => kind != ActorKind.None))
                    {
                        AssertNotLowered(context with { ActorKind = actorKind });
                    }
                }

                void AssertNotLowered(RiskContext changed)
                {
                    var raised = RiskModel.Assess(Descriptor(baseline), changed).EffectiveRisk;
                    Assert.True((int)raised >= (int)original,
                        $"Adding a modifier lowered {baseline} to {raised} for {context}.");
                }
            }
        }
    }

    [Fact]
    public void AutomationWithExternalEgressExceedsEitherModifierAlone()
    {
        var baseline = Descriptor(RiskLevel.R0);
        var context = DefaultContext();

        var automationOnly = RiskModel.Assess(baseline, context with { ActorKind = ActorKind.Automation }).EffectiveRisk;
        var egressOnly = RiskModel.Assess(baseline, context with { Egress = RiskEgress.External }).EffectiveRisk;
        var combined = RiskModel.Assess(baseline, context with
        {
            ActorKind = ActorKind.Automation,
            Egress = RiskEgress.External,
        }).EffectiveRisk;

        Assert.Equal(RiskLevel.R2, automationOnly);
        Assert.Equal(RiskLevel.R3, egressOnly);
        Assert.Equal(RiskLevel.R4, combined);
        Assert.True((int)combined > (int)automationOnly);
        Assert.True((int)combined > (int)egressOnly);
    }

    [Fact]
    public void SensitiveExternalTransferAndUnverifiedExtensionRequireR4()
    {
        var descriptor = Descriptor(RiskLevel.R0);
        var context = DefaultContext();

        var sensitiveOnly = RiskModel.Assess(descriptor,
            context with { Target = RiskTarget.SensitiveResource }).EffectiveRisk;
        var sensitiveAndExternal = RiskModel.Assess(descriptor, context with
        {
            Target = RiskTarget.SensitiveResource,
            Egress = RiskEgress.External,
        }).EffectiveRisk;
        var externalOnly = RiskModel.Assess(descriptor, context with { Egress = RiskEgress.External }).EffectiveRisk;

        var extensionOnly = RiskModel.Assess(descriptor, context with { ActorKind = ActorKind.Extension }).EffectiveRisk;
        var unverifiedOnly = RiskModel.Assess(descriptor, context with { IsPackageVerified = false }).EffectiveRisk;
        var unverifiedExtension = RiskModel.Assess(descriptor, context with
        {
            ActorKind = ActorKind.Extension,
            IsPackageVerified = false,
        }).EffectiveRisk;

        Assert.Equal(RiskLevel.R2, sensitiveOnly);
        Assert.Equal(RiskLevel.R3, externalOnly);
        Assert.Equal(RiskLevel.R4, sensitiveAndExternal);
        Assert.True((int)sensitiveAndExternal > (int)sensitiveOnly);
        Assert.True((int)sensitiveAndExternal > (int)externalOnly);

        Assert.Equal(RiskLevel.R3, extensionOnly);
        Assert.Equal(RiskLevel.R3, unverifiedOnly);
        Assert.Equal(RiskLevel.R4, unverifiedExtension);
        Assert.True((int)unverifiedExtension > (int)extensionOnly);
        Assert.True((int)unverifiedExtension > (int)unverifiedOnly);
    }

    [Fact]
    public void RejectsUnknownCapabilityRiskAndRuntimeClassifications()
    {
        var context = DefaultContext();
        Assert.Throws<ArgumentNullException>(() => new CapabilityDescriptor { Risk = null! });
        foreach (var malformedRisk in new[] { "", "r0", "R5", " R1", "R1 " })
        {
            var descriptor = new CapabilityDescriptor { Risk = malformedRisk };
            Assert.Throws<ArgumentException>(() => RiskModel.Assess(descriptor, context));
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => RiskModel.Assess(Descriptor(RiskLevel.R0),
            context with { Scope = (RiskScope)99 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => RiskModel.Assess(Descriptor(RiskLevel.R0),
            context with { Target = (RiskTarget)99 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => RiskModel.Assess(Descriptor(RiskLevel.R0),
            context with { Reversibility = (RiskReversibility)99 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => RiskModel.Assess(Descriptor(RiskLevel.R0),
            context with { Egress = (RiskEgress)99 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => RiskModel.Assess(Descriptor(RiskLevel.R0),
            context with { ActorKind = (ActorKind)99 }));
    }

    private static CapabilityDescriptor Descriptor(RiskLevel risk) => new() { Risk = risk.ToString() };

    private static RiskContext DefaultContext() => new(
        RiskScope.SingleOperation,
        RiskTarget.Ordinary,
        RiskReversibility.Reversible,
        RiskEgress.None,
        ActorKind.None,
        IsRemoteOrigin: false,
        IsPackageVerified: true,
        IsLargeDataVolume: false);

    private static IEnumerable<RiskContext> AllContexts()
    {
        foreach (var scope in Enum.GetValues<RiskScope>())
            foreach (var target in Enum.GetValues<RiskTarget>())
                foreach (var reversibility in Enum.GetValues<RiskReversibility>())
                    foreach (var egress in Enum.GetValues<RiskEgress>())
                        foreach (var actorKind in Enum.GetValues<ActorKind>())
                            foreach (var remote in new[] { false, true })
                                foreach (var verified in new[] { false, true })
                                    foreach (var largeData in new[] { false, true })
                                    {
                                        yield return new RiskContext(scope, target, reversibility, egress, actorKind, remote, verified, largeData);
                                    }
    }

    private static (RiskLevel EffectiveRisk, RiskAdjustment[] Adjustments) Expected(RiskContext context, RiskLevel baseline)
    {
        var adjustments = new List<RiskAdjustment>();
        if (context.IsRemoteOrigin)
        {
            adjustments.Add(new(RiskModifier.RemoteOrigin, RiskLevel.R3));
        }

        if (context.Scope == RiskScope.Bulk)
        {
            adjustments.Add(new(RiskModifier.BulkScope, RiskLevel.R2));
        }

        if (context.Target == RiskTarget.SensitiveResource)
        {
            adjustments.Add(new(RiskModifier.SensitiveResource, RiskLevel.R2));
        }

        if (context.IsLargeDataVolume)
        {
            adjustments.Add(new(RiskModifier.LargeDataVolume, RiskLevel.R2));
        }

        if (context.Egress == RiskEgress.External)
        {
            adjustments.Add(new(RiskModifier.ExternalEgress, RiskLevel.R3));
        }

        if (context.Reversibility == RiskReversibility.Irreversible)
        {
            adjustments.Add(new(RiskModifier.IrreversibleEffect, RiskLevel.R4));
        }

        if (!context.IsPackageVerified)
        {
            adjustments.Add(new(RiskModifier.UnverifiedPackage, RiskLevel.R3));
        }

        switch (context.ActorKind)
        {
            case ActorKind.None:
                break;
            case ActorKind.Agent:
                adjustments.Add(new(RiskModifier.AgentActor, RiskLevel.R2));
                break;
            case ActorKind.Extension:
                adjustments.Add(new(RiskModifier.ExtensionActor, RiskLevel.R3));
                break;
            case ActorKind.Automation:
                adjustments.Add(new(RiskModifier.AutomationActor, RiskLevel.R2));
                break;
            case ActorKind.InternalService:
                adjustments.Add(new(RiskModifier.InternalServiceActor, RiskLevel.R1));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(context));
        }

        if (context.ActorKind == ActorKind.Automation && context.Egress == RiskEgress.External)
        {
            adjustments.Add(new(RiskModifier.AutomationWithExternalEgress, RiskLevel.R4));
        }

        if (context.Target == RiskTarget.SensitiveResource && context.Egress == RiskEgress.External)
        {
            adjustments.Add(new(RiskModifier.SensitiveResourceWithExternalEgress, RiskLevel.R4));
        }

        if (context.ActorKind == ActorKind.Extension && !context.IsPackageVerified)
        {
            adjustments.Add(new(RiskModifier.ExtensionWithUnverifiedPackage, RiskLevel.R4));
        }

        var effectiveRisk = adjustments.Aggregate(baseline,
            (current, adjustment) => (int)adjustment.MinimumRisk > (int)current ? adjustment.MinimumRisk : current);
        return (effectiveRisk, adjustments.ToArray());
    }
}
