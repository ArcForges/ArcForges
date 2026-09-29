// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Security;

/// <summary>The closed ordered capability-risk scale used by the current Contracts descriptor.</summary>
public enum RiskLevel
{
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
}

/// <summary>Invocation scope; a bulk action is at least significant-risk.</summary>
public enum RiskScope
{
    SingleOperation = 0,
    Bulk = 1,
}

/// <summary>Whether the resolved target is an ordinary or sensitive resource.</summary>
public enum RiskTarget
{
    Ordinary = 0,
    SensitiveResource = 1,
}

/// <summary>Whether the proposed effect is reversible.</summary>
public enum RiskReversibility
{
    Reversible = 0,
    Irreversible = 1,
}

/// <summary>Destination classification for data leaving the owning trust boundary.</summary>
public enum RiskEgress
{
    None = 0,
    External = 1,
}

/// <summary>
/// Immutable invocation facts used only to raise the capability's declared baseline risk.
/// ActorKind.None denotes a direct human action with no delegated actor.
/// </summary>
public sealed record RiskContext(
    RiskScope Scope,
    RiskTarget Target,
    RiskReversibility Reversibility,
    RiskEgress Egress,
    ActorKind ActorKind,
    bool IsRemoteOrigin,
    bool IsPackageVerified,
    bool IsLargeDataVolume);

/// <summary>Stable, non-authorizing explanation codes for risk adjustments.</summary>
public enum RiskModifier
{
    RemoteOrigin = 0,
    BulkScope = 1,
    SensitiveResource = 2,
    LargeDataVolume = 3,
    ExternalEgress = 4,
    IrreversibleEffect = 5,
    UnverifiedPackage = 6,
    AgentActor = 7,
    ExtensionActor = 8,
    AutomationActor = 9,
    InternalServiceActor = 10,
    AutomationWithExternalEgress = 11,
    SensitiveResourceWithExternalEgress = 12,
    ExtensionWithUnverifiedPackage = 13,
}

/// <summary>A named modifier and the minimum risk level it requires.</summary>
public readonly record struct RiskAdjustment(RiskModifier Modifier, RiskLevel MinimumRisk);

/// <summary>Immutable, explainable result of classifying one capability invocation.</summary>
public sealed class RiskAssessment
{
    internal RiskAssessment(RiskLevel capabilityRisk, RiskLevel effectiveRisk, RiskAdjustment[] adjustments)
    {
        CapabilityRisk = capabilityRisk;
        EffectiveRisk = effectiveRisk;
        Adjustments = Array.AsReadOnly(adjustments);
    }

    public RiskLevel CapabilityRisk { get; }
    public RiskLevel EffectiveRisk { get; }
    public ReadOnlyCollection<RiskAdjustment> Adjustments { get; }
}

/// <summary>
/// Computes per-invocation risk as the maximum of the owner-declared capability baseline and
/// fixed minimum floors for active runtime modifiers. Modifier ordering is stable for explanation.
/// </summary>
public static class RiskModel
{
    /// <summary>Classify one invocation without allowing runtime facts to lower its descriptor risk.</summary>
    public static RiskAssessment Assess(CapabilityDescriptor descriptor, RiskContext context)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(context);
        ValidateContext(context);

        var capabilityRisk = ParseCapabilityRisk(descriptor.Risk);
        var adjustments = new List<RiskAdjustment>(12);

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
                throw new ArgumentOutOfRangeException(nameof(context), "The actor kind is not classified.");
        }

        // RK-07 requires automation plus external egress to be stricter than either modifier alone.
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

        var effectiveRisk = capabilityRisk;
        foreach (var adjustment in adjustments)
        {
            if ((int)adjustment.MinimumRisk > (int)effectiveRisk)
            {
                effectiveRisk = adjustment.MinimumRisk;
            }
        }

        return new RiskAssessment(capabilityRisk, effectiveRisk, adjustments.ToArray());
    }

    private static void ValidateContext(RiskContext context)
    {
        if (!Enum.IsDefined(context.Scope))
        {
            throw new ArgumentOutOfRangeException(nameof(context), "The invocation scope is not classified.");
        }

        if (!Enum.IsDefined(context.Target))
        {
            throw new ArgumentOutOfRangeException(nameof(context), "The invocation target is not classified.");
        }

        if (!Enum.IsDefined(context.Reversibility))
        {
            throw new ArgumentOutOfRangeException(nameof(context), "The effect reversibility is not classified.");
        }

        if (!Enum.IsDefined(context.Egress))
        {
            throw new ArgumentOutOfRangeException(nameof(context), "The egress destination is not classified.");
        }

        if (!Enum.IsDefined(context.ActorKind))
        {
            throw new ArgumentOutOfRangeException(nameof(context), "The actor kind is not classified.");
        }
    }

    private static RiskLevel ParseCapabilityRisk(string? value) => value switch
    {
        "R0" => RiskLevel.R0,
        "R1" => RiskLevel.R1,
        "R2" => RiskLevel.R2,
        "R3" => RiskLevel.R3,
        "R4" => RiskLevel.R4,
        _ => throw new ArgumentException("The capability baseline risk must be canonical R0 through R4.", nameof(value)),
    };
}
