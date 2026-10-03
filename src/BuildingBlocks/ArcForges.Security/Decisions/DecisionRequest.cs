// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Security.Approvals;

namespace ArcForges.Security.Decisions;

/// <summary>
/// One invocation presented to the decision pipeline. Every field is evidence to compare against an authoritative source; none of
/// them grants anything. The capability descriptor is deliberately absent: the pipeline reads it from the catalogue, so a caller
/// cannot lower the baseline risk or the declared approval and egress posture by supplying its own.
/// </summary>
public sealed class DecisionRequest
{
    public DecisionRequest(
        ActorChain actors,
        string capabilityKey,
        DecisionScope scope,
        CommandId commandId,
        ResourceReference resource,
        string effectSha256,
        DecisionOrigin origin,
        ITransportSession transport,
        RiskFacts? declaredFacts = null,
        string? egressDestination = null,
        string? secretUseKey = null,
        Guid? approvalId = null,
        StepUpProof? stepUpProof = null,
        SensitiveOperation sensitiveOperation = SensitiveOperation.None)
    {
        ArgumentNullException.ThrowIfNull(actors);
        SecurityText.Validate(capabilityKey, 256, nameof(capabilityKey));
        ArgumentNullException.ThrowIfNull(scope);
        _ = commandId.ToWire();
        ArgumentNullException.ThrowIfNull(resource);
        SecurityText.ValidateSha256(effectSha256, nameof(effectSha256));
        if (!Enum.IsDefined(origin) || origin == DecisionOrigin.None)
        {
            throw new ArgumentOutOfRangeException(nameof(origin));
        }

        ArgumentNullException.ThrowIfNull(transport);
        if (egressDestination is not null)
        {
            SecurityText.Validate(egressDestination, 512, nameof(egressDestination));
        }

        if (secretUseKey is not null)
        {
            SecurityText.Validate(secretUseKey, 256, nameof(secretUseKey));
        }

        if (approvalId == Guid.Empty)
        {
            throw new ArgumentException("An approval identity cannot be empty.", nameof(approvalId));
        }

        if (!Enum.IsDefined(sensitiveOperation))
        {
            throw new ArgumentOutOfRangeException(nameof(sensitiveOperation));
        }

        Actors = actors;
        CapabilityKey = capabilityKey;
        Scope = scope;
        CommandId = commandId;
        Resource = resource;
        EffectSha256 = effectSha256;
        Origin = origin;
        Transport = transport;
        DeclaredFacts = declaredFacts ?? RiskFacts.None;
        EgressDestination = egressDestination;
        SecretUseKey = secretUseKey;
        ApprovalId = approvalId;
        StepUpProof = stepUpProof;
        SensitiveOperation = sensitiveOperation;
    }

    public ActorChain Actors { get; }

    public string CapabilityKey { get; }

    public DecisionScope Scope { get; }

    public CommandId CommandId { get; }

    public ResourceReference Resource { get; }

    /// <summary>The canonical uppercase SHA-256 of the proposed effect, which an approval binds.</summary>
    public string EffectSha256 { get; }

    public DecisionOrigin Origin { get; }

    public ITransportSession Transport { get; }

    public RiskFacts DeclaredFacts { get; }

    /// <summary>The exact destination identity of an outbound transfer, when the capability sends data out.</summary>
    public string? EgressDestination { get; }

    /// <summary>The key of a secret the invocation uses (never reveals); it is a reference, not a value.</summary>
    public string? SecretUseKey { get; }

    public Guid? ApprovalId { get; }

    public StepUpProof? StepUpProof { get; }

    public SensitiveOperation SensitiveOperation { get; }

    /// <summary>The canonical key of the human owner the permission lookup is made for.</summary>
    public string PrincipalKey => string.Create(
        CultureInfo.InvariantCulture,
        $"principal:{Actors.Owner.Realm.Value:N}/{Actors.Owner.Id.Value:N}");

    /// <summary>The canonical key of the scope.</summary>
    public string ScopeKey => Scope.Key;
}
