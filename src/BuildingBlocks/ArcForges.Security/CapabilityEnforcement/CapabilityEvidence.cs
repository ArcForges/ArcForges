// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;
using ArcForges.Sdk.Contracts.V1;
using ArcForges.Security.Approvals;
using ArcForges.Security.Decisions;

namespace ArcForges.Security.CapabilityEnforcement;

/// <summary>
/// What the hosting product knows about one invocation that the invocation itself cannot prove: who acts for whom, in which scope, on
/// which exact resource and revision, through which transport session and from which origin. It is evidence for the decision
/// pipeline to compare against its authoritative sources; none of it grants anything. The capability, command, approval and lease
/// identities and the effect digest are never taken from the host: the gate reads them from the invocation itself.
/// </summary>
public sealed class CapabilityEvidence
{
    public CapabilityEvidence(
        ActorChain actors,
        DecisionScope scope,
        ResourceReference resource,
        DecisionOrigin origin,
        ITransportSession transport,
        RiskFacts? declaredFacts = null,
        string? egressDestination = null,
        string? secretUseKey = null,
        StepUpProof? stepUpProof = null,
        SensitiveOperation sensitiveOperation = SensitiveOperation.None)
    {
        Actors = actors ?? throw new ArgumentNullException(nameof(actors));
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        Resource = resource ?? throw new ArgumentNullException(nameof(resource));
        Origin = origin;
        Transport = transport ?? throw new ArgumentNullException(nameof(transport));
        DeclaredFacts = declaredFacts;
        EgressDestination = egressDestination;
        SecretUseKey = secretUseKey;
        StepUpProof = stepUpProof;
        SensitiveOperation = sensitiveOperation;
    }

    public ActorChain Actors { get; }

    public DecisionScope Scope { get; }

    public ResourceReference Resource { get; }

    public DecisionOrigin Origin { get; }

    public ITransportSession Transport { get; }

    public RiskFacts? DeclaredFacts { get; }

    /// <summary>The exact destination of an outbound transfer, when the capability sends data out.</summary>
    public string? EgressDestination { get; }

    /// <summary>The reference (never the value) of a stored secret the invocation uses.</summary>
    public string? SecretUseKey { get; }

    public StepUpProof? StepUpProof { get; }

    public SensitiveOperation SensitiveOperation { get; }
}

/// <summary>
/// The hosting product's source of <see cref="CapabilityEvidence"/>. It is consulted once per new command, after availability and
/// context freezing, and a source that returns nothing, throws or cannot answer refuses the invocation: there is no default.
/// </summary>
public interface ICapabilityEvidenceSource
{
    ValueTask<CapabilityEvidence?> DescribeAsync(
        CapabilityRegistration capability,
        Invocation invocation,
        CapabilityTarget target,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken);
}
