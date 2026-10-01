// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Security;

namespace ArcForges.Security.Audit;

/// <summary>Whether the egress enforcement point allowed or denied the transfer.</summary>
public enum EgressDecisionOutcome
{
    None = 0,
    Allowed = 1,
    Denied = 2,
}

/// <summary>
/// The closed typed fact of one egress decision, as the PLT.41 enforcement point must present it to audit:
/// the typed data class, the destination class and canonical identity, the authority identity and committed
/// revision, the effective risk, the allow/deny outcome and its reason, and the correlation. It cannot carry
/// transferred content, a secret value or any free-form property. Construction validates every field and
/// the outcome/reason agreement, so an invalid fact never reaches the store.
/// </summary>
public sealed class EgressDecisionFact
{
    private readonly AuditEvent auditEvent;

    public EgressDecisionFact(EgressDecisionOutcome outcome, AuditDecisionReason reason,
        AuditEgressDataClass dataClass, AuditEgressDestinationClass destinationClass,
        AuditEgressDestinationId destination, Revision authority, RiskLevel effectiveRisk,
        ActorChain actorChain, AuditSoftwareIdentity softwareIdentity, AuditCapabilityId capability,
        AuditResourceReference resource, AuditOrigin origin, CorrelationId correlation,
        WorkspaceId? workspace = null, TaskId? task = null)
    {
        if (outcome is not (EgressDecisionOutcome.Allowed or EgressDecisionOutcome.Denied))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome));
        }

        // Event construction is the single validator: closed enums, owner/actor chain, software identity,
        // typed egress detail, correlation and outcome/reason agreement all fail closed there.
        auditEvent = new AuditEvent(
            outcome == EgressDecisionOutcome.Allowed ? AuditEventType.DataEgressAuthorized : AuditEventType.DataEgressDenied,
            actorChain, softwareIdentity, capability, resource, AuditEnumValidation.FromRiskLevel(effectiveRisk),
            outcome == EgressDecisionOutcome.Allowed ? AuditDecision.Allowed : AuditDecision.Denied, reason, origin,
            workspace, task, correlation, new AuditEgressDetail(dataClass, destinationClass, destination, authority));
        Outcome = outcome;
    }

    public EgressDecisionOutcome Outcome { get; }

    internal AuditEvent Event => auditEvent;
}

/// <summary>
/// Typed audit intake for egress decisions. <see cref="Record"/> appends synchronously and durably, for both
/// allowed and denied decisions, and returns only after the row is committed. Any failure (wrong owner, a
/// purged partition, a disposed or unwritable store) propagates to the caller unchanged, so an enforcement
/// path that calls this before releasing a transfer cannot release an allowed transfer whose audit append
/// failed. The adapter accepts only <see cref="EgressDecisionFact"/>; it has no generic append and no
/// content, secret or property-bag parameter. Security owns the sink port and never references this project;
/// composition adapts that port to this class. This type proves the intake contract only: it is not evidence
/// that the real PLT.41 enforcement path emits to it.
/// </summary>
public sealed class EgressDecisionAuditAdapter
{
    private readonly AuditStore store;

    public EgressDecisionAuditAdapter(AuditStore store)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <summary>Durably append one egress decision before returning; throws on any failure.</summary>
    public AuditEventRecord Record(EgressDecisionFact fact)
    {
        ArgumentNullException.ThrowIfNull(fact);
        return store.Append(fact.Event);
    }
}
