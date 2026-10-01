// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;
using ArcForges.Security;

namespace ArcForges.Security.Audit;

/// <summary>
/// The stable, non-empty, Guid-backed identity of one capability lease. PLT.43's lease identity maps to this
/// value by its <c>Value</c> Guid directly; the Guid is never stringified, hashed or truncated.
/// </summary>
public readonly record struct AuditCapabilityLeaseId
{
    public AuditCapabilityLeaseId(Guid value)
    {
        if (value == Guid.Empty) throw new ArgumentException("A capability lease identity is required.", nameof(value));
        Value = value;
    }

    public Guid Value { get; }
}

/// <summary>The closed set of capability-lease lifecycle facts that are audited.</summary>
public enum CapabilityLeaseLifecycleKind
{
    None = 0,
    Issued = 1,
    Revoked = 2,
    Expired = 3,
    TaskEnded = 4,
}

/// <summary>
/// The closed typed fact of one lease lifecycle transition. Each carries the same lease identity; unknown
/// kinds are refused at construction. There is no payload, scope text or property bag.
/// </summary>
public sealed class CapabilityLeaseLifecycleFact
{
    private readonly AuditEvent auditEvent;

    public CapabilityLeaseLifecycleFact(CapabilityLeaseLifecycleKind kind, AuditCapabilityLeaseId lease,
        AuditDecisionReason reason, RiskLevel effectiveRisk, ActorChain actorChain,
        AuditSoftwareIdentity softwareIdentity, AuditCapabilityId capability, AuditOrigin origin,
        WorkspaceId? workspace = null, TaskId? task = null, CorrelationId? correlation = null)
    {
        var eventType = kind switch
        {
            CapabilityLeaseLifecycleKind.Issued => AuditEventType.CapabilityLeaseIssued,
            CapabilityLeaseLifecycleKind.Revoked => AuditEventType.CapabilityLeaseRevoked,
            CapabilityLeaseLifecycleKind.Expired => AuditEventType.CapabilityLeaseExpired,
            CapabilityLeaseLifecycleKind.TaskEnded => AuditEventType.CapabilityLeaseTaskEnded,
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        if (kind == CapabilityLeaseLifecycleKind.TaskEnded && task is null)
        {
            throw new ArgumentException("A task-end fact names the ended task.", nameof(task));
        }

        var decision = kind == CapabilityLeaseLifecycleKind.Issued ? AuditDecision.Allowed : AuditDecision.Completed;
        // Event construction is the single validator of the per-kind decision/reason pairing and of the
        // lease resource kind; the resource identity is the lease Guid, mapped directly.
        auditEvent = new AuditEvent(eventType, actorChain, softwareIdentity, capability,
            new AuditResourceReference(AuditResourceKind.CapabilityLease, lease.Value),
            AuditEnumValidation.FromRiskLevel(effectiveRisk), decision, reason, origin, workspace, task, correlation);
        Kind = kind;
        Lease = lease;
    }

    public CapabilityLeaseLifecycleKind Kind { get; }
    public AuditCapabilityLeaseId Lease { get; }

    internal AuditEvent Event => auditEvent;
}

/// <summary>
/// Typed audit intake for capability-lease issue, revocation, expiry and task-end facts. It preserves the
/// lease identity through append and query as the Guid-valued <see cref="AuditResourceReference"/> of kind
/// <see cref="AuditResourceKind.CapabilityLease"/>. Failures propagate unchanged. This type proves the intake
/// contract only: it is not evidence that a real PLT.43 lease runtime emits to it.
/// </summary>
public sealed class CapabilityLeaseAuditAdapter
{
    private readonly AuditStore store;

    public CapabilityLeaseAuditAdapter(AuditStore store)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <summary>Durably append one lease lifecycle fact before returning; throws on any failure.</summary>
    public AuditEventRecord Record(CapabilityLeaseLifecycleFact fact)
    {
        ArgumentNullException.ThrowIfNull(fact);
        return store.Append(fact.Event);
    }
}
