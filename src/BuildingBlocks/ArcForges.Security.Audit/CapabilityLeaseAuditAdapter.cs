// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;
using ArcForges.Security;
using ArcForges.Security.Decisions;
using ArcForges.Security.Leases;

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
/// <see cref="AuditResourceKind.CapabilityLease"/>. Failures propagate unchanged. The real PLT.43 lease manager reaches this
/// intake through <see cref="CapabilityLeaseEventAuditSink"/>.
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

/// <summary>
/// The audit side of the PLT.43 lease event port: it implements <see cref="ILeaseEventSink"/> over
/// <see cref="CapabilityLeaseAuditAdapter"/>, so the real <c>CapabilityLeaseManager</c> writes each issued, revoked, expired and
/// task-ended fact into the durable audit store. The mapping is total and closed: the lease identity travels as the exact Guid
/// (<c>CapabilityLeaseId.Value</c>), the event kind maps one to one, and the decision reason is derived from the lease's own recorded
/// basis (issue) or revocation reason, so no reason is invented. Any fact the audit shape cannot hold (a capability key that is not a
/// canonical audit key, an invalid software identity, an owner other than the store's owner, a purged partition, a disposed or
/// unwritable store) throws, and the manager then refuses the issue or reports the end fact as still owed; nothing is dropped silently.
/// The call is synchronous: it returns only after the row is committed.
/// </summary>
/// <remarks>
/// What the audit row carries and does not carry, by design of the PLT.43 fact: the actor chain is the delegator's issuing chain (a
/// revocation snapshot does not record the revoking principal, only that it was the owner), the occurrence time is stamped by the store
/// from its own clock at append (not the producer's time, so an expiry fact written by a later sweep is stamped at the sweep), and the
/// holder, scope resources and expiry stay in the lease store, which the lease identity points to. Facts are written at least once,
/// so a retried fact appears twice; the lease identity and event type identify it.
/// </remarks>
public sealed class CapabilityLeaseEventAuditSink : ILeaseEventSink
{
    private readonly CapabilityLeaseAuditAdapter adapter;
    private readonly AuditSoftwareIdentity fallbackSoftwareIdentity;

    /// <param name="adapter">The typed lease intake of the audit store.</param>
    /// <param name="fallbackSoftwareIdentity">
    /// The software identity recorded when the issuing chain has no delegated actor (a direct owner-side issue), supplied by the
    /// composition root.
    /// </param>
    public CapabilityLeaseEventAuditSink(CapabilityLeaseAuditAdapter adapter, AuditSoftwareIdentity fallbackSoftwareIdentity)
    {
        this.adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
        this.fallbackSoftwareIdentity = fallbackSoftwareIdentity ?? throw new ArgumentNullException(nameof(fallbackSoftwareIdentity));
    }

    /// <summary>Appends one lease lifecycle fact durably before returning; throws on any failure.</summary>
    public ValueTask WriteAsync(CapabilityLeaseEvent leaseEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(leaseEvent);
        cancellationToken.ThrowIfCancellationRequested();
        _ = adapter.Record(Map(leaseEvent));
        return ValueTask.CompletedTask;
    }

    private CapabilityLeaseLifecycleFact Map(CapabilityLeaseEvent leaseEvent)
    {
        var lease = leaseEvent.Lease;
        var (kind, reason) = leaseEvent.Kind switch
        {
            LeaseEventKind.Issued => (CapabilityLeaseLifecycleKind.Issued, IssueReason(lease.Basis)),
            LeaseEventKind.Revoked => (CapabilityLeaseLifecycleKind.Revoked, RevokeReason(lease.RevocationReason)),
            LeaseEventKind.Expired => (CapabilityLeaseLifecycleKind.Expired, AuditDecisionReason.PolicyExpired),
            LeaseEventKind.TaskEnded => (CapabilityLeaseLifecycleKind.TaskEnded, AuditDecisionReason.NotApplicable),
            _ => throw new ArgumentOutOfRangeException(nameof(leaseEvent), "The lease event kind is not an audited lifecycle kind."),
        };
        var software = lease.IssuedBy.Actors.Count > 0
            ? new AuditSoftwareIdentity(lease.IssuedBy.Actors[^1].SoftwareIdentity)
            : fallbackSoftwareIdentity;
        return new CapabilityLeaseLifecycleFact(
            kind,
            new AuditCapabilityLeaseId(leaseEvent.LeaseId.Value),
            reason,
            lease.EffectiveRisk,
            lease.IssuedBy,
            software,
            new AuditCapabilityId(lease.CapabilityKey),
            lease.Origin switch
            {
                DecisionOrigin.Local => AuditOrigin.Local,
                DecisionOrigin.Remote => AuditOrigin.Remote,
                _ => throw new ArgumentOutOfRangeException(nameof(leaseEvent), "The lease origin is not an audited origin."),
            },
            lease.Scope.Workspace,
            lease.Task);
    }

    private static AuditDecisionReason IssueReason(LeaseIssueBasis basis) => basis switch
    {
        LeaseIssueBasis.PolicyAllowed => AuditDecisionReason.PolicyAllowed,
        LeaseIssueBasis.UserApproved => AuditDecisionReason.UserApproved,
        LeaseIssueBasis.StepUpSatisfied => AuditDecisionReason.StepUpSatisfied,
        LeaseIssueBasis.RiskAccepted => AuditDecisionReason.RiskAccepted,
        _ => throw new ArgumentOutOfRangeException(nameof(basis), "The lease issue basis is not an audited reason."),
    };

    private static AuditDecisionReason RevokeReason(LeaseRevocationReason reason) => reason switch
    {
        LeaseRevocationReason.OwnerRevoked => AuditDecisionReason.UserRejected,
        LeaseRevocationReason.PolicyDenied => AuditDecisionReason.PolicyDenied,
        LeaseRevocationReason.RiskRejected => AuditDecisionReason.RiskRejected,
        LeaseRevocationReason.AuthorityLost => AuditDecisionReason.AuthorityMissing,
        _ => throw new ArgumentOutOfRangeException(nameof(reason), "The lease revocation reason is not an audited reason."),
    };
}
