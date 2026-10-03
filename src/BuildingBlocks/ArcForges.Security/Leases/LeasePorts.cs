// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Security.Decisions;

namespace ArcForges.Security.Leases;

/// <summary>
/// Durable, linearizable store of capability leases. Creation is insert-if-absent. Replacement is a compare-and-swap on the current
/// version: it preserves every coverage field, increments the version exactly once and only ever moves a lease forward (an Active lease to
/// one terminal state, or a terminal lease's end-event flag from false to true); a terminal lease is never made Active again. A true result
/// is returned only after the complete snapshot is durably committed, so a revocation or an expiry that was reported survives a restart.
/// </summary>
public interface ILeaseStore
{
    ValueTask<CapabilityLease?> ReadAsync(CapabilityLeaseId id, CancellationToken cancellationToken);

    /// <summary>Stores a new Active lease at version 1. False when a lease with that identity already exists.</summary>
    ValueTask<bool> TryCreateAsync(CapabilityLease lease, CancellationToken cancellationToken);

    /// <summary>Replaces the lease only when its stored version is <paramref name="expectedVersion"/>; false otherwise.</summary>
    ValueTask<bool> TryReplaceAsync(CapabilityLeaseId id, long expectedVersion, CapabilityLease replacement, CancellationToken cancellationToken);

    /// <summary>
    /// Leases still owed work, at most <paramref name="limit"/>: Active leases whose expiry is at or before <paramref name="dueAt"/> (or
    /// every Active lease when it is null) and terminal leases whose end fact is not yet recorded, each optionally limited to one task.
    /// </summary>
    ValueTask<IReadOnlyList<CapabilityLease>> ListUnsettledAsync(TaskId? task, Instant? dueAt, int limit, CancellationToken cancellationToken);
}

/// <summary>
/// One lifecycle fact of a lease: issued, revoked, expired or task-ended. The lease snapshot carries the same identity in every fact, the
/// delegator's chain, the holder, the capability, the task, the scope and the origin. It carries no payload, secret or content.
/// </summary>
public sealed class CapabilityLeaseEvent
{
    public CapabilityLeaseEvent(LeaseEventKind kind, CapabilityLease lease, Instant occurredAt)
    {
        ArgumentNullException.ThrowIfNull(lease);
        var expected = lease.State switch
        {
            LeaseState.Active => LeaseEventKind.Issued,
            LeaseState.Revoked => LeaseEventKind.Revoked,
            LeaseState.Expired => LeaseEventKind.Expired,
            LeaseState.TaskEnded => LeaseEventKind.TaskEnded,
            _ => LeaseEventKind.None,
        };
        if (kind == LeaseEventKind.None || kind != expected)
        {
            throw new ArgumentException("The event kind must match the lease's state.", nameof(kind));
        }

        Kind = kind;
        Lease = lease;
        OccurredAt = occurredAt;
    }

    public LeaseEventKind Kind { get; }

    /// <summary>The lease as it was when the fact happened (Active for an issue, the terminal snapshot otherwise).</summary>
    public CapabilityLease Lease { get; }

    /// <summary>The identity every fact of this lease carries.</summary>
    public CapabilityLeaseId LeaseId => Lease.Id;

    public Instant OccurredAt { get; }
}

/// <summary>
/// Sink of the lifecycle facts (BR-07: a lease is audited). It must return only after the fact is durable and throw on any failure. The
/// audit store is a separate project that Security does not reference; the host maps the fact into it.
/// </summary>
public interface ILeaseEventSink
{
    ValueTask WriteAsync(CapabilityLeaseEvent leaseEvent, CancellationToken cancellationToken);
}

/// <summary>
/// The delegator's own authority, which bounds every lease derived from it (CL-03: a lease narrows, never widens). It answers with the
/// owner-issued permission for the principal, capability and scope, or null when there is none.
/// </summary>
public interface ILeaseCeilingSource
{
    ValueTask<PermissionGrantRecord?> FindAsync(string principalKey, string capabilityKey, string scopeKey, CancellationToken cancellationToken);
}

/// <summary>
/// The use-time check of a lease, the pipeline's lease step. It is read-only evidence for a decision: expiry, revocation and the end of the
/// task are enforced here at every use, not only when the lease was issued.
/// </summary>
public interface ILeaseUseValidator
{
    ValueTask<LeaseUseVerdict> ValidateAsync(LeaseUse use, CancellationToken cancellationToken);
}
