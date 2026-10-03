// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;
using ArcForges.Security.Decisions;

namespace ArcForges.Security.Leases;

/// <summary>Bounds the manager applies when it issues a lease.</summary>
public sealed record LeaseOptions
{
    /// <summary>The longest a lease may live (default one hour; never above <see cref="CapabilityLease.AbsoluteMaximumLifetime"/>).</summary>
    public TimeSpan MaximumLifetime { get; init; } = TimeSpan.FromHours(1);
}

/// <summary>The result of an issue: the stored lease, or the one stable reason nothing was issued.</summary>
public sealed class LeaseIssueResult
{
    internal LeaseIssueResult(CapabilityLease? lease, LeaseIssueRefusal refusal)
    {
        Lease = lease;
        Refusal = refusal;
    }

    /// <summary>The issued lease, or null when it was refused.</summary>
    public CapabilityLease? Lease { get; }

    public LeaseIssueRefusal Refusal { get; }

    public bool Issued => Lease is not null;

    /// <summary>The registered reason code of the refusal; empty when a lease was issued.</summary>
    public string RegisteredCode => Refusal switch
    {
        LeaseIssueRefusal.None => string.Empty,
        LeaseIssueRefusal.InvalidRequest or LeaseIssueRefusal.ExceedsMaximumLifetime => "validation.invalid_request",
        LeaseIssueRefusal.CeilingUnavailable or LeaseIssueRefusal.AuditUnavailable or LeaseIssueRefusal.StoreUnavailable => "resource.unavailable",
        LeaseIssueRefusal.Duplicate => "conflict.duplicate_identifier",
        _ => "perm.capability_denied",
    };
}

/// <summary>What a revoke did: the lease as it now is, whether this call ended it, and whether its end fact reached the sink.</summary>
public readonly record struct LeaseTransition(CapabilityLease Lease, bool Changed, bool EndRecorded);

/// <summary>What a sweep did: leases it ended, end facts it recorded, and end facts still owed afterwards.</summary>
public readonly record struct LeaseSweep(int Ended, int Recorded, int Owed);

/// <summary>
/// Issues, revokes, ends and judges capability leases (BR-07, CL-01 to CL-04, DG-01, DG-02). A lease is a durable, scoped, expiring,
/// revocable and audited narrowing of the delegator's own authority:
/// <list type="bullet">
/// <item>Issue checks the delegator's current permission (the ceiling): the lease can cover only a capability the delegator holds, inside
/// that permission's lifetime and constraints; a holder of delegated authority (agent or extension) cannot issue; only an agent or extension
/// holds one. The "issued" fact is durable before the lease is stored, so a lease exists only if its issue was audited.</item>
/// <item>Use is judged at every use (<see cref="ValidateAsync"/>): the stored state, the exact holder, owner, scope, capability and
/// resource, and expiry on a clock a wall-clock step back cannot rewind. An expiry observed is stored, so it cannot be revived.</item>
/// <item>Revocation and the end of the task are stored before their facts are written, so authority ends even when the audit sink is
/// down; the fact is then owed and is retried by the next sweep (<see cref="ExpireDueAsync"/> or <see cref="EndTaskAsync"/>). A use never
/// writes anything for a lease that has already ended.</item>
/// </list>
/// Trust and permission are not read here: a lease is never evidence of either, and holding one never replaces the grant or the owner's
/// resource authorization, which the decision pipeline still requires.
/// </summary>
public sealed class CapabilityLeaseManager : ILeaseUseValidator
{
    private const int MaximumCompareAndSwapAttempts = 8;
    private const int SweepPageSize = 64;
    private const int MaximumSweepPages = 64;

    private readonly IClock _clock;
    private readonly ILeaseStore _store;
    private readonly ILeaseEventSink _events;
    private readonly ILeaseCeilingSource _ceilings;
    private readonly LeaseOptions _options;
    private readonly Instant _anchorWall;
    private readonly MonotonicTimestamp _anchorMonotonic;
    private readonly Lock _timeLock = new();
    private Instant _highWater;

    public CapabilityLeaseManager(
        IClock clock,
        ILeaseStore store,
        ILeaseEventSink events,
        ILeaseCeilingSource ceilings,
        LeaseOptions? options = null)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _events = events ?? throw new ArgumentNullException(nameof(events));
        _ceilings = ceilings ?? throw new ArgumentNullException(nameof(ceilings));
        _options = options ?? new LeaseOptions();
        if (_options.MaximumLifetime <= TimeSpan.Zero || _options.MaximumLifetime > CapabilityLease.AbsoluteMaximumLifetime)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The maximum lease lifetime is above zero and at most twenty-four hours.");
        }

        _anchorWall = _clock.GetCurrentInstant();
        _anchorMonotonic = _clock.GetTimestamp();
        _highWater = _anchorWall;
    }

    /// <summary>
    /// Issues one lease when the delegator's own permission covers it. Nothing is stored or audited as issued when any check refuses, and
    /// nothing is stored when the issued fact cannot be made durable.
    /// </summary>
    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "A failing port must become a typed refusal that issues nothing; no exception text is retained.")]
    public async ValueTask<LeaseIssueResult> IssueAsync(LeaseRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var chain = request.IssuedBy;
        if (chain.Actors.Count > 0 && chain.Actors[^1].Kind is ActorKind.Agent or ActorKind.Extension)
        {
            // CL-03: tools cannot mint grants or sub-delegate; only the owner's own side delegates.
            return Refuse(LeaseIssueRefusal.IssuerCannotDelegate);
        }

        if (!request.Holder.CanHoldLease)
        {
            return Refuse(LeaseIssueRefusal.HolderCannotHoldLease);
        }

        if (request.Scope.Realm != chain.Owner.Realm || request.Lifetime <= TimeSpan.Zero)
        {
            return Refuse(LeaseIssueRefusal.InvalidRequest);
        }

        if (request.Lifetime > _options.MaximumLifetime)
        {
            return Refuse(LeaseIssueRefusal.ExceedsMaximumLifetime);
        }

        var principal = PermissionKeys.Principal(chain.Owner);
        var scopeKey = request.Scope.Key;
        PermissionGrantRecord? grant;
        try
        {
            grant = await _ceilings.FindAsync(principal, request.CapabilityKey, scopeKey, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Refuse(LeaseIssueRefusal.CeilingUnavailable);
        }

        // The instant is read after the source answered, so a slow source cannot make an expired permission look current.
        var now = Now();
        if (grant is null
            || !string.Equals(grant.PrincipalKey, principal, StringComparison.Ordinal)
            || !string.Equals(grant.CapabilityKey, request.CapabilityKey, StringComparison.Ordinal)
            || !string.Equals(grant.ScopeKey, scopeKey, StringComparison.Ordinal))
        {
            return Refuse(LeaseIssueRefusal.CeilingMissing);
        }

        var ceilingEnd = Instant.FromDateTimeOffset(grant.ValidUntilUtc);
        if (grant.State != PermissionGrantState.Granted || now < Instant.FromDateTimeOffset(grant.ValidFromUtc) || now >= ceilingEnd)
        {
            return Refuse(LeaseIssueRefusal.CeilingNotGranted);
        }

        var (understood, met) = PermissionConstraints.Evaluate(grant.Constraints, chain.Device, request.Origin);
        if (!understood)
        {
            return Refuse(LeaseIssueRefusal.CeilingConstraintUnknown);
        }

        if (!met)
        {
            return Refuse(LeaseIssueRefusal.CeilingConstraintUnmet);
        }

        CapabilityLease lease;
        try
        {
            var expiresAt = LeaseTime.Add(now, request.Lifetime);
            if (expiresAt > ceilingEnd)
            {
                return Refuse(LeaseIssueRefusal.ExceedsCeilingLifetime);
            }

            lease = new CapabilityLease(
                request.Id, chain.Owner, request.Scope, request.Task, request.Holder, request.CapabilityKey, request.ResourceIds,
                request.EffectiveRisk, request.Origin, request.Basis, chain, now, expiresAt, LeaseState.Active, 1);
        }
        catch (Exception exception) when (exception is ArgumentException or OverflowException)
        {
            return Refuse(LeaseIssueRefusal.InvalidRequest);
        }

        try
        {
            // A replay of the same request is a duplicate and must not write a second "issued" fact.
            if (await _store.ReadAsync(lease.Id, cancellationToken).ConfigureAwait(false) is not null)
            {
                return Refuse(LeaseIssueRefusal.Duplicate);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Refuse(LeaseIssueRefusal.StoreUnavailable);
        }

        try
        {
            await _events.WriteAsync(new CapabilityLeaseEvent(LeaseEventKind.Issued, lease, now), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Refuse(LeaseIssueRefusal.AuditUnavailable);
        }

        try
        {
            return await _store.TryCreateAsync(lease, cancellationToken).ConfigureAwait(false)
                ? new LeaseIssueResult(lease, LeaseIssueRefusal.None)
                : Refuse(LeaseIssueRefusal.Duplicate);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Refuse(LeaseIssueRefusal.StoreUnavailable);
        }
    }

    /// <summary>
    /// Ends a lease at the owner's request. Only the lease's own owner may revoke it. Revocation is stored first, so the lease is dead
    /// even if the lifecycle fact cannot be written (<see cref="LeaseTransition.EndRecorded"/> then says it is still owed). Revoking a
    /// lease that has already ended changes nothing. A lease past its expiry ends as expired, which is what it already was.
    /// </summary>
    public async ValueTask<Outcome<LeaseTransition>> RevokeAsync(
        CapabilityLeaseId id,
        HumanPrincipal revokedBy,
        LeaseRevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        if (!id.IsValid)
        {
            throw new ArgumentException("A capability lease identity is required.", nameof(id));
        }

        ArgumentNullException.ThrowIfNull(revokedBy);
        if (!Enum.IsDefined(reason) || reason == LeaseRevocationReason.None)
        {
            throw new ArgumentOutOfRangeException(nameof(reason));
        }

        for (var attempt = 0; attempt < MaximumCompareAndSwapAttempts; attempt++)
        {
            var lease = await _store.ReadAsync(id, cancellationToken).ConfigureAwait(false);
            if (lease is null)
            {
                return Failure<LeaseTransition>("state.not_found");
            }

            if (revokedBy != lease.Owner)
            {
                return Failure<LeaseTransition>("perm.capability_denied");
            }

            if (lease.IsTerminal)
            {
                return Outcome.Success(new LeaseTransition(lease, false, lease.EndEventRecorded));
            }

            var now = Now();
            var ended = now >= lease.ExpiresAt ? lease.End(LeaseState.Expired, now) : lease.End(LeaseState.Revoked, now, reason);
            if (!await _store.TryReplaceAsync(id, lease.Version, ended, cancellationToken).ConfigureAwait(false))
            {
                continue;
            }

            var recorded = await SettleAsync(ended, cancellationToken).ConfigureAwait(false);
            return Outcome.Success(new LeaseTransition(recorded.Lease, true, recorded.Recorded));
        }

        return Failure<LeaseTransition>("conflict.revision_mismatch");
    }

    /// <summary>
    /// Ends every lease of a task when the task ends (CL-02): a lease past its expiry ends as expired, any other as task-ended. Leases
    /// that ended without their fact being recorded are retried too. The host calls this when the task ends; nothing here observes tasks.
    /// </summary>
    public ValueTask<LeaseSweep> EndTaskAsync(TaskId task, CancellationToken cancellationToken = default)
    {
        if (task.Value == Guid.Empty)
        {
            throw new ArgumentException("A task identity is required.", nameof(task));
        }

        return SweepAsync(task, dueOnly: false, cancellationToken);
    }

    /// <summary>Ends every lease whose time is over and retries every end fact that is still owed.</summary>
    public ValueTask<LeaseSweep> ExpireDueAsync(CancellationToken cancellationToken = default) =>
        SweepAsync(null, dueOnly: true, cancellationToken);

    /// <summary>
    /// Judges one use of a lease at the moment of use. Anything but <see cref="LeaseUseVerdict.Valid"/> refuses the use. A use that is
    /// not exactly what the lease covers is out of scope whatever the lease's state, so a caller learns nothing about another lease.
    /// </summary>
    public async ValueTask<LeaseUseVerdict> ValidateAsync(LeaseUse use, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(use);
        for (var attempt = 0; attempt < MaximumCompareAndSwapAttempts; attempt++)
        {
            var lease = await _store.ReadAsync(use.Lease, cancellationToken).ConfigureAwait(false);
            if (lease is null || !lease.Covers(use))
            {
                return LeaseUseVerdict.OutOfScope;
            }

            if (lease.IsTerminal)
            {
                return lease.State == LeaseState.Revoked ? LeaseUseVerdict.Revoked : LeaseUseVerdict.Expired;
            }

            var now = Now();
            if (now < lease.ExpiresAt)
            {
                return LeaseUseVerdict.Valid;
            }

            // Expiry is enforced at use and stored when seen: a wall clock set back afterwards cannot bring the lease back.
            var expired = lease.End(LeaseState.Expired, now);
            if (await _store.TryReplaceAsync(lease.Id, lease.Version, expired, cancellationToken).ConfigureAwait(false))
            {
                _ = await SettleAsync(expired, cancellationToken).ConfigureAwait(false);
                return LeaseUseVerdict.Expired;
            }
        }

        return LeaseUseVerdict.Unknown;
    }

    private static LeaseIssueResult Refuse(LeaseIssueRefusal refusal) => new(null, refusal);

    private static Outcome<T> Failure<T>(string code) => Outcome.Failure<T>(TypedFailure.Create(code));

    /// <summary>
    /// The instant lease time is judged at: the wall clock, but never earlier than the monotonic time since this manager started and never
    /// earlier than any instant it has already judged. A wall-clock step back therefore cannot extend a lease, and a step forward
    /// shortens it. Across a restart only the wall clock is available.
    /// </summary>
    private Instant Now()
    {
        var wall = _clock.GetCurrentInstant();
        var monotonicFloor = LeaseTime.Add(_anchorWall, _clock.GetElapsedTime(_anchorMonotonic, _clock.GetTimestamp()));
        lock (_timeLock)
        {
            _highWater = LeaseTime.Max(_highWater, LeaseTime.Max(wall, monotonicFloor));
            return _highWater;
        }
    }

    /// <summary>
    /// Writes the end fact of a terminal lease when it is still owed and then marks it written. It never throws (but for the caller's own
    /// cancellation): a sink or store failure leaves the fact owed, to be retried by a sweep. The fact is written at least once: a failure
    /// to mark it after it was written, or a sweep that runs while the ending call is still writing, can write it a second time, and the
    /// lease identity with the event kind identifies it because a lease ends exactly once.
    /// </summary>
    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "A failing sink or store leaves the end fact owed instead of undoing an ended lease; no exception text is retained.")]
    private async ValueTask<(CapabilityLease Lease, bool Recorded)> SettleAsync(CapabilityLease lease, CancellationToken cancellationToken)
    {
        if (lease.EndEventRecorded)
        {
            return (lease, true);
        }

        var kind = lease.State switch
        {
            LeaseState.Revoked => LeaseEventKind.Revoked,
            LeaseState.Expired => LeaseEventKind.Expired,
            LeaseState.TaskEnded => LeaseEventKind.TaskEnded,
            _ => LeaseEventKind.None,
        };
        if (kind == LeaseEventKind.None || lease.EndedAt is not { } endedAt)
        {
            return (lease, false);
        }

        try
        {
            await _events.WriteAsync(new CapabilityLeaseEvent(kind, lease, endedAt), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return (lease, false);
        }

        var marked = lease.WithEndEventRecorded();
        try
        {
            if (await _store.TryReplaceAsync(lease.Id, lease.Version, marked, cancellationToken).ConfigureAwait(false))
            {
                return (marked, true);
            }

            var current = await _store.ReadAsync(lease.Id, cancellationToken).ConfigureAwait(false);
            return current is null ? (lease, true) : (current, current.EndEventRecorded);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return (lease, false);
        }
    }

    private async ValueTask<LeaseSweep> SweepAsync(TaskId? task, bool dueOnly, CancellationToken cancellationToken)
    {
        var ended = 0;
        var recorded = 0;
        var owed = 0;
        var seen = new HashSet<CapabilityLeaseId>();
        for (var page = 0; page < MaximumSweepPages; page++)
        {
            // Leases already handled stay listed when their fact is still owed, so the page grows by what was seen to reach the rest.
            var limit = SweepPageSize + seen.Count;
            var batch = await _store.ListUnsettledAsync(task, dueOnly ? Now() : null, limit, cancellationToken).ConfigureAwait(false);
            var progressed = false;
            foreach (var lease in batch)
            {
                if (!seen.Add(lease.Id))
                {
                    continue;
                }

                progressed = true;
                var current = lease;
                if (!current.IsTerminal)
                {
                    var at = Now();
                    var next = at >= current.ExpiresAt ? current.End(LeaseState.Expired, at) : current.End(LeaseState.TaskEnded, at);
                    if (!await _store.TryReplaceAsync(current.Id, current.Version, next, cancellationToken).ConfigureAwait(false))
                    {
                        continue;
                    }

                    ended++;
                    current = next;
                }

                var settled = await SettleAsync(current, cancellationToken).ConfigureAwait(false);
                if (settled.Recorded)
                {
                    recorded++;
                }
                else
                {
                    owed++;
                }
            }

            if (!progressed || batch.Count < limit)
            {
                break;
            }
        }

        return new LeaseSweep(ended, recorded, owed);
    }
}
