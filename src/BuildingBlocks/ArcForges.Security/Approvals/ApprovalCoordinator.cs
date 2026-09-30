// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;

namespace ArcForges.Security.Approvals;

/// <summary>
/// Coordinates one-action human approvals. An approval is a provisional decision only; it never
/// becomes a standing permission, step-up proof, or execution grant.
/// </summary>
public sealed class ApprovalCoordinator
{
    public static TimeSpan MaximumLifetime { get; } = TimeSpan.FromMinutes(10);

    private const int MaximumCompareAndSwapAttempts = 16;
    private readonly IClock _clock;
    private readonly IApprovalStore _store;

    public ApprovalCoordinator(IClock clock, IApprovalStore store)
    {
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(store);
        _clock = clock;
        _store = store;
    }

    /// <summary>Creates a durable pending action binding with an expiry no longer than ten minutes.</summary>
    public async ValueTask<Outcome<ApprovalMutation>> RequestAsync(ApprovalIntent intent, TimeSpan lifetime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(intent);
        if (lifetime <= TimeSpan.Zero || lifetime > MaximumLifetime)
        {
            return Failure<ApprovalMutation>("validation.invalid_request");
        }

        var requestedAt = _clock.GetCurrentInstant();
        Instant expiresAt;
        try
        {
            expiresAt = Add(requestedAt, lifetime);
        }
        catch (ArgumentOutOfRangeException)
        {
            return Failure<ApprovalMutation>("validation.invalid_request");
        }

        var pending = new ApprovalSnapshot(intent.ApprovalId, intent.CommandId, intent.Owner,
            intent.OperationId, intent.TargetResourceId, intent.TargetRevision, intent.EffectSha256,
            intent.EffectiveRisk, requestedAt, expiresAt, ApprovalState.Pending, version: 1);
        if (await _store.TryCreatePendingAsync(pending, cancellationToken).ConfigureAwait(false))
        {
            return Outcome.Success(new ApprovalMutation(pending, Applied: true));
        }

        var existing = await _store.ReadAsync(intent.ApprovalId, cancellationToken).ConfigureAwait(false);
        if (existing is not null && existing.ToIntent().Matches(intent))
        {
            return Outcome.Success(new ApprovalMutation(existing, Applied: false));
        }

        return Failure<ApprovalMutation>("validation.invalid_request");
    }

    /// <summary>Reads an approval and durably marks it expired at or after its exact expiry instant.</summary>
    public async ValueTask<Outcome<ApprovalSnapshot>> GetAsync(Guid approvalId,
        CancellationToken cancellationToken = default)
    {
        if (approvalId == Guid.Empty)
        {
            return Failure<ApprovalSnapshot>("validation.invalid_request");
        }

        var current = await _store.ReadAsync(approvalId, cancellationToken).ConfigureAwait(false);
        if (current is null)
        {
            return Failure<ApprovalSnapshot>("perm.approval_required");
        }

        return await ExpireIfNeededAsync(current, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Applies one approve/deny decision with an atomic version check and idempotent replay.</summary>
    public async ValueTask<Outcome<ApprovalMutation>> DecideAsync(Guid approvalId, ApprovalDecisionRequest decision,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(decision);
        if (approvalId == Guid.Empty)
        {
            return Failure<ApprovalMutation>("validation.invalid_request");
        }

        for (var attempt = 0; attempt < MaximumCompareAndSwapAttempts; attempt++)
        {
            var current = await _store.ReadAsync(approvalId, cancellationToken).ConfigureAwait(false);
            if (current is null)
            {
                return Failure<ApprovalMutation>("perm.approval_required");
            }

            var now = _clock.GetCurrentInstant();
            if (current.State == ApprovalState.Pending && now >= current.ExpiresAt)
            {
                var expired = current.Resolve(ApprovalState.Expired, now);
                if (await _store.TryResolveAsync(approvalId, current.Version, expired, cancellationToken).ConfigureAwait(false))
                {
                    return Failure<ApprovalMutation>("perm.approval_expired");
                }

                continue;
            }

            var targetState = decision.Kind == ApprovalDecisionKind.Approve ? ApprovalState.Approved : ApprovalState.Denied;
            if (current.State == targetState && current.Decision is { } existingDecision && existingDecision.Matches(decision))
            {
                return Outcome.Success(new ApprovalMutation(current, Applied: false));
            }

            if (current.State != ApprovalState.Pending)
            {
                return Failure<ApprovalMutation>(current.State == ApprovalState.Expired
                    ? "perm.approval_expired" : "perm.approval_required");
            }

            var recordedDecision = new ApprovalDecision(decision.DecisionId, decision.Kind, decision.DecidedBy,
                decision.Device, decision.Origin, now, decision.Reason);
            var resolved = current.Resolve(targetState, now, recordedDecision);
            if (await _store.TryResolveAsync(approvalId, current.Version, resolved, cancellationToken).ConfigureAwait(false))
            {
                return Outcome.Success(new ApprovalMutation(resolved, Applied: true));
            }
        }

        return Failure<ApprovalMutation>("capacity.busy");
    }

    /// <summary>Allows the original human requester to cancel only while the request is pending.</summary>
    public async ValueTask<Outcome<ApprovalMutation>> CancelAsync(Guid approvalId, HumanPrincipal requester,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requester);
        if (approvalId == Guid.Empty)
        {
            return Failure<ApprovalMutation>("validation.invalid_request");
        }

        for (var attempt = 0; attempt < MaximumCompareAndSwapAttempts; attempt++)
        {
            var current = await _store.ReadAsync(approvalId, cancellationToken).ConfigureAwait(false);
            if (current is null)
            {
                return Failure<ApprovalMutation>("perm.approval_required");
            }

            if (current.Owner != requester)
            {
                return Failure<ApprovalMutation>("perm.capability_denied");
            }

            var now = _clock.GetCurrentInstant();
            if (current.State == ApprovalState.Pending && now >= current.ExpiresAt)
            {
                var expired = current.Resolve(ApprovalState.Expired, now);
                if (await _store.TryResolveAsync(approvalId, current.Version, expired, cancellationToken).ConfigureAwait(false))
                {
                    return Failure<ApprovalMutation>("perm.approval_expired");
                }

                continue;
            }

            if (current.State == ApprovalState.Cancelled && current.CancelledBy == requester)
            {
                return Outcome.Success(new ApprovalMutation(current, Applied: false));
            }

            if (current.State != ApprovalState.Pending)
            {
                return Failure<ApprovalMutation>(current.State == ApprovalState.Expired
                    ? "perm.approval_expired" : "perm.approval_required");
            }

            var cancelled = current.Resolve(ApprovalState.Cancelled, now, cancelledBy: requester);
            if (await _store.TryResolveAsync(approvalId, current.Version, cancelled, cancellationToken).ConfigureAwait(false))
            {
                return Outcome.Success(new ApprovalMutation(cancelled, Applied: true));
            }
        }

        return Failure<ApprovalMutation>("capacity.busy");
    }

    private async ValueTask<Outcome<ApprovalSnapshot>> ExpireIfNeededAsync(ApprovalSnapshot current,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < MaximumCompareAndSwapAttempts; attempt++)
        {
            if (current.State != ApprovalState.Pending || _clock.GetCurrentInstant() < current.ExpiresAt)
            {
                return Outcome.Success(current);
            }

            var expired = current.Resolve(ApprovalState.Expired, _clock.GetCurrentInstant());
            if (await _store.TryResolveAsync(current.ApprovalId, current.Version, expired, cancellationToken).ConfigureAwait(false))
            {
                return Outcome.Success(expired);
            }

            var reread = await _store.ReadAsync(current.ApprovalId, cancellationToken).ConfigureAwait(false);
            if (reread is null)
            {
                return Failure<ApprovalSnapshot>("perm.approval_required");
            }

            current = reread;
        }

        return Failure<ApprovalSnapshot>("capacity.busy");
    }

    private static Instant Add(Instant instant, TimeSpan duration)
    {
        var wholeSeconds = duration.Ticks / TimeSpan.TicksPerSecond;
        var remainingTicks = duration.Ticks % TimeSpan.TicksPerSecond;
        var seconds = checked(instant.UnixSeconds + wholeSeconds);
        var nanoseconds = instant.Nanoseconds + checked((uint)(remainingTicks * 100));
        if (nanoseconds >= 1_000_000_000U)
        {
            seconds = checked(seconds + 1);
            nanoseconds -= 1_000_000_000U;
        }

        return new Instant(seconds, nanoseconds);
    }

    private static Outcome<T> Failure<T>(string code) => Outcome.Failure<T>(TypedFailure.Create(code));
}
