// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;

namespace ArcForges.Security.Approvals;

public enum ApprovalState
{
    None = 0,
    Pending = 1,
    Approved = 2,
    Denied = 3,
    Cancelled = 4,
    Expired = 5,
}

public enum ApprovalDecisionKind
{
    None = 0,
    Approve = 1,
    Deny = 2,
}

public enum ApprovalOrigin
{
    None = 0,
    Local = 1,
    Remote = 2,
}

/// <summary>
/// Exact, immutable action binding for one approval request. The owner, command, operation,
/// target and revision, proposed-effect digest, and effective risk are data to compare; none
/// independently authenticates a caller or grants permission.
/// </summary>
public sealed class ApprovalIntent
{
    public ApprovalIntent(Guid approvalId, CommandId commandId, HumanPrincipal owner, string operationId,
        string targetResourceId, string targetRevision, string effectSha256, RiskLevel effectiveRisk)
    {
        if (approvalId == Guid.Empty)
        {
            throw new ArgumentException("A nonempty approval identity is required.", nameof(approvalId));
        }

        _ = commandId.ToWire();
        ArgumentNullException.ThrowIfNull(owner);
        SecurityText.Validate(operationId, 128, nameof(operationId));
        SecurityText.Validate(targetResourceId, 512, nameof(targetResourceId));
        SecurityText.Validate(targetRevision, 256, nameof(targetRevision));
        SecurityText.ValidateSha256(effectSha256, nameof(effectSha256));
        if (!Enum.IsDefined(effectiveRisk))
        {
            throw new ArgumentOutOfRangeException(nameof(effectiveRisk));
        }

        ApprovalId = approvalId;
        CommandId = commandId;
        Owner = owner;
        OperationId = operationId;
        TargetResourceId = targetResourceId;
        TargetRevision = targetRevision;
        EffectSha256 = effectSha256;
        EffectiveRisk = effectiveRisk;
    }

    public Guid ApprovalId { get; }
    public CommandId CommandId { get; }
    public HumanPrincipal Owner { get; }
    public string OperationId { get; }
    public string TargetResourceId { get; }
    public string TargetRevision { get; }
    public string EffectSha256 { get; }
    public RiskLevel EffectiveRisk { get; }

    internal bool Matches(ApprovalIntent other) =>
        ApprovalId == other.ApprovalId && CommandId == other.CommandId && Owner == other.Owner &&
        OperationId == other.OperationId && TargetResourceId == other.TargetResourceId &&
        TargetRevision == other.TargetRevision && EffectSha256 == other.EffectSha256 &&
        EffectiveRisk == other.EffectiveRisk;
}

/// <summary>Recorded human decision metadata. Identity fields are claims for the caller's upstream authentication boundary.</summary>
public sealed record ApprovalDecision
{
    public ApprovalDecision(Guid decisionId, ApprovalDecisionKind kind, HumanPrincipal decidedBy, DeviceId device,
        ApprovalOrigin origin, Instant decidedAt, string? reason = null)
    {
        if (decisionId == Guid.Empty)
        {
            throw new ArgumentException("A nonempty decision identity is required.", nameof(decisionId));
        }

        if (!Enum.IsDefined(kind) || kind == ApprovalDecisionKind.None)
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        ArgumentNullException.ThrowIfNull(decidedBy);
        _ = device.ToWire();
        if (!Enum.IsDefined(origin) || origin == ApprovalOrigin.None)
        {
            throw new ArgumentOutOfRangeException(nameof(origin));
        }

        if (reason is not null)
        {
            SecurityText.Validate(reason, 512, nameof(reason), allowEmpty: true);
        }

        DecisionId = decisionId;
        Kind = kind;
        DecidedBy = decidedBy;
        Device = device;
        Origin = origin;
        DecidedAt = decidedAt;
        Reason = reason;
    }

    public Guid DecisionId { get; }
    public ApprovalDecisionKind Kind { get; }
    public HumanPrincipal DecidedBy { get; }
    public DeviceId Device { get; }
    public ApprovalOrigin Origin { get; }
    public Instant DecidedAt { get; }
    public string? Reason { get; }

    internal bool Matches(ApprovalDecisionRequest request) => DecisionId == request.DecisionId &&
        Kind == request.Kind && DecidedBy == request.DecidedBy && Device == request.Device &&
        Origin == request.Origin && Reason == request.Reason;
}

/// <summary>Decision input without a caller-controlled timestamp; the coordinator records its own clock instant.</summary>
public sealed record ApprovalDecisionRequest
{
    public ApprovalDecisionRequest(Guid decisionId, ApprovalDecisionKind kind, HumanPrincipal decidedBy,
        DeviceId device, ApprovalOrigin origin, string? reason = null)
    {
        if (decisionId == Guid.Empty)
        {
            throw new ArgumentException("A nonempty decision identity is required.", nameof(decisionId));
        }

        if (!Enum.IsDefined(kind) || kind == ApprovalDecisionKind.None)
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        ArgumentNullException.ThrowIfNull(decidedBy);
        _ = device.ToWire();
        if (!Enum.IsDefined(origin) || origin == ApprovalOrigin.None)
        {
            throw new ArgumentOutOfRangeException(nameof(origin));
        }

        if (reason is not null)
        {
            SecurityText.Validate(reason, 512, nameof(reason), allowEmpty: true);
        }

        DecisionId = decisionId;
        Kind = kind;
        DecidedBy = decidedBy;
        Device = device;
        Origin = origin;
        Reason = reason;
    }

    public Guid DecisionId { get; }
    public ApprovalDecisionKind Kind { get; }
    public HumanPrincipal DecidedBy { get; }
    public DeviceId Device { get; }
    public ApprovalOrigin Origin { get; }
    public string? Reason { get; }
}

/// <summary>
/// Durable approval aggregate. Implementations must atomically compare versions across processes;
/// returning success from a write means its complete snapshot is durably committed.
/// </summary>
public sealed class ApprovalSnapshot
{
    public ApprovalSnapshot(Guid approvalId, CommandId commandId, HumanPrincipal owner, string operationId,
        string targetResourceId, string targetRevision, string effectSha256, RiskLevel effectiveRisk,
        Instant requestedAt, Instant expiresAt, ApprovalState state, long version,
        Instant? resolvedAt = null, ApprovalDecision? decision = null, HumanPrincipal? cancelledBy = null)
    {
        if (approvalId == Guid.Empty)
        {
            throw new ArgumentException("A nonempty approval identity is required.", nameof(approvalId));
        }

        _ = commandId.ToWire();
        ArgumentNullException.ThrowIfNull(owner);
        SecurityText.Validate(operationId, 128, nameof(operationId));
        SecurityText.Validate(targetResourceId, 512, nameof(targetResourceId));
        SecurityText.Validate(targetRevision, 256, nameof(targetRevision));
        SecurityText.ValidateSha256(effectSha256, nameof(effectSha256));
        if (!Enum.IsDefined(effectiveRisk) || !Enum.IsDefined(state) || state == ApprovalState.None || version <= 0 ||
            !SecurityTime.IsBoundedApprovalLifetime(requestedAt, expiresAt))
        {
            throw new ArgumentException("The approval snapshot has invalid risk, state, version, or lifetime.");
        }

        if ((state == ApprovalState.Pending && (resolvedAt is not null || decision is not null || cancelledBy is not null)) ||
            (state is ApprovalState.Approved or ApprovalState.Denied) &&
                (resolvedAt is null || decision is null || cancelledBy is not null ||
                 (state == ApprovalState.Approved) != (decision.Kind == ApprovalDecisionKind.Approve) ||
                 decision.DecidedAt != resolvedAt.Value || resolvedAt.Value < requestedAt || resolvedAt.Value >= expiresAt) ||
            (state == ApprovalState.Cancelled && (resolvedAt is null || decision is not null || cancelledBy is null ||
                cancelledBy != owner || resolvedAt.Value < requestedAt || resolvedAt.Value >= expiresAt)) ||
            (state == ApprovalState.Expired && (resolvedAt is null || decision is not null || cancelledBy is not null ||
                resolvedAt.Value < expiresAt)))
        {
            throw new ArgumentException("The approval resolution does not match its state.");
        }

        ApprovalId = approvalId;
        CommandId = commandId;
        Owner = owner;
        OperationId = operationId;
        TargetResourceId = targetResourceId;
        TargetRevision = targetRevision;
        EffectSha256 = effectSha256;
        EffectiveRisk = effectiveRisk;
        RequestedAt = requestedAt;
        ExpiresAt = expiresAt;
        State = state;
        Version = version;
        ResolvedAt = resolvedAt;
        Decision = decision;
        CancelledBy = cancelledBy;
    }

    public Guid ApprovalId { get; }
    public CommandId CommandId { get; }
    public HumanPrincipal Owner { get; }
    public string OperationId { get; }
    public string TargetResourceId { get; }
    public string TargetRevision { get; }
    public string EffectSha256 { get; }
    public RiskLevel EffectiveRisk { get; }
    public Instant RequestedAt { get; }
    public Instant ExpiresAt { get; }
    public ApprovalState State { get; }
    public long Version { get; }
    public Instant? ResolvedAt { get; }
    public ApprovalDecision? Decision { get; }
    public HumanPrincipal? CancelledBy { get; }

    internal ApprovalIntent ToIntent() => new(ApprovalId, CommandId, Owner, OperationId, TargetResourceId,
        TargetRevision, EffectSha256, EffectiveRisk);

    internal ApprovalSnapshot Resolve(ApprovalState state, Instant resolvedAt, ApprovalDecision? decision = null,
        HumanPrincipal? cancelledBy = null) => new(ApprovalId, CommandId, Owner, OperationId,
        TargetResourceId, TargetRevision, EffectSha256, EffectiveRisk, RequestedAt, ExpiresAt,
        state, checked(Version + 1), resolvedAt, decision, cancelledBy);
}

public readonly record struct ApprovalMutation(ApprovalSnapshot Snapshot, bool Applied);

/// <summary>
/// Durable, linearizable store contract for approval snapshots. Creation is insert-if-absent;
/// replacement is compare-and-swap on the current version, preserves every immutable action-binding
/// field, increments the version exactly once, and may only commit Pending to a legal terminal
/// transition. A true result is returned only after durable commit, never merely after enqueueing.
/// </summary>
public interface IApprovalStore
{
    ValueTask<ApprovalSnapshot?> ReadAsync(Guid approvalId, CancellationToken cancellationToken = default);

    ValueTask<bool> TryCreatePendingAsync(ApprovalSnapshot snapshot, CancellationToken cancellationToken = default);

    ValueTask<bool> TryResolveAsync(Guid approvalId, long expectedVersion, ApprovalSnapshot resolved,
        CancellationToken cancellationToken = default);
}

internal static class SecurityText
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static void Validate(string value, int maxUtf8Bytes, string parameterName, bool allowEmpty = false)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if ((!allowEmpty && string.IsNullOrWhiteSpace(value)) || value.Length > maxUtf8Bytes || value.Any(char.IsControl))
        {
            throw new ArgumentException("Text is empty, contains control characters, or exceeds its bound.", parameterName);
        }

        if (StrictUtf8.GetByteCount(value) > maxUtf8Bytes)
        {
            throw new ArgumentException("UTF-8 text exceeds its bound.", parameterName);
        }
    }

    internal static void ValidateSha256(string value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (value.Length != 64 || value.Any(character => character is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
        {
            throw new ArgumentException("A canonical uppercase SHA-256 digest is required.", parameterName);
        }
    }
}

internal static class SecurityTime
{
    internal static bool IsBoundedApprovalLifetime(Instant requestedAt, Instant expiresAt)
    {
        if (expiresAt <= requestedAt)
        {
            return false;
        }

        var seconds = expiresAt.UnixSeconds - requestedAt.UnixSeconds;
        var nanoseconds = (long)expiresAt.Nanoseconds - requestedAt.Nanoseconds;
        if (nanoseconds < 0)
        {
            seconds--;
            nanoseconds += 1_000_000_000;
        }

        const long maximumSeconds = 10 * 60;
        return seconds < maximumSeconds || (seconds == maximumSeconds && nanoseconds == 0);
    }
}
