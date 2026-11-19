// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store;

internal sealed record StoredResourcePolicy(string ScopeKind, string? ScopeId, long Revision, string PolicyJson);

internal enum StoredRunLimitStatus
{
    Pending = 1,
    Effective = 2,
    Degraded = 3,
    Failed = 4,
    Unsupported = 5,
}

internal sealed record StoredRunLimit(
    string Dimension,
    string Unit,
    long DesiredRevision,
    string DesiredValue,
    string? AppliedValue = null,
    string? ReadbackValue = null,
    DateTimeOffset? AppliedAt = null,
    DateTimeOffset? ReadbackAt = null,
    StoredRunLimitStatus Status = StoredRunLimitStatus.Pending,
    string Reason = "native_readback_pending",
    string? BoundaryIdentity = null);

internal sealed record StoredRunLimitObservation(
    StoredRunLimitStatus Status,
    string Reason,
    string? AppliedValue = null,
    string? ReadbackValue = null,
    DateTimeOffset? AppliedAt = null,
    DateTimeOffset? ReadbackAt = null);

/// <summary>Owner-scoped desired policy and limit evidence in the existing V2 resource tables.</summary>
internal static class ResourceStateRecords
{
    private const string VisiblePolicy = """
        (($scope = 'node' AND $id = $owner)
         OR ($scope = 'sandbox' AND EXISTS(
             SELECT 1 FROM sandbox WHERE sandbox_id = $id AND owner_id = $owner))
         OR ($scope = 'run' AND EXISTS(
             SELECT 1 FROM run AS r JOIN sandbox AS s ON s.sandbox_id = r.sandbox_id
             WHERE r.run_id = $id AND s.owner_id = $owner)))
        """;

    private const string MatchedBoundary = """
        EXISTS(
            SELECT 1 FROM run AS r JOIN sandbox AS s ON s.sandbox_id = r.sandbox_id
            JOIN supervisor_identity AS o ON o.run_id = r.run_id
            WHERE r.run_id = $run AND s.owner_id = $owner AND r.epoch = $epoch
              AND o.control_epoch = r.epoch AND o.boundary_identity = $boundary
              AND r.state IN ($state1,$state2))
        """;

    internal static StoredResourcePolicy? GetPolicy(StoreReader reader, string ownerId, string scopeKind, string? scopeId)
    {
        string id = PolicyKey(ownerId, scopeKind, scopeId);
        using var command = reader.CreateCommand("""
            SELECT revision,policy_json FROM resource_policy WHERE scope_kind=$scope AND scope_id=$id AND
            """ + " " + VisiblePolicy);
        StoreReader.Bind(command, [("$scope", scopeKind), ("$id", id), ("$owner", ownerId)]);
        using var row = command.ExecuteReader();
        return row.Read() ? new(scopeKind, scopeId, row.GetInt64(0), row.GetString(1)) : null;
    }

    /// <summary>Inserts a missing scope or replaces exactly one existing revision in the caller's receipt transaction.</summary>
    internal static bool TryWritePolicy(StoreTransaction transaction, string ownerId, StoredResourcePolicy policy, long? expectedRevision)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(policy);
        string id = PolicyKey(ownerId, policy.ScopeKind, policy.ScopeId);
        if (policy.Revision <= 0 || expectedRevision is <= 0 or long.MaxValue
            || (expectedRevision is long prior && policy.Revision != prior + 1))
        {
            throw new ArgumentException("The resource policy revision is invalid.", nameof(policy));
        }

        using var json = JsonDocument.Parse(policy.PolicyJson);
        if (json.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("The resource policy must be an object.", nameof(policy));
        }

        return expectedRevision is null
            ? transaction.Execute("""
                INSERT INTO resource_policy(scope_kind,scope_id,revision,policy_json)
                SELECT $scope,$id,$revision,$policy WHERE
                """ + " " + VisiblePolicy + " ON CONFLICT(scope_kind,scope_id) DO NOTHING;",
                ("$scope", policy.ScopeKind), ("$id", id), ("$owner", ownerId), ("$revision", policy.Revision),
                ("$policy", policy.PolicyJson)) == 1
            : transaction.Execute("""
                UPDATE resource_policy SET revision=$revision,policy_json=$policy
                WHERE scope_kind=$scope AND scope_id=$id AND revision=$expected AND
                """ + " " + VisiblePolicy,
                ("$scope", policy.ScopeKind), ("$id", id), ("$owner", ownerId), ("$revision", policy.Revision),
                ("$policy", policy.PolicyJson), ("$expected", expectedRevision)) == 1;
    }

    internal static IReadOnlyList<StoredRunLimit> ReadLimits(StoreReader reader, string ownerId, string runId)
    {
        using var command = reader.CreateCommand("""
            SELECT l.dimension,l.unit,l.desired_revision,l.desired_value,l.applied_value,l.readback_value,
                   l.applied_utc,l.readback_utc,l.state,l.reason,l.boundary_identity
            FROM limit_application AS l JOIN run AS r ON r.run_id=l.run_id
            JOIN sandbox AS s ON s.sandbox_id=r.sandbox_id
            WHERE l.run_id=$run AND s.owner_id=$owner ORDER BY l.dimension;
            """);
        StoreReader.Bind(command, [("$run", runId), ("$owner", ownerId)]);
        using var rows = command.ExecuteReader();
        var limits = new List<StoredRunLimit>();
        while (rows.Read())
        {
            limits.Add(ReadLimit(rows));
        }

        return limits;
    }

    /// <summary>Creates a pending dimension in the same transaction that inserts the new STARTING Run.</summary>
    internal static bool TryInsertPendingLimit(StoreTransaction transaction, string ownerId, string runId, string runEpoch,
        StoredRunLimit request)
    {
        RequireFull(transaction);
        ValidatePending(request);
        if (request is not { DesiredRevision: 1, BoundaryIdentity: null })
        {
            throw new ArgumentException("A new Run starts with an unbound first limit revision.", nameof(request));
        }

        return transaction.Execute("""
            INSERT INTO limit_application(run_id,dimension,unit,desired_revision,desired_value,state,reason,boundary_identity)
            SELECT r.run_id,$dimension,$unit,$revision,$value,'pending',$reason,''
            FROM run AS r JOIN sandbox AS s ON s.sandbox_id=r.sandbox_id
            WHERE r.run_id=$run AND s.owner_id=$owner AND r.epoch=$epoch AND r.state=$starting
              AND NOT EXISTS(SELECT 1 FROM supervisor_identity WHERE run_id=r.run_id)
            ON CONFLICT(run_id,dimension) DO NOTHING;
            """, ("$dimension", request.Dimension), ("$unit", request.Unit), ("$revision", request.DesiredRevision),
            ("$value", request.DesiredValue), ("$reason", request.Reason), ("$run", runId), ("$owner", ownerId),
            ("$epoch", runEpoch), ("$starting", (int)StoredRunState.Starting)) == 1;
    }

    /// <summary>Associates only previously unbound pending limits with the Run's original verified boundary.</summary>
    internal static int BindPendingLimits(StoreTransaction transaction, string ownerId, string runId, string runEpoch,
        string boundaryIdentity)
    {
        RequireFull(transaction);
        ValidateBoundary(boundaryIdentity);
        return transaction.Execute("""
            UPDATE limit_application SET boundary_identity=$boundary
            WHERE run_id=$run AND boundary_identity='' AND state='pending' AND
            """ + " " + MatchedBoundary,
            ("$run", runId), ("$owner", ownerId), ("$epoch", runEpoch), ("$boundary", boundaryIdentity),
            ("$state1", (int)StoredRunState.Starting), ("$state2", (int)StoredRunState.Stopping));
    }

    /// <summary>Advances desired policy while retaining the last actual setter and reader facts.</summary>
    internal static bool TrySetLimitDesired(StoreTransaction transaction, string ownerId, string runId, string runEpoch,
        string boundaryIdentity, long expectedRevision, StoredRunLimit desired)
    {
        RequireFull(transaction);
        ValidateBoundary(boundaryIdentity);
        ValidatePending(desired);
        if (expectedRevision <= 0 || desired.DesiredRevision <= expectedRevision
            || (desired.BoundaryIdentity is { } assigned && assigned != boundaryIdentity))
        {
            throw new ArgumentException("The desired limit must advance the original boundary's revision.", nameof(desired));
        }

        return transaction.Execute("""
            UPDATE limit_application SET desired_revision=$revision,desired_value=$value,state='pending',reason=$reason
            WHERE run_id=$run AND dimension=$dimension AND unit=$unit AND desired_revision=$expected
              AND boundary_identity=$boundary AND state<>'pending' AND
            """ + " " + MatchedBoundary,
            ("$revision", desired.DesiredRevision), ("$value", desired.DesiredValue), ("$reason", desired.Reason),
            ("$run", runId), ("$dimension", desired.Dimension), ("$unit", desired.Unit), ("$expected", expectedRevision),
            ("$boundary", boundaryIdentity), ("$owner", ownerId), ("$epoch", runEpoch),
            ("$state1", (int)StoredRunState.Running), ("$state2", (int)StoredRunState.Running)) == 1;
    }

    /// <summary>Settles one pending revision using only facts observed on the same held boundary.</summary>
    internal static bool TryObserveLimit(StoreTransaction transaction, string ownerId, string runId, string runEpoch,
        string boundaryIdentity, string dimension, long desiredRevision, StoredRunLimitObservation observation)
    {
        RequireFull(transaction);
        ValidateBoundary(boundaryIdentity);
        ArgumentNullException.ThrowIfNull(observation);
        if (!Code(dimension) || desiredRevision <= 0 || !Code(observation.Reason)
            || observation.Status is StoredRunLimitStatus.Pending
            || !ValidFact(observation.AppliedValue, observation.AppliedAt)
            || !ValidFact(observation.ReadbackValue, observation.ReadbackAt)
            || (observation.Status == StoredRunLimitStatus.Effective
                && (observation.AppliedAt is null || observation.ReadbackAt is null
                    || observation.AppliedValue != observation.ReadbackValue)))
        {
            throw new ArgumentException("The limit outcome lacks valid native evidence.", nameof(observation));
        }

        return transaction.Execute("""
            UPDATE limit_application
            SET state=$state,reason=$reason,applied_value=coalesce($applied,applied_value),
                readback_value=coalesce($readback,readback_value),applied_utc=coalesce($appliedAt,applied_utc),
                readback_utc=coalesce($readbackAt,readback_utc)
            WHERE run_id=$run AND dimension=$dimension AND desired_revision=$revision
              AND boundary_identity=$boundary AND state='pending' AND
            """ + " " + MatchedBoundary,
            ("$state", StatusCode(observation.Status)), ("$reason", observation.Reason),
            ("$applied", observation.AppliedValue), ("$readback", observation.ReadbackValue),
            ("$appliedAt", FormatTime(observation.AppliedAt)), ("$readbackAt", FormatTime(observation.ReadbackAt)),
            ("$run", runId), ("$dimension", dimension), ("$revision", desiredRevision), ("$boundary", boundaryIdentity),
            ("$owner", ownerId), ("$epoch", runEpoch), ("$state1", (int)StoredRunState.Starting),
            ("$state2", (int)StoredRunState.Running)) == 1;
    }

    private static StoredRunLimit ReadLimit(SqliteDataReader row)
    {
        string boundary = row.GetString(10);
        return new(row.GetString(0), row.GetString(1), row.GetInt64(2), row.GetString(3), StringOrNull(row, 4),
            StringOrNull(row, 5), ParseTime(StringOrNull(row, 6)), ParseTime(StringOrNull(row, 7)),
            ParseStatus(row.GetString(8)), row.GetString(9), boundary.Length == 0 ? null : boundary);
    }

    private static string PolicyKey(string owner, string scope, string? id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(owner);
        return scope switch
        {
            "node" when id is null => owner,
            "sandbox" or "run" when id is { Length: 32 } && id.All(char.IsAsciiHexDigitLower) => id,
            _ => throw new ArgumentException("The resource policy scope identity is invalid.", nameof(id)),
        };
    }

    private static StoredRunLimitStatus ParseStatus(string status) => status switch
    {
        "pending" => StoredRunLimitStatus.Pending,
        "effective" => StoredRunLimitStatus.Effective,
        "degraded" => StoredRunLimitStatus.Degraded,
        "failed" => StoredRunLimitStatus.Failed,
        "unsupported" => StoredRunLimitStatus.Unsupported,
        _ => throw new InvalidDataException("The stored resource limit status is invalid."),
    };

    private static string StatusCode(StoredRunLimitStatus status) => status switch
    {
        StoredRunLimitStatus.Effective => "effective",
        StoredRunLimitStatus.Degraded => "degraded",
        StoredRunLimitStatus.Failed => "failed",
        StoredRunLimitStatus.Unsupported => "unsupported",
        _ => throw new ArgumentOutOfRangeException(nameof(status)),
    };

    private static void ValidatePending(StoredRunLimit limit)
    {
        ArgumentNullException.ThrowIfNull(limit);
        if (limit is not { Status: StoredRunLimitStatus.Pending, AppliedValue: null, ReadbackValue: null, AppliedAt: null, ReadbackAt: null }
            || !Code(limit.Dimension) || !Code(limit.Unit) || limit.DesiredRevision <= 0 || !LimitValue(limit.DesiredValue)
            || !Code(limit.Reason))
        {
            throw new ArgumentException("The pending resource limit is invalid.", nameof(limit));
        }
    }

    private static void ValidateBoundary(string boundary)
    {
        if (boundary.Length is 0 or > 2048 || boundary.Any(char.IsControl))
        {
            throw new ArgumentException("The Run boundary identity is invalid.", nameof(boundary));
        }
    }

    private static bool Code(string code) => code.Length is > 0 and <= 128
        && code.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.' or ':' or '/');

    private static bool LimitValue(string value) => value is "max" or "unlimited"
        || (ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong number)
            && value == number.ToString(CultureInfo.InvariantCulture));

    private static bool ValidFact(string? value, DateTimeOffset? at) =>
        value is null ? at is null : at is not null && LimitValue(value);

    private static string? StringOrNull(SqliteDataReader row, int index) => row.IsDBNull(index) ? null : row.GetString(index);

    private static string? FormatTime(DateTimeOffset? time) => time?.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset? ParseTime(string? time) => time is null ? null
        : DateTimeOffset.Parse(time, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    private static void RequireFull(StoreTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.Durability != CommitDurability.Full)
        {
            throw new InvalidOperationException("Resource policy and limit evidence require a FULL transaction.");
        }
    }
}
