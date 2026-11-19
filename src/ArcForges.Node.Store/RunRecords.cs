// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store;

internal enum StoredRunState
{
    Starting = 1,
    Running = 2,
    Stopping = 3,
    Draining = 4,
    Exited = 5,
    Failed = 6,
    RecoveryRequired = 7,
}

internal enum StoredPayloadStart
{
    Unknown = 1,
    NotStarted = 2,
    Confirmed = 3,
}

/// <summary>A durable Run. SnapshotJson contains only the Core's redacted launch projection.</summary>
internal sealed record StoredRun(
    string RunId,
    string SandboxId,
    long SandboxRevision,
    long Revision,
    StoredRunState State,
    string Epoch,
    string LaunchSha256,
    string SnapshotJson,
    StoredPayloadStart PayloadStarted,
    DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt = null,
    DateTimeOffset? EndedAt = null,
    int? RawExitCode = null,
    string? ExitSource = null,
    string? TerminationReason = null,
    int EffectCertainty = 3);

internal sealed record StoredSupervisorIdentity(
    string RunId,
    string InstanceId,
    string BootId,
    int ProcessId,
    string CreationIdentity,
    string Endpoint,
    string BoundaryIdentity,
    string BackendId,
    string Cohort,
    string ControlEpoch,
    DateTimeOffset LastSeenAt);

/// <summary>Observation from the authenticated owner and native boundary, independently of payload output.</summary>
internal sealed record StoredRunObservation(
    StoredRunState State,
    StoredPayloadStart PayloadStarted,
    int EffectCertainty,
    DateTimeOffset? StartedAt = null,
    DateTimeOffset? EndedAt = null,
    int? RawExitCode = null,
    string? ExitSource = null,
    string? TerminationReason = null,
    bool GroupEmptyVerified = false);

/// <summary>Run and supervisor metadata in the existing schema 16 tables.</summary>
internal static class RunRecords
{
    private const string OwnedRuns = """
        SELECT r.run_id, r.sandbox_id, r.sandbox_revision, r.revision, r.state, r.epoch,
               r.launch_sha256, r.snapshot_json, r.payload_started, r.created_utc, r.started_utc, r.ended_utc,
               r.raw_exit_code, r.exit_source, r.termination_reason, r.effect_certainty
        FROM run AS r JOIN sandbox AS s ON s.sandbox_id=r.sandbox_id
        WHERE s.owner_id=$owner
        """;

    internal static StoredRun? Get(StoreReader reader, string ownerId, string runId)
    {
        using var command = reader.CreateCommand(OwnedRuns + " AND r.run_id=$id;");
        StoreReader.Bind(command, [("$owner", ownerId), ("$id", runId)]);
        using var row = command.ExecuteReader();
        return row.Read() ? Read(row) : null;
    }

    internal static IReadOnlyList<StoredRun> List(
        StoreReader reader, string ownerId, string? sandboxId, string? afterRunId, int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);
        using var command = reader.CreateCommand(OwnedRuns + """
             AND ($sandbox IS NULL OR r.sandbox_id=$sandbox) AND ($after IS NULL OR r.run_id>$after)
             ORDER BY r.run_id LIMIT $count;
            """);
        StoreReader.Bind(command, [("$owner", ownerId), ("$sandbox", sandboxId), ("$after", afterRunId), ("$count", count)]);
        using var rows = command.ExecuteReader();
        var result = new List<StoredRun>();
        while (rows.Read())
        {
            result.Add(Read(rows));
        }

        return result;
    }

    internal static IReadOnlyList<StoredRun> ListNonterminal(StoreReader reader, string ownerId)
    {
        using var command = reader.CreateCommand(OwnedRuns + " AND r.state IN (1,2,3,4,7) ORDER BY r.run_id;");
        StoreReader.Bind(command, [("$owner", ownerId)]);
        using var rows = command.ExecuteReader();
        var runs = new List<StoredRun>();
        while (rows.Read())
        {
            runs.Add(Read(rows));
        }

        return runs;
    }

    /// <summary>Inserts revision one in the same FULL admission transaction as the Start receipt.</summary>
    internal static bool InsertStarting(StoreTransaction transaction, string ownerId, StoredRun run)
    {
        if (run is not
            {
                Revision: 1, State: StoredRunState.Starting, PayloadStarted: StoredPayloadStart.Unknown, EffectCertainty: 3,
                StartedAt: null, EndedAt: null, RawExitCode: null, ExitSource: null, TerminationReason: null,
            })
        {
            throw new ArgumentException("Run admission requires a STARTING reservation without an observed payload effect.", nameof(run));
        }

        return transaction.Execute("""
            INSERT INTO run(run_id, sandbox_id, sandbox_revision, revision, state, epoch,
                            launch_sha256, snapshot_json, payload_started, created_utc, effect_certainty)
            SELECT $id, s.sandbox_id, s.revision, 1, $starting, $epoch, $digest, $snapshot, $payload, $created, 3
            FROM sandbox AS s
            WHERE s.owner_id=$owner AND s.sandbox_id=$sandbox AND s.revision=$sandboxRevision AND s.state=$ready
              AND s.root_identity<>$pending;
            """, ("$id", run.RunId), ("$starting", (int)StoredRunState.Starting), ("$epoch", run.Epoch),
            ("$digest", run.LaunchSha256), ("$snapshot", run.SnapshotJson), ("$payload", (int)StoredPayloadStart.Unknown),
            ("$created", FormatTime(run.CreatedAt)), ("$owner", ownerId), ("$sandbox", run.SandboxId),
            ("$sandboxRevision", run.SandboxRevision), ("$ready", (int)StoredSandboxState.Ready),
            ("$pending", SandboxRecords.PendingRootIdentity)) == 1;
    }

    internal static StoredSupervisorIdentity? GetSupervisor(StoreReader reader, string ownerId, string runId)
    {
        using var command = reader.CreateCommand("""
            SELECT o.run_id, o.instance_id, o.boot_id, o.process_id, o.creation_identity, o.endpoint,
                   o.boundary_identity, o.backend_id, o.cohort, o.control_epoch, o.last_seen_utc
            FROM supervisor_identity AS o JOIN run AS r ON r.run_id=o.run_id
            JOIN sandbox AS s ON s.sandbox_id=r.sandbox_id
            WHERE s.owner_id=$owner AND o.run_id=$id;
            """);
        StoreReader.Bind(command, [("$owner", ownerId), ("$id", runId)]);
        using var row = command.ExecuteReader();
        return row.Read()
            ? new(row.GetString(0), row.GetString(1), row.GetString(2), row.GetInt32(3), row.GetString(4), row.GetString(5),
                row.GetString(6), row.GetString(7), row.GetString(8), row.GetString(9), ParseTime(row.GetString(10)))
            : null;
    }

    /// <summary>Binds an exact owner to this Run epoch once. A late binding can still be recorded during an admitted Stop.</summary>
    internal static bool InsertSupervisor(
        StoreTransaction transaction, string ownerId, string expectedRunEpoch, StoredSupervisorIdentity supervisor)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(supervisor.ProcessId);
        return transaction.Execute("""
            INSERT INTO supervisor_identity(run_id, instance_id, boot_id, process_id, creation_identity, endpoint,
                                            boundary_identity, backend_id, cohort, control_epoch, last_seen_utc)
            SELECT r.run_id, $instance, $boot, $pid, $creation, $endpoint, $boundary, $backend, $cohort, $control, $seen
            FROM run AS r JOIN sandbox AS s ON s.sandbox_id=r.sandbox_id
            WHERE s.owner_id=$owner AND r.run_id=$id AND r.epoch=$epoch AND r.state IN ($starting,$stopping)
            ON CONFLICT(run_id) DO NOTHING;
            """, ("$instance", supervisor.InstanceId), ("$boot", supervisor.BootId), ("$pid", supervisor.ProcessId),
            ("$creation", supervisor.CreationIdentity), ("$endpoint", supervisor.Endpoint), ("$boundary", supervisor.BoundaryIdentity),
            ("$backend", supervisor.BackendId), ("$cohort", supervisor.Cohort), ("$control", supervisor.ControlEpoch),
            ("$seen", FormatTime(supervisor.LastSeenAt)), ("$owner", ownerId), ("$id", supervisor.RunId), ("$epoch", expectedRunEpoch),
            ("$starting", (int)StoredRunState.Starting), ("$stopping", (int)StoredRunState.Stopping)) == 1;
    }

    internal static bool TryAdvance(
        StoreTransaction transaction,
        string ownerId,
        string runId,
        string expectedEpoch,
        long expectedRevision,
        StoredRunState expectedState,
        StoredRunObservation observation)
    {
        var current = Get(transaction, ownerId, runId);
        if (current is null || current.Epoch != expectedEpoch || current.Revision != expectedRevision || current.State != expectedState
            || !CanAdvance(expectedState, observation.State) || !ValidObservation(current, observation)
            || (observation.State == StoredRunState.Running && GetSupervisor(transaction, ownerId, runId) is null))
        {
            return false;
        }

        var payload = observation.PayloadStarted == StoredPayloadStart.Unknown ? current.PayloadStarted : observation.PayloadStarted;
        var started = current.StartedAt ?? observation.StartedAt;
        var exitCode = observation.RawExitCode ?? current.RawExitCode;
        var exitSource = observation.ExitSource ?? current.ExitSource;
        var reason = observation.TerminationReason ?? current.TerminationReason;
        return transaction.Execute("""
            UPDATE run SET revision=$next, state=$state, payload_started=$payload, started_utc=$started,
                           ended_utc=$ended, raw_exit_code=$raw, exit_source=$source, termination_reason=$reason,
                           effect_certainty=$effect
            WHERE run_id=$id AND epoch=$epoch AND revision=$expectedRevision AND state=$expectedState
              AND EXISTS(SELECT 1 FROM sandbox AS s WHERE s.sandbox_id=run.sandbox_id AND s.owner_id=$owner);
            """, ("$next", checked(expectedRevision + 1)), ("$state", (int)observation.State), ("$payload", (int)payload),
            ("$started", started is { } startedAt ? FormatTime(startedAt) : null),
            ("$ended", observation.EndedAt is { } endedAt ? FormatTime(endedAt) : null), ("$raw", exitCode),
            ("$source", exitSource), ("$reason", reason), ("$effect", observation.EffectCertainty), ("$id", runId),
            ("$epoch", expectedEpoch), ("$expectedRevision", expectedRevision), ("$expectedState", (int)expectedState),
            ("$owner", ownerId)) == 1;
    }

    private static bool CanAdvance(StoredRunState current, StoredRunState next) => current switch
    {
        StoredRunState.Starting => next is StoredRunState.Starting or StoredRunState.Running or StoredRunState.Stopping
            or StoredRunState.Draining or StoredRunState.Failed or StoredRunState.RecoveryRequired,
        StoredRunState.Running => next is StoredRunState.Running or StoredRunState.Stopping
            or StoredRunState.Draining or StoredRunState.RecoveryRequired,
        StoredRunState.Stopping => next is StoredRunState.Stopping or StoredRunState.Draining or StoredRunState.RecoveryRequired,
        StoredRunState.Draining => next is StoredRunState.Draining or StoredRunState.Exited or StoredRunState.RecoveryRequired,
        StoredRunState.RecoveryRequired => next is StoredRunState.RecoveryRequired or StoredRunState.Running
            or StoredRunState.Draining or StoredRunState.Failed,
        _ => false,
    };

    private static bool ValidObservation(StoredRun current, StoredRunObservation observation)
    {
        if (observation.PayloadStarted is not (StoredPayloadStart.Unknown or StoredPayloadStart.NotStarted or StoredPayloadStart.Confirmed)
            || observation.EffectCertainty is < 1 or > 3
            || (current.PayloadStarted != StoredPayloadStart.Unknown && observation.PayloadStarted != StoredPayloadStart.Unknown
                && current.PayloadStarted != observation.PayloadStarted)
            || (current.StartedAt is { } started && observation.StartedAt is { } observedStart && started != observedStart)
            || (observation.State == StoredRunState.Running && current.StartedAt is null && observation.StartedAt is null))
        {
            return false;
        }

        bool terminal = observation.State is StoredRunState.Exited or StoredRunState.Failed;
        if (terminal != observation.EndedAt.HasValue || (terminal && !observation.GroupEmptyVerified)
            || (observation.State == StoredRunState.Failed
                && (observation.PayloadStarted != StoredPayloadStart.NotStarted || observation.EffectCertainty != 1)))
        {
            return false;
        }

        string? source = observation.ExitSource ?? current.ExitSource;
        if (source is not (null or "payload" or "official_executor" or "supervisor" or "unknown")
            || (terminal && (source is null || string.IsNullOrWhiteSpace(observation.TerminationReason ?? current.TerminationReason)))
            || (observation.RawExitCode is not null && (source is null or "unknown"))
            || (current.RawExitCode is { } priorCode && ((observation.RawExitCode is { } candidate && candidate != priorCode)
                || source != current.ExitSource)))
        {
            return false;
        }

        return true;
    }

    private static StoredRun Read(SqliteDataReader row) =>
        new(row.GetString(0), row.GetString(1), row.GetInt64(2), row.GetInt64(3), (StoredRunState)row.GetInt32(4), row.GetString(5),
            row.GetString(6), row.GetString(7), (StoredPayloadStart)row.GetInt32(8), ParseTime(row.GetString(9)),
            row.IsDBNull(10) ? null : ParseTime(row.GetString(10)), row.IsDBNull(11) ? null : ParseTime(row.GetString(11)),
            row.IsDBNull(12) ? null : row.GetInt32(12), row.IsDBNull(13) ? null : row.GetString(13),
            row.IsDBNull(14) ? null : row.GetString(14), row.GetInt32(15));

    private static string FormatTime(DateTimeOffset value) => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTime(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
}
