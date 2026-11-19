// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Node.Store;

internal sealed record StoredRunRecovery(string BootId, string SupervisorPath, string SupervisorSha256,
    string InstallationRoot, bool PrepareStarted = false, long Generation = 0);

internal sealed record StoredRunStop(string CommandId, DateTimeOffset AcceptedAt, DateTimeOffset Deadline, bool Pressure)
{
    internal TimeSpan Remaining(DateTimeOffset now) => Deadline > now
        ? TimeSpan.FromTicks(Math.Min((Deadline - now).Ticks, (Deadline - AcceptedAt).Ticks)) : TimeSpan.Zero;
}

internal static class RunRecoveryRecords
{
    internal static bool Insert(StoreTransaction transaction, string owner, StoredRun run, StoredRunRecovery recovery)
    {
        RequireFull(transaction);
        return transaction.Execute("""
            INSERT INTO run_recovery(run_id,run_epoch,boot_id,supervisor_path,supervisor_sha256,installation_root)
            SELECT r.run_id,r.epoch,$boot,$path,$hash,$install FROM run r JOIN sandbox s ON s.sandbox_id=r.sandbox_id
            WHERE s.owner_id=$owner AND r.run_id=$run AND r.epoch=$epoch AND r.state=1;
            """, ("$owner", owner), ("$run", run.RunId), ("$epoch", run.Epoch), ("$boot", recovery.BootId),
            ("$path", recovery.SupervisorPath), ("$hash", recovery.SupervisorSha256), ("$install", recovery.InstallationRoot)) == 1;
    }

    internal static StoredRunRecovery? Read(StoreReader reader, string owner, StoredRun run)
    {
        using var command = reader.CreateCommand("""
            SELECT v.boot_id,v.supervisor_path,v.supervisor_sha256,v.installation_root,v.prepare_started,v.control_generation
            FROM run_recovery v JOIN run r ON r.run_id=v.run_id AND r.epoch=v.run_epoch
            JOIN sandbox s ON s.sandbox_id=r.sandbox_id WHERE s.owner_id=$owner AND v.run_id=$run AND v.run_epoch=$epoch;
            """);
        StoreReader.Bind(command, [("$owner", owner), ("$run", run.RunId), ("$epoch", run.Epoch)]);
        using var result = command.ExecuteReader();
        return result.Read() ? new(result.GetString(0), result.GetString(1), result.GetString(2), result.GetString(3),
            result.GetInt32(4) != 0, result.GetInt64(5)) : null;
    }

    internal static bool MarkPreparing(StoreTransaction transaction, string owner, string runId, string epoch)
    {
        RequireFull(transaction);
        return transaction.Execute("""
            UPDATE run_recovery SET prepare_started=1 WHERE run_id=$run AND run_epoch=$epoch AND prepare_started=0
              AND EXISTS(SELECT 1 FROM run r JOIN sandbox s ON s.sandbox_id=r.sandbox_id
                         WHERE r.run_id=$run AND r.epoch=$epoch AND r.state=1 AND s.owner_id=$owner);
            """, ("$owner", owner), ("$run", runId), ("$epoch", epoch)) == 1;
    }

    internal static bool AdvanceGeneration(StoreTransaction transaction, string owner, StoredRun run,
        StoredSupervisorIdentity supervisor, long expected)
    {
        RequireFull(transaction);
        return transaction.Execute("""
            UPDATE run_recovery SET control_generation=$next WHERE run_id=$run AND run_epoch=$epoch
              AND prepare_started=1 AND control_generation=$expected
              AND EXISTS(SELECT 1 FROM run r JOIN sandbox s ON s.sandbox_id=r.sandbox_id
                         JOIN supervisor_identity o ON o.run_id=r.run_id
                         WHERE r.run_id=$run AND r.epoch=$epoch AND r.launch_sha256=$digest AND r.revision=$revision AND r.state IN (1,2,3,4,7)
                           AND s.owner_id=$owner AND o.instance_id=$instance AND o.boot_id=$boot AND o.process_id=$pid
                           AND o.creation_identity=$birth AND o.boundary_identity=$boundary AND o.endpoint=$endpoint
                           AND o.backend_id=$backend AND o.cohort=$cohort AND o.control_epoch=$epoch);
            """, ("$owner", owner), ("$run", run.RunId), ("$epoch", run.Epoch), ("$revision", run.Revision),
            ("$expected", expected), ("$next", checked(expected + 1)), ("$instance", supervisor.InstanceId),
            ("$boot", supervisor.BootId), ("$pid", supervisor.ProcessId), ("$birth", supervisor.CreationIdentity),
            ("$boundary", supervisor.BoundaryIdentity), ("$endpoint", supervisor.Endpoint), ("$backend", supervisor.BackendId),
            ("$cohort", supervisor.Cohort), ("$digest", run.LaunchSha256)) == 1;
    }

    internal static bool InsertStop(StoreTransaction transaction, string owner, byte[] ownerEpoch,
        StoredRun run, StoredRunStop stop, string startCommand)
    {
        RequireFull(transaction);
        return transaction.Execute("""
            INSERT INTO run_stop_intent(run_id,run_epoch,owner_id,owner_epoch,command_id,accepted_utc,deadline_utc,pressure)
            SELECT r.run_id,r.epoch,s.owner_id,c.owner_epoch,c.command_id,$accepted,$deadline,$pressure
            FROM run r JOIN sandbox s ON s.sandbox_id=r.sandbox_id
            JOIN command_receipt c ON c.owner_id=s.owner_id AND c.aggregate_id=r.run_id
            WHERE r.run_id=$run AND r.epoch=$epoch AND r.state IN (1,2,3,4,7) AND s.owner_id=$owner
              AND c.owner_epoch=$ownerEpoch AND c.command_id=$command AND c.method='RunService.Stop'
              AND c.aggregate_kind='run' AND c.safety_parent_command_id=$start AND c.state IN ('ACCEPTED','UNKNOWN');
            """, ("$run", run.RunId), ("$epoch", run.Epoch), ("$owner", owner), ("$ownerEpoch", ownerEpoch),
            ("$command", stop.CommandId), ("$start", startCommand), ("$accepted", Time(stop.AcceptedAt)),
            ("$deadline", Time(stop.Deadline)), ("$pressure", stop.Pressure ? 1 : 0)) == 1;
    }

    internal static StoredRunStop? ReadStop(StoreReader reader, string owner, byte[] ownerEpoch, StoredRun run, string startCommand)
    {
        using var command = reader.CreateCommand("""
            SELECT i.command_id,i.accepted_utc,i.deadline_utc,i.pressure FROM run_stop_intent i
            JOIN run r ON r.run_id=i.run_id AND r.epoch=i.run_epoch JOIN sandbox s ON s.sandbox_id=r.sandbox_id
            JOIN command_receipt c ON c.owner_id=i.owner_id AND c.owner_epoch=i.owner_epoch AND c.command_id=i.command_id
            WHERE s.owner_id=$owner AND i.owner_id=$owner AND i.owner_epoch=$ownerEpoch AND i.run_id=$run AND i.run_epoch=$epoch
              AND c.method='RunService.Stop' AND c.aggregate_kind='run' AND c.aggregate_id=$run
              AND c.safety_parent_command_id=$start AND c.state IN ('ACCEPTED','UNKNOWN');
            """);
        StoreReader.Bind(command, [("$owner", owner), ("$ownerEpoch", ownerEpoch), ("$run", run.RunId), ("$epoch", run.Epoch), ("$start", startCommand)]);
        using var result = command.ExecuteReader();
        if (!result.Read()) return null;
        var accepted = ParseTime(result.GetString(1));
        var deadline = ParseTime(result.GetString(2));
        if (deadline < accepted || deadline - accepted > TimeSpan.FromMinutes(1))
        {
            throw new InvalidDataException("run_stop_deadline_invalid");
        }

        return new(result.GetString(0), accepted, deadline, result.GetInt32(3) != 0);
    }

    private static string Time(DateTimeOffset value) => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTime(string value) => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static void RequireFull(StoreTransaction transaction)
    {
        if (transaction.Durability != CommitDurability.Full)
        {
            throw new InvalidOperationException("Run recovery authority requires FULL durability.");
        }
    }
}
