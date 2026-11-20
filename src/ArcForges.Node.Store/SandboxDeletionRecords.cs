// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.Node.Store;

internal sealed record StoredSandboxDeletion(string DeletionId, string OriginalCommandId, long OriginalExpectedRevision,
    string RootIdentity, string? QuarantineIdentity, string Phase, int Effect, string? LatestSuccessorId,
    long? LatestExpectedRevision, string? LatestSuccessorState, string? OriginalState = null,
    bool RemovalVerified = false);

internal sealed record StoredPendingSandboxDeletion(string SandboxId, byte[] OwnerEpoch, StoredSandboxDeletion Journal);

/// <summary>Links a new authorization to an original deletion without modifying its outcome.</summary>
internal static class SandboxDeletionRecords
{
    internal const string Method = "SandboxService.Delete";
    internal const string RemovalWitnessField = "_deletionRemovalVerified";
    private const string Unsettled = """
        SELECT d.deletion_id,d.command_id,d.expected_revision,d.root_identity,d.quarantine_identity,d.phase,d.effect_certainty,
            d.latest_resume_command_id,d.latest_resume_expected_revision,successor.state,original.state,d.sandbox_id,d.owner_epoch,
            original.response_json
        FROM deletion_journal AS d
        JOIN sandbox AS s ON s.sandbox_id=d.sandbox_id AND s.owner_id=d.owner_id
        JOIN command_receipt AS original
          ON original.owner_id=d.owner_id AND original.owner_epoch=d.owner_epoch AND original.command_id=d.command_id
            AND original.method=$method AND original.aggregate_kind='sandbox' AND original.aggregate_id=d.sandbox_id
            AND original.state IN ('ACCEPTED','UNKNOWN') AND original.effect_certainty=3
        LEFT JOIN command_receipt AS successor
          ON successor.owner_id=d.owner_id AND successor.owner_epoch=d.owner_epoch
            AND successor.command_id=d.latest_resume_command_id AND successor.method=$method
            AND successor.aggregate_kind='sandbox' AND successor.aggregate_id=d.sandbox_id
        WHERE d.owner_id=$owner
        """;

    internal static StoredSandboxDeletion? ReadOriginal(StoreReader reader, string ownerId, byte[] epoch,
        string sandboxId, string originalCommandId)
    {
        using var command = reader.CreateCommand(Unsettled + " AND d.owner_epoch=$epoch AND d.sandbox_id=$sandbox AND d.command_id=$original;");
        StoreReader.Bind(command, [("$owner", ownerId), ("$epoch", epoch), ("$sandbox", sandboxId),
            ("$original", originalCommandId), ("$method", Method)]);
        using var row = command.ExecuteReader();
        return row.Read() ? Read(row) : null;
    }

    internal static IReadOnlyList<StoredPendingSandboxDeletion> ReadPending(StoreReader reader, string ownerId)
    {
        using var command = reader.CreateCommand(Unsettled + " AND d.phase<>'complete' ORDER BY d.deletion_id;");
        StoreReader.Bind(command, [("$owner", ownerId), ("$method", Method)]);
        using var rows = command.ExecuteReader();
        var result = new List<StoredPendingSandboxDeletion>();
        while (rows.Read())
        {
            result.Add(new(rows.GetString(11), rows.GetFieldValue<byte[]>(12), Read(rows)));
        }

        return result;
    }

    internal static bool CanAdmitSuccessor(StoreReader reader, string ownerId, byte[] epoch, string sandboxId, DurableDeletionBinding binding) =>
        ReadOriginal(reader, ownerId, epoch, sandboxId, binding.OriginalCommandId) is { } original
        && original.DeletionId == binding.DeletionId
        && original.Phase is "locked" or "quarantined" or "removing" or "recovery_required"
        && (original.LatestSuccessorId is null || original.LatestSuccessorState is "UNKNOWN" or "FAILED" or "SUCCEEDED");

    internal static bool IsBoundSuccessor(StoreReader reader, string ownerId, byte[] epoch, string sandboxId,
        DurableDeletionBinding binding, string commandId) =>
        ReadOriginal(reader, ownerId, epoch, sandboxId, binding.OriginalCommandId) is { } original
        && original.DeletionId == binding.DeletionId && original.LatestSuccessorId == commandId
        && original.LatestSuccessorState == "ACCEPTED";

    internal static IReadOnlyList<string> OlderUnsettledSuccessors(StoreReader reader, string ownerId, byte[] epoch,
        string sandboxId, StoredSandboxDeletion journal)
    {
        using var command = reader.CreateCommand("""
            SELECT r.command_id FROM command_receipt AS r
            WHERE r.owner_id=$owner AND r.owner_epoch=$epoch AND r.method=$method AND r.aggregate_kind='sandbox'
              AND r.aggregate_id=$sandbox AND r.command_id IS NOT $latest AND r.command_id<>$original
              AND r.state IN ('ACCEPTED','UNKNOWN') AND r.effect_certainty=3
              AND json_extract(r.response_json,'$._deletionBinding.originalCommandId')=$original
              AND json_extract(r.response_json,'$._deletionBinding.deletionId')=$deletion
            ORDER BY r.command_id;
            """);
        StoreReader.Bind(command, [("$owner", ownerId), ("$epoch", epoch), ("$method", Method),
            ("$sandbox", sandboxId), ("$latest", journal.LatestSuccessorId), ("$original", journal.OriginalCommandId),
            ("$deletion", journal.DeletionId)]);
        using var rows = command.ExecuteReader();
        var result = new List<string>();
        while (rows.Read())
        {
            result.Add(rows.GetString(0));
        }

        return result;
    }

    /// <summary>Consumes an owned plan in the durable Delete admission transaction.</summary>
    internal static bool TryAdmitFresh(StoreTransaction transaction, StoredSandbox sandbox, byte[] epoch, string planId, string commandId)
    {
        RequireFull(transaction);
        if (!IsId(planId) || !IsId(commandId)
            || sandbox.State is not (StoredSandboxState.Ready or StoredSandboxState.Error)
            || sandbox.RootIdentity is "" or SandboxRecords.PendingRootIdentity
            || SandboxRecords.Get(transaction, sandbox.OwnerId, sandbox.SandboxId) != sandbox
            || !HasAcceptedDelete(transaction, sandbox, epoch, commandId)
            || SandboxRecords.HasUnresolvedUse(transaction, sandbox.OwnerId, sandbox.SandboxId, epoch, commandId)
            || Equals(transaction.Scalar("SELECT EXISTS(SELECT 1 FROM deletion_journal WHERE deletion_id=$plan);", ("$plan", planId)), 1L))
            return false;

        string updated = SandboxRecords.FormatTime(transaction.Clock.GetUtcNow());
        transaction.Execute("""
            INSERT INTO deletion_journal(deletion_id,sandbox_id,owner_id,owner_epoch,command_id,expected_revision,
                root_identity,phase,effect_certainty,updated_utc)
            VALUES($plan,$sandbox,$owner,$epoch,$command,$revision,$root,'locked',3,$updated);
            """, ("$plan", planId), ("$sandbox", sandbox.SandboxId), ("$owner", sandbox.OwnerId), ("$epoch", epoch),
            ("$command", commandId), ("$revision", sandbox.Revision), ("$root", sandbox.RootIdentity), ("$updated", updated));
        RequireChanged(TrySetState(transaction, sandbox, StoredSandboxState.Deleting, updated));
        return true;
    }

    internal static bool TryLinkSuccessor(StoreTransaction transaction, StoredSandbox sandbox, byte[] epoch,
        StoredSandboxDeletion deletion, string successorId)
    {
        RequireFull(transaction);
        if (!MatchesPending(transaction, sandbox, epoch, deletion) || deletion.LatestSuccessorState == "ACCEPTED"
            || deletion.Phase is not ("locked" or "quarantined" or "removing" or "recovery_required")
            || successorId == deletion.OriginalCommandId || successorId == deletion.LatestSuccessorId
            || !HasAcceptedDelete(transaction, sandbox, epoch, successorId)
            || SandboxRecords.HasUnresolvedUse(transaction, sandbox.OwnerId, sandbox.SandboxId, epoch, successorId, deletion))
            return false;

        string updated = SandboxRecords.FormatTime(transaction.Clock.GetUtcNow());
        if (!TrySetState(transaction, sandbox, StoredSandboxState.Deleting, updated))
            return false;

        // A REC-01 successor could be linked by the journal before receipt metadata carried ancestry.
        // Preserve its unknown response and add only the relation the current journal proves.
        if (deletion is { LatestSuccessorId: { } earlier, LatestSuccessorState: "UNKNOWN" })
        {
            transaction.Execute("""
                UPDATE command_receipt SET
                  reserved_response=substr(reserved_response,1,max(0,length(reserved_response) - (
                    length(CAST(json_set(response_json,'$._deletionBinding',
                        json_object('originalCommandId',$original,'deletionId',$deletion)) AS BLOB))
                    - length(CAST(response_json AS BLOB)) ))),
                  response_json=json_set(response_json,'$._deletionBinding',
                    json_object('originalCommandId',$original,'deletionId',$deletion))
                WHERE owner_id=$owner AND owner_epoch=$epoch AND command_id=$earlier AND method=$method
                  AND aggregate_kind='sandbox' AND aggregate_id=$sandbox AND state='UNKNOWN' AND effect_certainty=3
                  AND json_type(response_json)='object' AND json_type(response_json,'$._deletionBinding') IS NULL;
                """, ("$owner", sandbox.OwnerId), ("$epoch", epoch), ("$earlier", earlier),
                ("$method", Method), ("$sandbox", sandbox.SandboxId), ("$original", deletion.OriginalCommandId),
                ("$deletion", deletion.DeletionId));
        }

        RequireChanged(transaction.Execute("""
            UPDATE deletion_journal SET latest_resume_command_id=$successor, latest_resume_expected_revision=$expected,
                updated_utc=$updated
            WHERE deletion_id=$deletion AND owner_id=$owner AND owner_epoch=$epoch AND command_id=$original;
            """, ("$successor", successorId), ("$expected", sandbox.Revision), ("$updated", updated),
            ("$deletion", deletion.DeletionId), ("$owner", sandbox.OwnerId), ("$epoch", epoch),
            ("$original", deletion.OriginalCommandId)) == 1);
        return true;
    }

    /// <summary>Records native quarantine or bounded cleanup progress without settling the original effect.</summary>
    internal static bool TryAdvance(StoreTransaction transaction, StoredSandbox sandbox, byte[] epoch,
        StoredSandboxDeletion before, string phase, string? quarantineIdentity)
    {
        RequireFull(transaction);
        if (!MatchesPending(transaction, sandbox, epoch, before) || before.RemovalVerified || !CanAdvance(before, phase, quarantineIdentity))
            return false;

        string updated = SandboxRecords.FormatTime(transaction.Clock.GetUtcNow());
        if (phase == "recovery_required" && sandbox.State != StoredSandboxState.RecoveryRequired
            && !TrySetState(transaction, sandbox, StoredSandboxState.RecoveryRequired, updated))
            return false;

        RequireChanged(WritePhase(transaction, sandbox, epoch, before, phase, quarantineIdentity, effect: 3, updated));
        return true;
    }

    /// <summary>Writes the tombstone only after the caller proves exact native removal and released handles.</summary>
    internal static bool TryComplete(StoreTransaction transaction, StoredSandbox sandbox, byte[] epoch, StoredSandboxDeletion before)
    {
        RequireFull(transaction);
        if (!MatchesPending(transaction, sandbox, epoch, before)
            || !before.RemovalVerified || before.Phase != "removing" || before.QuarantineIdentity is null)
            return false;

        string updated = SandboxRecords.FormatTime(transaction.Clock.GetUtcNow());
        if (!TrySetState(transaction, sandbox, StoredSandboxState.Deleted, updated))
            return false;

        RequireChanged(WritePhase(transaction, sandbox, epoch, before, "complete", before.QuarantineIdentity, effect: 2, updated));
        return true;
    }

    internal static bool HasTombstone(StoreReader reader, string ownerId, byte[] epoch, string sandboxId, string originalId, string? successorId) =>
        Equals(reader.Scalar("""
            SELECT EXISTS(SELECT 1 FROM deletion_journal AS d
                JOIN sandbox AS s ON s.sandbox_id=d.sandbox_id AND s.owner_id=d.owner_id
                WHERE d.owner_id=$owner AND d.owner_epoch=$epoch AND d.sandbox_id=$sandbox AND d.command_id=$command
                  AND d.latest_resume_command_id IS $successor AND d.phase='complete' AND d.effect_certainty=2
                  AND d.quarantine_identity IS NOT NULL AND s.state=$deleted AND d.root_identity=s.root_identity);
            """, ("$owner", ownerId), ("$epoch", epoch), ("$sandbox", sandboxId), ("$command", originalId),
            ("$successor", successorId), ("$deleted", (int)StoredSandboxState.Deleted)), 1L);

    private static bool MatchesPending(StoreTransaction transaction, StoredSandbox sandbox, byte[] epoch, StoredSandboxDeletion before) =>
        sandbox.State is StoredSandboxState.Deleting or StoredSandboxState.RecoveryRequired
        && sandbox.RootIdentity == before.RootIdentity && before.Effect == 3 && before.Phase != "complete"
        && SandboxRecords.Get(transaction, sandbox.OwnerId, sandbox.SandboxId) == sandbox
        && ReadOriginal(transaction, sandbox.OwnerId, epoch, sandbox.SandboxId, before.OriginalCommandId) == before;

    private static bool WritePhase(StoreTransaction transaction, StoredSandbox sandbox, byte[] epoch, StoredSandboxDeletion before,
        string phase, string? identity, int effect, string updated) =>
        transaction.Execute("""
            UPDATE deletion_journal SET phase=$next,quarantine_identity=$nextIdentity,effect_certainty=$effect,updated_utc=$updated
            WHERE deletion_id=$deletion AND owner_id=$owner AND owner_epoch=$epoch AND sandbox_id=$sandbox AND command_id=$command
              AND phase=$previous AND quarantine_identity IS $previousIdentity AND latest_resume_command_id IS $successor;
            """, ("$next", phase), ("$nextIdentity", identity), ("$effect", effect), ("$updated", updated),
            ("$deletion", before.DeletionId), ("$owner", sandbox.OwnerId), ("$epoch", epoch), ("$sandbox", sandbox.SandboxId),
            ("$command", before.OriginalCommandId), ("$previous", before.Phase), ("$previousIdentity", before.QuarantineIdentity),
            ("$successor", before.LatestSuccessorId)) == 1;

    private static bool CanAdvance(StoredSandboxDeletion before, string phase, string? identity)
    {
        if (identity is { Length: 0 or > 4096 } || identity?.Any(char.IsControl) == true
            || before.QuarantineIdentity is { } held && held != identity)
            return false;

        return phase switch
        {
            "locked" => before.Phase == "recovery_required" && identity is null,
            "quarantined" => before.Phase is "locked" or "recovery_required" && identity is not null,
            "removing" => before.Phase is "quarantined" or "removing" or "recovery_required"
                && before.QuarantineIdentity is not null,
            "recovery_required" => before.Phase is "locked" or "quarantined" or "removing" or "recovery_required",
            _ => false,
        };
    }

    private static bool HasAcceptedDelete(StoreReader reader, StoredSandbox sandbox, byte[] epoch, string commandId) =>
        Equals(reader.Scalar("""
            SELECT EXISTS(SELECT 1 FROM command_receipt
                WHERE owner_id=$owner AND owner_epoch=$epoch AND command_id=$command AND method=$method
                  AND aggregate_kind='sandbox' AND aggregate_id=$sandbox AND state='ACCEPTED' AND effect_certainty=3);
            """, ("$owner", sandbox.OwnerId), ("$epoch", epoch), ("$command", commandId), ("$method", Method),
            ("$sandbox", sandbox.SandboxId)), 1L);

    private static bool TrySetState(StoreTransaction transaction, StoredSandbox sandbox, StoredSandboxState state, string updated)
    {
        long revision = checked(sandbox.Revision + 1);
        if (transaction.Execute("""
            UPDATE sandbox SET state=$nextState,revision=$next,updated_utc=$updated
            WHERE owner_id=$owner AND sandbox_id=$sandbox AND state=$state AND revision=$expected
              AND root_identity=$root AND root_relative=$relative AND root_generation=$generation;
            """, ("$nextState", (int)state), ("$next", revision), ("$updated", updated),
            ("$owner", sandbox.OwnerId), ("$sandbox", sandbox.SandboxId), ("$state", (int)sandbox.State),
            ("$expected", sandbox.Revision), ("$root", sandbox.RootIdentity), ("$relative", sandbox.RootRelative),
            ("$generation", sandbox.RootGeneration)) != 1)
            return false;

        SandboxRecords.InsertConfig(transaction, sandbox.SandboxId, revision, sandbox.Config, updated);
        return true;
    }

    private static StoredSandboxDeletion Read(Microsoft.Data.Sqlite.SqliteDataReader row)
    {
        var deletion = new StoredSandboxDeletion(row.GetString(0), row.GetString(1), row.GetInt64(2), row.GetString(3),
            row.IsDBNull(4) ? null : row.GetString(4), row.GetString(5), row.GetInt32(6),
            row.IsDBNull(7) ? null : row.GetString(7), row.IsDBNull(8) ? null : row.GetInt64(8),
            row.IsDBNull(9) ? null : row.GetString(9), row.GetString(10));
        string? witness = ReadRemovalWitness(row.IsDBNull(13) ? null : row.GetString(13));
        if (witness is null) return deletion;
        if (deletion.Phase != "removing" || deletion.QuarantineIdentity is null
            || witness != RemovalWitness(deletion, row.GetFieldValue<byte[]>(12)))
            throw new DurableStoreMaintenanceException();
        return deletion with { RemovalVerified = true };
    }

    internal static string RemovalWitness(StoredSandboxDeletion deletion, ReadOnlySpan<byte> ownerEpoch) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\0',
            "sandbox-root-removed-v1", deletion.DeletionId, deletion.OriginalCommandId,
            deletion.RootIdentity, deletion.QuarantineIdentity, Convert.ToHexStringLower(ownerEpoch)))));

    internal static string? ReadRemovalWitness(string? response)
    {
        if (response is null) return null;
        using var value = JsonDocument.Parse(response);
        if (value.RootElement.ValueKind != JsonValueKind.Object
            || !value.RootElement.TryGetProperty(RemovalWitnessField, out var witness))
            return null;
        if (witness.ValueKind != JsonValueKind.String || witness.GetString() is not { Length: 64 } digest
            || !digest.All(char.IsAsciiHexDigitLower))
            throw new DurableStoreMaintenanceException();
        return digest;
    }

    private static bool IsId(string value) => value.Length == 32 && value.All(char.IsAsciiHexDigitLower);

    private static void RequireFull(StoreTransaction transaction)
    {
        if (transaction.Durability != CommitDurability.Full)
            throw new InvalidOperationException("Deletion evidence requires a FULL writer transaction.");
    }

    private static void RequireChanged(bool changed)
    {
        if (!changed) throw new InvalidOperationException("The exact deletion journal changed within its writer transaction.");
    }
}
