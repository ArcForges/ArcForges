// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Store;

internal sealed record StoredSandboxDeletion(string DeletionId, string OriginalCommandId, long OriginalExpectedRevision,
    string RootIdentity, string? QuarantineIdentity, string Phase, int Effect, string? LatestSuccessorId,
    long? LatestExpectedRevision, string? LatestSuccessorState);

/// <summary>Links a new authorization to an original deletion without modifying its outcome.</summary>
internal static class SandboxDeletionRecords
{
    internal const string Method = "SandboxService.Delete";

    internal static StoredSandboxDeletion? ReadOriginal(StoreReader reader, string ownerId, byte[] epoch,
        string sandboxId, string originalCommandId)
    {
        using var command = reader.CreateCommand("""
            SELECT d.deletion_id, d.command_id, d.expected_revision, d.root_identity, d.quarantine_identity,
                   d.phase, d.effect_certainty, d.latest_resume_command_id, d.latest_resume_expected_revision, successor.state
            FROM deletion_journal AS d
            JOIN command_receipt AS original
              ON original.owner_id=d.owner_id AND original.owner_epoch=d.owner_epoch AND original.command_id=d.command_id
                AND original.method=$method AND original.aggregate_kind='sandbox' AND original.aggregate_id=d.sandbox_id
                AND original.state IN ('ACCEPTED','UNKNOWN') AND original.effect_certainty=3
            LEFT JOIN command_receipt AS successor
              ON successor.owner_id=d.owner_id AND successor.owner_epoch=d.owner_epoch
                AND successor.command_id=d.latest_resume_command_id AND successor.method=$method
                AND successor.aggregate_kind='sandbox' AND successor.aggregate_id=d.sandbox_id
            WHERE d.owner_id=$owner AND d.owner_epoch=$epoch AND d.sandbox_id=$sandbox AND d.command_id=$original;
            """);
        StoreReader.Bind(command, [("$owner", ownerId), ("$epoch", epoch), ("$sandbox", sandboxId),
            ("$original", originalCommandId), ("$method", Method)]);
        using var row = command.ExecuteReader();
        return row.Read() ? new(row.GetString(0), row.GetString(1), row.GetInt64(2), row.GetString(3),
            row.IsDBNull(4) ? null : row.GetString(4), row.GetString(5), row.GetInt32(6),
            row.IsDBNull(7) ? null : row.GetString(7), row.IsDBNull(8) ? null : row.GetInt64(8),
            row.IsDBNull(9) ? null : row.GetString(9)) : null;
    }

    internal static bool TryLinkSuccessor(StoreTransaction transaction, StoredSandbox sandbox, byte[] epoch,
        StoredSandboxDeletion deletion, string successorId)
    {
        if (ReadOriginal(transaction, sandbox.OwnerId, epoch, sandbox.SandboxId, deletion.OriginalCommandId) != deletion
            || SandboxRecords.HasUnresolvedUse(transaction, sandbox.OwnerId, sandbox.SandboxId, epoch, successorId, deletion))
        {
            return false;
        }

        long revision = checked(sandbox.Revision + 1);
        string updated = SandboxRecords.FormatTime(transaction.Clock.GetUtcNow());
        if (transaction.Execute("""
            UPDATE sandbox SET state=$deleting, revision=$next, updated_utc=$updated
            WHERE owner_id=$owner AND sandbox_id=$sandbox AND state=$state AND revision=$expected
              AND root_identity=$root AND root_relative=$relative AND root_generation=$generation;
            """, ("$deleting", (int)StoredSandboxState.Deleting), ("$next", revision), ("$updated", updated),
            ("$owner", sandbox.OwnerId), ("$sandbox", sandbox.SandboxId), ("$state", (int)sandbox.State),
            ("$expected", sandbox.Revision), ("$root", sandbox.RootIdentity), ("$relative", sandbox.RootRelative),
            ("$generation", sandbox.RootGeneration)) != 1)
        {
            return false;
        }

        SandboxRecords.InsertConfig(transaction, sandbox.SandboxId, revision, sandbox.Config, updated);
        return transaction.Execute("""
            UPDATE deletion_journal SET latest_resume_command_id=$successor, latest_resume_expected_revision=$expected,
                updated_utc=$updated
            WHERE deletion_id=$deletion AND owner_id=$owner AND owner_epoch=$epoch AND command_id=$original;
            """, ("$successor", successorId), ("$expected", sandbox.Revision), ("$updated", updated),
            ("$deletion", deletion.DeletionId), ("$owner", sandbox.OwnerId), ("$epoch", epoch),
            ("$original", deletion.OriginalCommandId)) == 1;
    }
}
