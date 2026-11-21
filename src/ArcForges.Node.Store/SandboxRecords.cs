// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store;

internal enum StoredSandboxState
{
    Creating = 1,
    Ready = 2,
    Deleting = 3,
    Deleted = 4,
    Error = 5,
    RecoveryRequired = 6,
}

internal sealed record StoredSandboxConfig(string ProfileId, string ProfileVersion, string Json, string Sha256);

internal sealed record StoredSandbox(
    string SandboxId,
    string OwnerId,
    string DisplayName,
    string NormalizedName,
    long Revision,
    StoredSandboxState State,
    string RootRelative,
    string RootIdentity,
    long RootGeneration,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    StoredSandboxConfig Config);

/// <summary>
/// Sandbox persistence in the schema 16 tables. The caller holds the common Sandbox admission lock
/// across precondition checks, metadata transactions and any native effects.
/// </summary>
internal static class SandboxRecords
{
    internal const string PendingRootIdentity = "pending";
    private const string TransferManagedUse = """
        (t.state IN (1,2,5) OR t.effect_certainty=3
         OR (t.closed_utc IS NULL AND (t.state=3 OR (t.state=4 AND t.staging_identity<>$unbound))))
        """;

    private const string Current = """
        SELECT s.sandbox_id, s.owner_id, s.display_name, s.normalized_name, s.revision, s.state,
               s.root_relative, s.root_identity, s.root_generation, s.created_utc, s.updated_utc,
               c.profile_id, c.profile_version, c.config_json, c.config_sha256
        FROM sandbox AS s LEFT JOIN sandbox_config AS c
            ON c.sandbox_id=s.sandbox_id AND c.revision=s.revision
        """;

    internal static StoredSandbox? Get(StoreReader reader, string ownerId, string sandboxId)
    {
        using var command = reader.CreateCommand(Current + " WHERE s.owner_id=$owner AND s.sandbox_id=$id;");
        StoreReader.Bind(command, [("$owner", ownerId), ("$id", sandboxId)]);
        using var row = command.ExecuteReader();
        return row.Read() ? Read(row) : null;
    }

    /// <summary>Reads the exact immutable revision referenced by an already-settled command.</summary>
    internal static StoredSandboxConfig? GetConfig(StoreReader reader, string ownerId, string sandboxId, long revision)
    {
        using var command = reader.CreateCommand("""
            SELECT c.profile_id, c.profile_version, c.config_json, c.config_sha256
            FROM sandbox AS s JOIN sandbox_config AS c ON c.sandbox_id=s.sandbox_id
            WHERE s.owner_id=$owner AND s.sandbox_id=$id AND c.revision=$revision;
            """);
        StoreReader.Bind(command, [("$owner", ownerId), ("$id", sandboxId), ("$revision", revision)]);
        using var row = command.ExecuteReader();
        return row.Read() ? new(row.GetString(0), row.GetString(1), row.GetString(2), row.GetString(3)) : null;
    }

    internal static IReadOnlyList<StoredSandbox> List(StoreReader reader, string ownerId, string? afterSandboxId, int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);
        using var command = reader.CreateCommand(Current + """
             WHERE s.owner_id=$owner AND ($after IS NULL OR s.sandbox_id>$after)
             ORDER BY s.sandbox_id LIMIT $count;
            """);
        StoreReader.Bind(command, [("$owner", ownerId), ("$after", afterSandboxId), ("$count", count)]);
        using var rows = command.ExecuteReader();
        var result = new List<StoredSandbox>();
        while (rows.Read())
        {
            result.Add(Read(rows));
        }

        return result;
    }

    /// <summary>Returns the owner journal revision to which the current Sandbox catalog view is bound.</summary>
    internal static long CatalogRevision(StoreReader reader, string ownerId) =>
        (long?)reader.Scalar("""
            SELECT admission_sequence FROM owner_epoch WHERE owner_id=$owner AND state='ACTIVE';
            """, ("$owner", ownerId)) ?? 0;

    internal static bool NameInUse(StoreReader reader, string ownerId, string normalizedName, string? exceptSandboxId = null) =>
        Equals(reader.Scalar("""
            SELECT EXISTS(SELECT 1 FROM sandbox WHERE owner_id=$owner AND normalized_name=$name AND sandbox_id IS NOT $except);
            """, ("$owner", ownerId), ("$name", normalizedName), ("$except", exceptSandboxId)), 1L);

    // STARTING, RUNNING, STOPPING, DRAINING and RECOVERY_REQUIRED all hold managed use.
    internal static bool HasNonterminalRuns(StoreReader reader, string sandboxId) =>
        Equals(reader.Scalar("""
            SELECT EXISTS(SELECT 1 FROM run WHERE sandbox_id=$id AND state IN (1,2,3,4,7));
            """, ("$id", sandboxId)), 1L);

    internal static IReadOnlyList<string> ListNonterminalRunIds(StoreReader reader, string sandboxId)
    {
        using var command = reader.CreateCommand("""
            SELECT run_id FROM run WHERE sandbox_id=$id AND state IN (1,2,3,4,7) ORDER BY run_id;
            """);
        StoreReader.Bind(command, [("$id", sandboxId)]);
        using var rows = command.ExecuteReader();
        var result = new List<string>();
        while (rows.Read())
        {
            result.Add(rows.GetString(0));
        }

        return result;
    }

    internal static IReadOnlyList<string> ListDeletionBlockingRuns(StoreReader reader, string ownerId, string sandboxId, int limit) =>
        ReadBlockingIds(reader, """
            SELECT r.run_id FROM run AS r JOIN sandbox AS s ON s.sandbox_id=r.sandbox_id
            WHERE s.owner_id=$owner AND s.sandbox_id=$id AND (r.state IN (1,2,3,4,7) OR EXISTS(
                SELECT 1 FROM command_receipt AS c WHERE c.owner_id=s.owner_id
                AND c.aggregate_kind='run' AND c.aggregate_id=r.run_id
                AND (c.state IN ('ACCEPTED','UNKNOWN') OR c.effect_certainty=3)))
            ORDER BY r.run_id LIMIT $limit;
            """, ownerId, sandboxId, limit, transfer: false);

    internal static IReadOnlyList<string> ListDeletionBlockingTransfers(StoreReader reader, string ownerId, string sandboxId, int limit) =>
        ReadBlockingIds(reader, $"""
            SELECT t.transfer_id FROM transfer AS t JOIN sandbox AS s ON s.sandbox_id=t.sandbox_id AND s.owner_id=t.owner_id
            WHERE s.owner_id=$owner AND s.sandbox_id=$id AND ({TransferManagedUse} OR EXISTS(
                SELECT 1 FROM command_receipt AS c WHERE c.owner_id=s.owner_id
                  AND (c.state IN ('ACCEPTED','UNKNOWN') OR c.effect_certainty=3)
                  AND ((c.aggregate_kind='transfer' AND c.aggregate_id=t.transfer_id)
                       OR (c.owner_epoch=t.owner_epoch AND c.command_id=t.command_id))))
            ORDER BY t.transfer_id LIMIT $limit;
            """, ownerId, sandboxId, limit, transfer: true);

    private static List<string> ReadBlockingIds(StoreReader reader, string sql, string ownerId, string sandboxId,
        int limit, bool transfer)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);
        using var command = reader.CreateCommand(sql);
        StoreReader.Bind(command, [("$owner", ownerId), ("$id", sandboxId), ("$limit", limit)]);
        if (transfer) StoreReader.Bind(command, [("$unbound", TransferRecords.UnboundStage)]);
        using var rows = command.ExecuteReader();
        var result = new List<string>();
        while (rows.Read())
        {
            result.Add(rows.GetString(0));
        }

        return result;
    }

    /// <summary>Checks persisted managed use before ERROR repair or deletion while the Sandbox lock is held.</summary>
    internal static bool HasUnresolvedUse(StoreReader reader, string ownerId, string sandboxId,
        byte[]? currentEpoch = null, string? admittedCommandId = null, StoredSandboxDeletion? continuation = null) =>
        Equals(reader.Scalar($"""
            SELECT EXISTS(
                SELECT 1 FROM sandbox AS s
                WHERE s.owner_id=$owner AND s.sandbox_id=$id AND (
                    EXISTS(SELECT 1 FROM run AS r WHERE r.sandbox_id=s.sandbox_id AND r.state IN (1,2,3,4,7))
                    OR EXISTS(
                        SELECT 1 FROM command_receipt AS r
                        WHERE r.owner_id=s.owner_id
                          AND (r.state IN ('ACCEPTED','UNKNOWN') OR r.effect_certainty=3)
                          AND NOT (r.owner_epoch IS $epoch AND (
                            r.command_id IS $admitted OR r.command_id IS $original OR r.command_id IS $previous
                            OR ($deletion IS NOT NULL AND r.method IS $method AND r.aggregate_kind IS 'sandbox'
                                AND r.aggregate_id IS s.sandbox_id
                                AND json_extract(r.response_json,'$._deletionBinding.originalCommandId') IS $original
                                AND json_extract(r.response_json,'$._deletionBinding.deletionId') IS $deletion)))
                          AND (
                            (r.aggregate_kind='sandbox' AND r.aggregate_id=s.sandbox_id)
                            OR (r.aggregate_kind='run' AND EXISTS(SELECT 1 FROM run AS u
                                WHERE u.run_id=r.aggregate_id AND u.sandbox_id=s.sandbox_id))
                            OR EXISTS(SELECT 1 FROM transfer AS t
                                WHERE t.sandbox_id=s.sandbox_id AND t.owner_id=r.owner_id
                                  AND ((r.aggregate_kind='transfer' AND t.transfer_id=r.aggregate_id)
                                    OR (t.owner_epoch=r.owner_epoch AND t.command_id=r.command_id)))
                          )
                    )
                    OR EXISTS(
                        SELECT 1 FROM transfer AS t WHERE t.sandbox_id=s.sandbox_id
                            AND {TransferManagedUse}
                    )
                    OR EXISTS(
                        SELECT 1 FROM deletion_journal AS d WHERE d.sandbox_id=s.sandbox_id
                          AND (d.phase<>'complete' OR d.effect_certainty=3)
                          AND NOT (d.owner_id=s.owner_id AND d.owner_epoch IS $epoch AND d.command_id IS $original)
                    )
                )
            );
            """, ("$owner", ownerId), ("$id", sandboxId), ("$epoch", currentEpoch), ("$admitted", admittedCommandId),
            ("$original", continuation?.OriginalCommandId), ("$previous", continuation?.LatestSuccessorId),
            ("$deletion", continuation?.DeletionId), ("$method", SandboxDeletionRecords.Method),
            ("$unbound", TransferRecords.UnboundStage)), 1L);

    /// <summary>Reserves the identity and first configuration in the durable Create admission transaction.</summary>
    internal static void Reserve(StoreTransaction transaction, StoredSandbox reservation)
    {
        if (reservation is not { Revision: 1, State: StoredSandboxState.Creating, RootGeneration: 1, RootIdentity: PendingRootIdentity })
        {
            throw new ArgumentException("A new Sandbox must reserve its first revision without a confirmed root.", nameof(reservation));
        }

        string created = FormatTime(reservation.CreatedAt);
        transaction.Execute("""
            INSERT INTO sandbox(sandbox_id, owner_id, display_name, normalized_name, revision, state,
                                root_relative, root_identity, root_generation, created_utc, updated_utc)
            VALUES($id, $owner, $name, $normalized, 1, $state, $path, $identity, 1, $created, $created);
            """, ("$id", reservation.SandboxId), ("$owner", reservation.OwnerId), ("$name", reservation.DisplayName),
            ("$normalized", reservation.NormalizedName), ("$state", (int)StoredSandboxState.Creating),
            ("$path", reservation.RootRelative), ("$identity", PendingRootIdentity), ("$created", created));
        InsertConfig(transaction, reservation.SandboxId, 1, reservation.Config, created);
    }

    /// <summary>Settles native creation and any observed root identity in the durable result transaction.</summary>
    internal static bool SettleCreation(
        StoreTransaction transaction,
        string ownerId,
        string sandboxId,
        string? rootIdentity,
        StoredSandboxState state)
    {
        if (state is not (StoredSandboxState.Ready or StoredSandboxState.Error or StoredSandboxState.RecoveryRequired))
        {
            throw new ArgumentOutOfRangeException(nameof(state));
        }

        if ((rootIdentity is not null && (string.IsNullOrWhiteSpace(rootIdentity) || rootIdentity == PendingRootIdentity))
            || (state == StoredSandboxState.Ready && rootIdentity is null))
        {
            throw new ArgumentException("Creation settlement requires a valid observed identity to publish READY.", nameof(rootIdentity));
        }

        return transaction.Execute("""
            UPDATE sandbox SET state=$state, root_identity=coalesce($identity, root_identity), updated_utc=$updated
            WHERE owner_id=$owner AND sandbox_id=$id AND revision=1 AND state=$creating;
            """, ("$state", (int)state), ("$identity", rootIdentity), ("$updated", FormatTime(transaction.Clock.GetUtcNow())),
            ("$owner", ownerId), ("$id", sandboxId), ("$creating", (int)StoredSandboxState.Creating)) == 1;
    }

    /// <summary>Applies one validated replacement and advances the aggregate without changing its owned root.</summary>
    internal static bool AppendRevision(
        StoreTransaction transaction,
        string ownerId,
        string sandboxId,
        long expectedRevision,
        string displayName,
        string normalizedName,
        StoredSandboxConfig configuration,
        bool repairError = false)
    {
        long nextRevision = checked(expectedRevision + 1);
        string updated = FormatTime(transaction.Clock.GetUtcNow());
        int changed = transaction.Execute("""
            UPDATE sandbox SET display_name=$name, normalized_name=$normalized, revision=$next, state=$ready, updated_utc=$updated
            WHERE owner_id=$owner AND sandbox_id=$id AND revision=$expected AND state=$prior AND root_identity<>$pending;
            """, ("$name", displayName), ("$normalized", normalizedName), ("$next", nextRevision),
            ("$ready", (int)StoredSandboxState.Ready), ("$updated", updated), ("$owner", ownerId), ("$id", sandboxId),
            ("$expected", expectedRevision), ("$prior", (int)(repairError ? StoredSandboxState.Error : StoredSandboxState.Ready)),
            ("$pending", PendingRootIdentity));
        if (changed != 1)
        {
            return false;
        }

        InsertConfig(transaction, sandboxId, nextRevision, configuration, updated);
        return true;
    }

    internal static void InsertConfig(StoreTransaction transaction, string sandboxId, long revision, StoredSandboxConfig configuration, string created) =>
        transaction.Execute("""
            INSERT INTO sandbox_config(sandbox_id, revision, profile_id, profile_version, config_json, config_sha256, created_utc)
            VALUES($id, $revision, $profile, $version, $json, $sha, $created);
            """, ("$id", sandboxId), ("$revision", revision), ("$profile", configuration.ProfileId),
            ("$version", configuration.ProfileVersion), ("$json", configuration.Json), ("$sha", configuration.Sha256), ("$created", created));

    private static StoredSandbox Read(SqliteDataReader row)
    {
        if (row.IsDBNull(11))
        {
            throw new InvalidDataException("The current Sandbox configuration revision is missing.");
        }

        return new(row.GetString(0), row.GetString(1), row.GetString(2), row.GetString(3), row.GetInt64(4),
            (StoredSandboxState)row.GetInt32(5), row.GetString(6), row.GetString(7), row.GetInt64(8),
            ParseTime(row.GetString(9)), ParseTime(row.GetString(10)),
            new(row.GetString(11), row.GetString(12), row.GetString(13), row.GetString(14)));
    }

    internal static string FormatTime(DateTimeOffset value) => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTime(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
}
