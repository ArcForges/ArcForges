// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store;

public sealed partial class NodeStore
{
    private const string ContractionCheckpoint = "AFV2-MIG-02/schema20";
    private const string FreshContraction = "CONTRACTED_FRESH";
    private const string VerifiedContraction = "CONTRACTED_VERIFIED_ARCHIVE";
    private const string NoPredecessor = "fresh:no-predecessor";

    private static readonly string[] ContractedTables =
    [
        "approval", "audit", "audit_log", "command_dedup", "command_receipt", "contracted_command_hold",
        "deletion_journal", "event", "event_eviction", "event_journal", "finding", "job", "limit_application",
        "migration_checkpoint", "node_setting", "notification", "output_segment", "owner_epoch", "owner_epoch_capacity",
        "policy_document", "remote_command_binding", "remote_grant", "resource_policy", "run", "run_recovery",
        "run_stop_intent", "sandbox", "sandbox_config", "schema_version", "store_meta", "supervisor_identity",
        "transfer", "v2_resource_sample",
    ];

    // The archive owns the private staged identity and the original source lease until publication.
    internal static void ContractVerifiedCopy(VerifiedNodeContractionArchive archive, TimeProvider clock, Action? beforeCommit = null)
    {
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentNullException.ThrowIfNull(clock);
        archive.VerifyHeld();
        SQLitePCL.Batteries_V2.Init();
        using var writer = new SqliteConnection(StorePaths.ConnectionString(archive.StagedDatabasePath, SqliteOpenMode.ReadWrite));
        writer.Open();
        archive.VerifyStagedIdentity();
        writer.CreateFunction<long>("arcforges_store_reader_version", () => StoreMigrations.SupportedSchemaVersion);
        Pragma(writer, "PRAGMA foreign_keys=ON;");
        Pragma(writer, "PRAGMA secure_delete=ON;");
        InTransaction(writer, CommitDurability.Full, transaction =>
        {
            ApplyContraction(new StoreTransaction(writer, transaction, clock, CommitDurability.Full), archive);
            beforeCommit?.Invoke();
            archive.VerifyCommit();
        });
    }

    private static void ApplyContraction(StoreTransaction transaction, VerifiedNodeContractionArchive archive)
    {
        if (!Sha256(archive.SourceDatabaseSha256) || !Sha256(archive.BackupManifestSha256) ||
            !Sha256(archive.HistoryArchiveSha256) || !Sha256(archive.RestoreDatabaseSha256) ||
            archive.ScopeReceiptSha256 is not null && !Sha256(archive.ScopeReceiptSha256))
        {
            throw new StoreIncompatibleException("The verified Node archive is missing its contraction checksums.");
        }

        ApplyContractionStep(transaction, StoreMigrations.ExpandedSchemaVersion, archive);
    }

    private static void ApplyFreshContraction(StoreTransaction transaction) => ApplyContractionStep(transaction, 0, null);

    private static void ApplyContractionStep(StoreTransaction transaction, int sourceSchema, VerifiedNodeContractionArchive? archive)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        const int Expanded = StoreMigrations.ExpandedSchemaVersion;
        const int Contracted = StoreMigrations.ContractedSchemaVersion;
        if (transaction.Durability != CommitDurability.Full ||
            !Equals(transaction.Scalar("PRAGMA foreign_keys;"), 1L) ||
            transaction.Scalar("PRAGMA synchronous;") is not (long and >= 2) ||
            transaction.Scalar("SELECT arcforges_store_reader_version();") is not (long and >= Contracted) ||
            transaction.Scalar("""
                SELECT s.cohort FROM schema_version s JOIN store_meta m ON s.singleton = m.singleton
                WHERE s.singleton = 1 AND m.schema_version = $version AND m.min_reader_version = $version;
                """, ("$version", Expanded)) is not string cohort)
        {
            throw new StoreIncompatibleException("Node schema contraction requires the released layout and a FULL current writer.");
        }

        if (Equals(transaction.Scalar("""
            SELECT EXISTS(SELECT 1 FROM task WHERE state IN (1, 2, 3, 4, 5, 6))
              OR EXISTS(SELECT 1 FROM attempt WHERE state BETWEEN 1 AND 8 OR leftover_count > 0)
              OR EXISTS(SELECT 1 FROM approval WHERE state IN (1, 2) AND operation <> 'NodeService.UpdateNodeSettings')
              OR EXISTS(SELECT 1 FROM command_dedup WHERE outcome IS NULL)
              OR EXISTS(SELECT 1 FROM file_operation_journal WHERE phase <> 2 OR held = 1)
              OR EXISTS(SELECT 1 FROM file_effect_worker WHERE ended = 0)
              OR EXISTS(SELECT 1 FROM file_private_stage_reservation WHERE active = 1)
              OR EXISTS(SELECT 1 FROM file_stage_production WHERE active = 1 OR released = 0)
              OR EXISTS(SELECT 1 FROM file_stage_worker WHERE ended = 0)
              OR EXISTS(SELECT 1 FROM file_removal_plan r JOIN cleanup_plan p ON p.plan_id = r.plan_id WHERE p.state IN (1, 2, 3))
              OR EXISTS(SELECT 1 FROM quarantine_entry WHERE restored_at IS NULL AND purged_at IS NULL)
              OR EXISTS(SELECT 1 FROM routed_call_log WHERE decision = 5)
              OR EXISTS(SELECT 1 FROM routed_file_call_log WHERE decision = 5);
            """), 1L))
        {
            throw new StoreIncompatibleException("Unresolved legacy custody prevents Node schema contraction.");
        }

        transaction.Execute(StoreMigrations.Released.Steps[Expanded].Sql);
        if (transaction.Execute("""
            UPDATE store_meta SET schema_version = $version, min_reader_version = $version WHERE singleton = 1;
            """, ("$version", Contracted)) != 1)
        {
            throw new StoreIncompatibleException("The Node schema writer floor could not be recorded.");
        }

        var state = archive is null ? FreshContraction : VerifiedContraction;
        var backup = archive?.BackupManifestSha256 ?? NoPredecessor;
        var receipt = ContractionDigest(sourceSchema, state, cohort, backup, archive?.SourceDatabaseSha256,
            archive?.HistoryArchiveSha256, archive?.RestoreDatabaseSha256, archive?.ScopeReceiptSha256);
        transaction.Execute("""
            INSERT INTO migration_checkpoint(migration_id,source_schema,target_schema,backup_identity,state,cohort,
                unresolved_count,receipt_sha256,created_utc,source_database_sha256,history_archive_sha256,
                restore_database_sha256,scope_receipt_sha256)
            VALUES($id,$source,$target,$backup,$state,$cohort,0,$receipt,$now,$database,$history,$restore,$scope);
            """, ("$id", ContractionCheckpoint), ("$source", sourceSchema), ("$target", Contracted), ("$backup", backup),
            ("$state", state), ("$cohort", cohort), ("$receipt", receipt),
            ("$now", transaction.Clock.GetUtcNow().UtcDateTime.ToString("O", CultureInfo.InvariantCulture)),
            ("$database", archive?.SourceDatabaseSha256), ("$history", archive?.HistoryArchiveSha256),
            ("$restore", archive?.RestoreDatabaseSha256), ("$scope", archive?.ScopeReceiptSha256));
        VerifyContractedLayout(transaction, Contracted, Contracted);
        if (transaction.Scalar("SELECT 1 FROM pragma_foreign_key_check LIMIT 1;") is not null)
        {
            throw new StoreIncompatibleException("The contracted Node layout has a foreign-key violation.");
        }
    }

    private static void VerifyContractedLayout(SqliteConnection connection, int version, int minimum) =>
        VerifyContractedLayout(new StoreReader(connection, null, TimeProvider.System), version, minimum);

    private static void VerifyContractedLayout(StoreReader reader, int version, int minimum)
    {
        const int Contracted = StoreMigrations.ContractedSchemaVersion;
        List<string> tables = [];
        using (var command = reader.CreateCommand("""
            SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name;
            """))
        using (var rows = command.ExecuteReader())
        {
            while (rows.Read())
            {
                tables.Add(rows.GetString(0));
            }
        }

        if (minimum < Contracted || (version == Contracted
                ? !tables.SequenceEqual(ContractedTables, StringComparer.Ordinal)
                : ContractedTables.Except(tables, StringComparer.Ordinal).Any()))
        {
            throw new StoreIncompatibleException("The physical Node schema does not match its recorded contraction.");
        }

        using var checkpoint = reader.CreateCommand("""
            SELECT m.source_schema,m.state,m.cohort,m.backup_identity,m.source_database_sha256,m.history_archive_sha256,
                m.restore_database_sha256,m.scope_receipt_sha256,m.receipt_sha256
            FROM migration_checkpoint m JOIN schema_version s ON s.singleton = 1 AND s.cohort = m.cohort
            WHERE m.migration_id = $id AND m.target_schema = $target AND m.unresolved_count = 0
              AND s.version BETWEEN $target AND $version AND s.min_reader BETWEEN $target AND $minimum;
            """);
        checkpoint.Parameters.AddWithValue("$id", ContractionCheckpoint);
        checkpoint.Parameters.AddWithValue("$target", Contracted);
        checkpoint.Parameters.AddWithValue("$version", version);
        checkpoint.Parameters.AddWithValue("$minimum", minimum);
        using var row = checkpoint.ExecuteReader();
        if (!row.Read())
            throw new StoreIncompatibleException("The contracted Node schema has no verified checkpoint.");

        string? Optional(int ordinal) => row.IsDBNull(ordinal) ? null : row.GetString(ordinal);
        var source = row.GetInt32(0);
        var state = row.GetString(1);
        var cohort = row.GetString(2);
        var backup = row.GetString(3);
        var database = Optional(4);
        var history = Optional(5);
        var restore = Optional(6);
        var scope = Optional(7);
        var valid = source == 0
            ? state == FreshContraction && backup == NoPredecessor && database is null && history is null && restore is null && scope is null
            : source == StoreMigrations.ExpandedSchemaVersion && state == VerifiedContraction && Sha256(backup) &&
              Sha256(database) && Sha256(history) && Sha256(restore) && (scope is null || Sha256(scope));
        if (!valid || !string.Equals(row.GetString(8), ContractionDigest(source, state, cohort, backup, database, history, restore, scope),
            StringComparison.Ordinal))
        {
            throw new StoreIncompatibleException("The Node contraction checkpoint is inconsistent.");
        }
    }

    private static string ContractionDigest(int source, string state, string cohort, string backup,
        string? database, string? history, string? restore, string? scope)
    {
        var contract = StoreMigrations.Released.Steps[StoreMigrations.ExpandedSchemaVersion];
        var payload = string.Create(CultureInfo.InvariantCulture,
            $"{ContractionCheckpoint}|{source}|{contract.Sha256}|{state}|{backup}|{database}|{history}|{restore}|{scope}|{cohort}");
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
    }

    private static bool Sha256(string? value) => value is { Length: 64 } &&
        value.All(character => character is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
}
