// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>
/// Exercises real SQLite migrations and connections with synthetic encoded identities. Native name comparison and actual
/// process effects are exercised by the Core and Host tests, not by this schema test.
/// </summary>
[Trait("check", "schema")]
public sealed class TargetHoldMigrationTests
{
    [Fact]
    public void UpgradeFencesAnOlderConnectionAndScopesDistinctTargetWitnessesToOneTransaction()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var workspace = StoreIds.NewUuid7(clock);
        var held = StoreIds.NewUuid7(clock);
        var rootId = Identity(7);
        var parent = Identity(9);
        var heldTarget = Identity(10);
        var digest = new byte[32];
        var caller = new byte[] { 1 };

        using (var previous = root.Open(clock, new MigrationPlan(StoreMigrations.Released.Steps.Take(10))))
        {
            previous.Write(t =>
            {
                t.Execute("""
                    INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
                    VALUES ($id, 1, 2, 'owned fixture', '/fixture', 0, 0, 0);
                    """, ("$id", workspace));
                InsertCommand(t, held);
                InsertJournal(t, held, workspace, "held", rootId, parent, heldTarget, digest, caller);
            }, CommitDurability.Full);
        }

        using var current = root.Open(clock, new MigrationPlan(StoreMigrations.Released.Steps.Take(11)));
        Assert.Equal(10, current.Opening.MigratedFrom);
        Assert.Equal(11, current.Metadata.SchemaVersion);
        Assert.Equal(1, current.Metadata.MinReaderVersion);
        Assert.Equal(1L, current.Write(t => t.Scalar("PRAGMA trusted_schema;"), CommitDurability.Full));
        Assert.Equal(1L, current.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal WHERE held = 1;")));

        var oldCommand = StoreIds.NewUuid7(clock);
        current.Write(t => InsertCommand(t, oldCommand), CommitDurability.Full);
        using (var oldConnection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = root.Database,
            Pooling = false,
        }.ToString()))
        {
            oldConnection.Open();
            using var statement = oldConnection.CreateCommand();
            statement.CommandText = """
                INSERT INTO file_operation_journal
                  (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
                   identity_platform, root_identity, parent_identity, target_identity, expected_absent,
                   original_size, original_sha256, original_stage_identity, intended_size, intended_sha256,
                   intended_stage_identity, created_at, updated_at, held, acknowledged)
                VALUES ($id, 1, 1, $digest, $caller, $id, $workspace, 'alias', 1, $root, $parent, $target, 0,
                        0, zeroblob(32), $target, 0, zeroblob(32), $target, 0, 0, 1, 0);
                """;
            statement.Parameters.AddWithValue("$id", oldCommand);
            statement.Parameters.AddWithValue("$workspace", workspace);
            statement.Parameters.AddWithValue("$root", rootId);
            statement.Parameters.AddWithValue("$parent", parent);
            statement.Parameters.AddWithValue("$target", heldTarget);
            statement.Parameters.AddWithValue("$digest", digest);
            statement.Parameters.AddWithValue("$caller", caller);
            var rejected = Assert.Throws<SqliteException>(() => statement.ExecuteNonQuery());
            Assert.Contains("arcforges_file_hold_witness", rejected.Message, StringComparison.Ordinal);
        }
        Assert.Null(current.Read(r => r.Scalar("SELECT 1 FROM file_operation_journal WHERE command_id = $id;", ("$id", oldCommand))));

        // Even a deliberately supplied witness can never exempt the very same native object.
        var same = StoreIds.NewUuid7(clock);
        current.Write(t =>
        {
            InsertCommand(t, same);
            t.AllowDistinctFileTarget(same, held, workspace, "alias", rootId, parent, heldTarget, digest, caller, 1);
            var rejected = Assert.Throws<SqliteException>(() =>
                InsertJournal(t, same, workspace, "alias", rootId, parent, heldTarget, digest, caller));
            Assert.Contains("file_recovery_pending", rejected.Message, StringComparison.Ordinal);
            t.ClearFileTargetWitnesses();
        }, CommitDurability.Full);

        var distinct = StoreIds.NewUuid7(clock);
        var otherTarget = Identity(11);
        current.Write(t =>
        {
            InsertCommand(t, distinct);
            var rejected = Assert.Throws<SqliteException>(() =>
                InsertJournal(t, distinct, workspace, "independent", rootId, parent, otherTarget, digest, caller));
            Assert.Contains("file_recovery_pending", rejected.Message, StringComparison.Ordinal);
            t.AllowDistinctFileTarget(distinct, held, workspace, "different-name", rootId, parent, otherTarget, digest, caller, 1);
            rejected = Assert.Throws<SqliteException>(() =>
                InsertJournal(t, distinct, workspace, "independent", rootId, parent, otherTarget, digest, caller));
            Assert.Contains("file_recovery_pending", rejected.Message, StringComparison.Ordinal);
            t.ClearFileTargetWitnesses();
            t.AllowDistinctFileTarget(distinct, held, workspace, "independent", rootId, parent, otherTarget, digest, caller, 1);
            InsertJournal(t, distinct, workspace, "independent", rootId, parent, otherTarget, digest, caller);
            t.ClearFileTargetWitnesses();
        }, CommitDurability.Full);
        Assert.Equal(1L, current.Read(r => r.Scalar(
            "SELECT held FROM file_operation_journal WHERE command_id = $id;", ("$id", distinct))));

        var rolledBack = StoreIds.NewUuid7(clock);
        Assert.Throws<InvalidOperationException>(() => current.Write(t =>
        {
            InsertCommand(t, rolledBack);
            t.AllowDistinctFileTarget(rolledBack, held, workspace, "rollback", rootId, parent, Identity(12), digest, caller, 1);
            throw new InvalidOperationException("owned fixture rollback");
        }, CommitDurability.Full));
        current.Write(t =>
        {
            InsertCommand(t, rolledBack);
            var rejected = Assert.Throws<SqliteException>(() =>
                InsertJournal(t, rolledBack, workspace, "rollback", rootId, parent, Identity(12), digest, caller));
            Assert.Contains("file_recovery_pending", rejected.Message, StringComparison.Ordinal);
        }, CommitDurability.Full);

        current.Write(t => t.Execute("""
            UPDATE file_operation_journal SET phase = 3, held = 0, acknowledged = 1 WHERE command_id = $id;
            """, ("$id", held)), CommitDurability.Full);
        var reactivation = Assert.Throws<SqliteException>(() => current.Write(t => t.Execute("""
            UPDATE file_operation_journal SET phase = 1, held = 1, acknowledged = 0 WHERE command_id = $id;
            """, ("$id", held)), CommitDurability.Full));
        Assert.Contains("file_recovery_pending", reactivation.Message, StringComparison.Ordinal);
        Assert.Equal(0L, current.Read(r => r.Scalar(
            "SELECT held FROM file_operation_journal WHERE command_id = $id;", ("$id", held))));
    }

    [Fact]
    public void NativeStatementPreparedOnOlderOpenConnectionIsRevalidatedAfterUpgrade()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var workspace = StoreIds.NewUuid7(clock);
        var held = StoreIds.NewUuid7(clock);
        var olderCommand = StoreIds.NewUuid7(clock);
        var rootId = Identity(7);
        var parent = Identity(9);
        var heldTarget = Identity(10);
        var digest = new byte[32];
        var caller = new byte[] { 1 };

        using (var previous = root.Open(clock, new MigrationPlan(StoreMigrations.Released.Steps.Take(10))))
        {
            previous.Write(t =>
            {
                t.Execute("""
                    INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
                    VALUES ($id, 1, 2, 'owned fixture', '/fixture', 0, 0, 0);
                    """, ("$id", workspace));
                InsertCommand(t, held);
                InsertCommand(t, olderCommand);
                InsertJournal(t, held, workspace, "held", rootId, parent, heldTarget, digest, caller);
            }, CommitDurability.Full);
        }

        using var older = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = root.Database,
            Pooling = false,
        }.ToString());
        older.Open();
        var database = older.Handle ?? throw new InvalidOperationException("The old connection is not open.");
        const string sql = """
            INSERT INTO file_operation_journal
              (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
               identity_platform, root_identity, parent_identity, target_identity, expected_absent,
               original_size, original_sha256, original_stage_identity, intended_size, intended_sha256,
               intended_stage_identity, created_at, updated_at, held, acknowledged)
            VALUES (?1, 1, 1, ?2, ?3, ?1, ?4, 'alias', 1, ?5, ?6, ?7, 0,
                    0, zeroblob(32), ?7, 0, zeroblob(32), ?7, 0, 0, 1, 0);
            """;
        // Prepare the actual native SQLite statement while the older connection still sees schema 10.
        Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_prepare_v2(database, sql, out var prepared));
        Assert.NotNull(prepared);
        try
        {
            Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_bind_blob(prepared, 1, olderCommand));
            Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_bind_blob(prepared, 2, digest));
            Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_bind_blob(prepared, 3, caller));
            Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_bind_blob(prepared, 4, workspace));
            Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_bind_blob(prepared, 5, rootId));
            Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_bind_blob(prepared, 6, parent));
            Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_bind_blob(prepared, 7, heldTarget));

            using var current = root.Open(clock, new MigrationPlan(StoreMigrations.Released.Steps.Take(11)));
            Assert.Equal(10, current.Opening.MigratedFrom);
            Assert.Equal(11, current.Metadata.SchemaVersion);
            Assert.Same(database, older.Handle);
            Assert.Equal(SQLitePCL.raw.SQLITE_ERROR, SQLitePCL.raw.sqlite3_step(prepared));
            Assert.Contains("arcforges_file_hold_witness", SQLitePCL.raw.sqlite3_errmsg(database).utf8_to_string(),
                StringComparison.Ordinal);
            Assert.Null(current.Read(r => r.Scalar(
                "SELECT 1 FROM file_operation_journal WHERE command_id = $id;", ("$id", olderCommand))));
            Assert.Equal(1L, current.Read(r => r.Scalar(
                "SELECT held FROM file_operation_journal WHERE command_id = $id;", ("$id", held))));
        }
        finally
        {
            _ = SQLitePCL.raw.sqlite3_finalize(prepared);
        }
    }

    private static byte[] Identity(byte marker)
    {
        var id = new byte[33];
        id[0] = 1;
        id[1] = marker;
        return id;
    }

    private static void InsertCommand(StoreTransaction t, byte[] id) => t.Execute("""
        INSERT INTO command_dedup (command_id, method, payload_digest, origin, created_at, expires_at)
        VALUES ($id, 'arcforges.node.v1.FileService/WriteFile', zeroblob(32), 4, 0, 1);
        """, ("$id", id));

    private static void InsertJournal(StoreTransaction t, byte[] id, byte[] workspace, string path,
        byte[] root, byte[] parent, byte[] target, byte[] digest, byte[] caller) => t.Execute("""
        INSERT INTO file_operation_journal
          (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
           identity_platform, root_identity, parent_identity, target_identity, expected_absent,
           original_size, original_sha256, original_stage_identity, intended_size, intended_sha256,
           intended_stage_identity, created_at, updated_at, held, acknowledged)
        VALUES ($id, 1, 1, $digest, $caller, $id, $workspace, $path, 1, $root, $parent, $target, 0,
                0, zeroblob(32), $target, 0, zeroblob(32), $target, 0, 0, 1, 0);
        """, ("$id", id), ("$workspace", workspace), ("$path", path), ("$root", root),
        ("$parent", parent), ("$target", target), ("$digest", digest), ("$caller", caller));
}
