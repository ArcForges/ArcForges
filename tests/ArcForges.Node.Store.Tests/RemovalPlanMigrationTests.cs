// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Actual SQLite upgrade and constraints; encoded identities here are synthetic metadata, not native file proof.</summary>
[Trait("check", "schema")]
public sealed class RemovalPlanMigrationTests
{
    [Fact]
    public void VersionElevenUpgradesWithoutChangingTheExistingCleanupLedgerAndAddsBoundedPlanMetadata()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var workspace = StoreIds.NewUuid7(clock);
        var plan = StoreIds.NewUuid7(clock);
        var item = StoreIds.NewUuid7(clock);
        var command = StoreIds.NewUuid7(clock);
        var digest = new byte[32];
        using (var prior = root.Open(clock, new MigrationPlan(StoreMigrations.Released.Steps.Take(11))))
        {
            prior.Write(tx =>
            {
                tx.Execute("""
                    INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
                    VALUES ($id, 1, 2, 'fixture', '/fixture', 0, 0, 0);
                    """, ("$id", workspace));
                tx.Execute("""
                    INSERT INTO cleanup_plan (plan_id, state, digest, planned_by, total_bytes, item_count, created_at, expires_at, rev)
                    VALUES ($id, 1, $digest, x'01', 0, 1, 0, 3600000000, 0);
                    """, ("$id", plan), ("$digest", digest));
                tx.Execute("""
                    INSERT INTO cleanup_item (plan_id, item_id, path, size_bytes, item_class, reason, risk, action, fp_mtime, fp_size, fp_owner_state)
                    VALUES ($plan, $item, '/fixture/tree', 0, 10, 'fixture', 3, 1, 0, 0, 'unverified');
                    """, ("$plan", plan), ("$item", item));
                Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, command, "fixture", digest, Origin.Remote).Status);
                CommandDeduplication.Complete(tx, command, [1]);
            }, CommitDurability.Full);
        }

        using var current = root.Open(clock);
        Assert.Equal(11, current.Opening.MigratedFrom);
        Assert.Equal(12, current.Metadata.SchemaVersion);
        Assert.Equal(1L, current.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_item WHERE plan_id=$id;", ("$id", plan))));
        current.Write(tx =>
        {
            tx.Execute("""
                INSERT INTO file_removal_plan
                  (plan_id, command_id, request_sha256, caller, target_kind, workspace_id, workspace_path,
                   root_platform, root_identity, requires_approval, quarantine_available)
                VALUES ($plan, $command, $digest, x'01', 1, $workspace, 'tree', 1, zeroblob(33), 1, 0);
                """, ("$plan", plan), ("$command", command), ("$digest", digest), ("$workspace", workspace));
            tx.Execute("""
                INSERT INTO file_removal_plan_item
                  (plan_id, item_id, ordinal, relative_path, entry_kind, native_platform, native_identity,
                   identity_sha256, fingerprint_sha256, stamp_size, stamp_mtime, stamp_mtime_nsec,
                   stamp_change, stamp_change_nsec, mode, link_count, owner_verified)
                VALUES ($plan, $item, 0, 'tree', 2, 1, zeroblob(33), zeroblob(32), zeroblob(32), 0, 0, 0, 0, 0, 16384, 1, 0);
                """, ("$plan", plan), ("$item", item));
            tx.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($command, x'01');", ("$command", command));
            Assert.Throws<SqliteException>(() => tx.Execute("""
                UPDATE file_removal_plan SET attempt_id = zeroblob(16) WHERE plan_id = $plan;
                """, ("$plan", plan)));
        }, CommitDurability.Full);
        Assert.Equal(1L, current.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan_item WHERE plan_id=$id;", ("$id", plan))));
        Assert.Equal(1L, current.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_command_owner WHERE command_id=$id;", ("$id", command))));
    }
}
