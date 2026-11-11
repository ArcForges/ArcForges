// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Real SQLite expansion for bounded metadata-only file/workspace audit records.</summary>
[Trait("feature", "workspace-audit-store")]
[Trait("check", "schema")]
public sealed class WorkspaceAuditMigrationTests
{
    [Fact]
    public void Step4PreservesOldRowsBoundsObservationsAndCascadesWithExistingAuditRetention()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var oldPlan = new MigrationPlan(StoreMigrations.Released.Steps.Take(3));
        var step4Plan = new MigrationPlan(StoreMigrations.Released.Steps.Take(4));
        long auditId;
        using (var old = root.Open(clock, oldPlan))
        {
            auditId = old.Write(transaction => (long)transaction.Scalar("""
                INSERT INTO audit_log (at, actor, operation, decision, outcome_summary)
                VALUES ($now, x'01', 'workspace.read', 1, 'old event') RETURNING seq;
                """, ("$now", transaction.NowMicroseconds))!);
        }

        using (var current = root.Open(clock, step4Plan))
        {
            Assert.Equal(3, current.Opening.MigratedFrom);
            Assert.Equal(4, current.Metadata.SchemaVersion);
            Assert.Equal(1, current.Metadata.MinReaderVersion);
            Assert.Equal(1L, current.Read(reader => reader.Scalar("SELECT count(*) FROM audit_log WHERE seq=$id;", ("$id", auditId))));
            current.Write(transaction =>
            {
                transaction.Execute("INSERT INTO file_workspace_audit (audit_seq, workspace_id, path) VALUES ($id, zeroblob(16), '/safe/path');",
                    ("$id", auditId));
                foreach (var kind in Enumerable.Range(1, 4))
                {
                    transaction.Execute("""
                        INSERT INTO file_workspace_audit_observation (audit_seq, kind, size_bytes, digest_input_bytes, item_count, sha256)
                        VALUES ($id, $kind, 0, 1, 0, zeroblob(32));
                        """, ("$id", auditId), ("$kind", kind));
                }
            });
            Assert.Equal(4L, current.Read(reader => reader.Scalar("SELECT count(*) FROM file_workspace_audit_observation WHERE audit_seq=$id;", ("$id", auditId))));
            var over = Assert.Throws<SqliteException>(() => current.Write(transaction => transaction.Execute("""
                INSERT INTO file_workspace_audit_observation (audit_seq, kind, size_bytes, digest_input_bytes, sha256)
                VALUES ($id, 5, 0, 1, zeroblob(32));
                """, ("$id", auditId))));
            Assert.Contains("file_audit_observation_limit", over.Message, StringComparison.Ordinal);
            Assert.Equal(19, Assert.Throws<SqliteException>(() => current.Write(transaction => transaction.Execute("""
                INSERT INTO file_workspace_audit (audit_seq, workspace_id, attempt_id) VALUES (9223372036854775807, zeroblob(16), zeroblob(16));
                """))).SqliteErrorCode);
        }

        // The real current SQL can still be opened through an older schema plan; this is not proof of a deployed binary rollback.
        using (var oldView = root.Open(clock, oldPlan))
        {
            Assert.Equal(4, oldView.Metadata.SchemaVersion);
            Assert.Equal(1L, oldView.Read(reader => reader.Scalar("SELECT count(*) FROM audit_log WHERE seq=$id;", ("$id", auditId))));
            oldView.Write(transaction => transaction.Execute("DELETE FROM audit_log WHERE seq=$id;", ("$id", auditId)));
        }

        using var reopened = root.Open(clock, step4Plan);
        Assert.Equal(0L, reopened.Read(reader => reader.Scalar("SELECT count(*) FROM file_workspace_audit;")));
        Assert.Equal(0L, reopened.Read(reader => reader.Scalar("SELECT count(*) FROM file_workspace_audit_observation;")));
    }
}
