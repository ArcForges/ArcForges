// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

public sealed partial class DurableCommandStoreTests
{
    [Fact]
    public void SqliteGuardsRejectReplacementRekeyEvictionAndKnownEffectChanges()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        using var commands = Commands(store, root.Path);
        var intent = Intent(commands);
        commands.Admit(intent);
        commands.SetResult(intent.CommandId, "SUCCEEDED", 2, "{\"synthetic_observation\":1}");
        foreach (string sql in new[]
        {
            "DELETE FROM command_receipt;", "INSERT OR REPLACE INTO command_receipt SELECT * FROM command_receipt;",
            "UPDATE command_receipt SET method='FixtureService.Other';",
            "UPDATE command_receipt SET request_hmac_sha256=lower(hex(randomblob(32)));",
            "UPDATE command_receipt SET aggregate_id='different';", "UPDATE command_receipt SET effect_certainty=1;",
            "UPDATE command_receipt SET response_json='{}';", "UPDATE command_receipt SET resolved_utc='2020-01-01';",
            "UPDATE owner_epoch SET digest_key_ref='other';", "UPDATE owner_epoch SET owner_epoch=randomblob(16);",
            "INSERT OR REPLACE INTO owner_epoch SELECT * FROM owner_epoch;", "DELETE FROM owner_epoch;",
        }) Assert.Throws<SqliteException>(() => store.Write(tx => tx.Execute(sql), CommitDurability.Full));
        Assert.Equal(DurableDecision.Replay, commands.Admit(intent).Decision);
        store.Write(tx => tx.Execute("UPDATE owner_epoch SET state='RETIRED',retired_utc='2026-10-15T12:00:00.0000000Z';"), CommitDurability.Full);
        Assert.Equal(DurableDecision.EpochRetired, commands.Admit(intent).Decision);
        Assert.Throws<SqliteException>(() => store.Write(tx => tx.Execute("UPDATE owner_epoch SET state='ACTIVE',retired_utc=NULL;")));
    }

    [Fact]
    public void UnresolvedDeletionFixtureKeepsItsBodyUntilDefiniteObservation()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        using var commands = Commands(store, root.Path);
        var intent = Intent(commands) with { AggregateKind = "sandbox", AggregateId = "fixture-sandbox" };
        commands.Admit(intent, tx =>
        {
            tx.Execute("""
                INSERT INTO sandbox(sandbox_id,owner_id,display_name,normalized_name,revision,state,root_relative,root_identity,root_generation,created_utc,updated_utc)
                VALUES('fixture-sandbox','fixture-owner','fixture','fixture',1,6,'owned/fixture','supplied-root-identity',1,'2026-10-15','2026-10-15');
                """);
            tx.Execute("""
                INSERT INTO deletion_journal(deletion_id,sandbox_id,owner_id,owner_epoch,command_id,expected_revision,root_identity,phase,effect_certainty,updated_utc)
                VALUES('fixture-delete','fixture-sandbox','fixture-owner',$e,$c,1,'supplied-root-identity','recovery_required',3,'2026-10-15');
                """, ("$e", commands.OwnerEpoch.ToArray()), ("$c", Convert.ToHexStringLower(intent.CommandId)));
        });
        commands.SetResult(intent.CommandId, "UNKNOWN", 3, "{\"fixture\":\"delete_reconciliation_needed\"}");
        clock.Advance(TimeSpan.FromDays(4));
        Assert.Equal(0, commands.CompactKnownResponses());
        Assert.Throws<InvalidOperationException>(() => commands.SetResult(intent.CommandId, "SUCCEEDED", 2, "{}"));
        Assert.False(commands.MaintenanceRequired);
        Assert.Contains("delete_reconciliation_needed", commands.Inspect(intent.CommandId)!.ResponseJson, StringComparison.Ordinal);
        commands.SetResult(intent.CommandId, "SUCCEEDED", 2, "{\"fixture\":\"observed_complete\"}", tx =>
            tx.Execute("UPDATE deletion_journal SET phase='complete',effect_certainty=2 WHERE deletion_id='fixture-delete';"));
        Assert.Equal(0, commands.CompactKnownResponses());
        clock.Advance(TimeSpan.FromHours(24));
        Assert.Equal(1, commands.CompactKnownResponses());
    }

    [Fact]
    public void NativePrivateFilesContainNoCanonicalRequestAndTornFenceRefusesAdmission()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        const string marker = "synthetic-private-request-must-not-persist";
        DurableIntent intent;
        using (var store = root.Open(clock))
        using (var commands = Commands(store, root.Path))
        {
            intent = Intent(commands, body: marker);
            commands.Admit(intent);
            if (OperatingSystem.IsWindows())
            {
                var acl = new DirectoryInfo(root.Path).GetAccessControl();
                var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).OfType<FileSystemAccessRule>();
                foreach (var rule in rules)
                    Assert.False(rule.AccessControlType == AccessControlType.Allow
                        && rule.IdentityReference.Value is "S-1-1-0" or "S-1-5-11"
                        && (rule.FileSystemRights & (FileSystemRights.ReadData | FileSystemRights.WriteData | FileSystemRights.AppendData)) != 0);
            }
            else
            {
                Assert.Equal(StorePaths.PrivateDirectoryMode, File.GetUnixFileMode(Path.Combine(root.Path, "store")));
                string keyFile = Assert.Single(Directory.EnumerateFiles(Path.Combine(root.Path, "run", TestDataRootSecretStore.DirectoryName)));
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(keyFile));
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                    File.GetUnixFileMode(DurableEpochFence.PathFor(root.Path, "fixture-owner")));
            }
        }
        foreach (string file in Directory.EnumerateFiles(Path.Combine(root.Path, "store")))
            Assert.True(File.ReadAllBytes(file).AsSpan().IndexOf(Encoding.UTF8.GetBytes(marker)) < 0);
        string fence = DurableEpochFence.PathFor(root.Path, "fixture-owner");
        using (var file = new FileStream(fence, FileMode.Append)) file.WriteByte(1); // Controlled torn-frame input.
        using var reopened = root.Open(clock);
        using var owner = Commands(reopened, root.Path);
        Assert.True(owner.MaintenanceRequired);
        Assert.Equal(DurableDecision.Maintenance, owner.Admit(intent).Decision);
        Assert.NotNull(owner.Inspect(intent.CommandId));
    }

    [Fact]
    public void ABackupMissingItsEpochKeyOrLaterAdmissionCannotActivateOldAuthority()
    {
        using var source = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var destination = new TemporaryDataRoot();
        var clock = new ManualClock();
        var backupSecrets = NodeSecretStores.ForTestDataRoot(backup.Path);
        using (var store = source.Open(clock))
        using (var commands = Commands(store, source.Path))
        {
            var first = Intent(commands);
            commands.Admit(first);
            commands.SetResult(first.CommandId, "FAILED", 1, "{\"synthetic_effect\":\"did_not_happen\"}");
            commands.CreateBackup(backup.Path, backupSecrets);
            commands.Admit(Intent(commands));
        }
        Assert.Throws<DurableStoreMaintenanceException>(() => DurableCommandStore.RestoreBackup(backup.Path, backupSecrets,
            source.Path, NodeSecretStores.ForTestDataRoot(source.Path), destination.Path, NodeSecretStores.ForTestDataRoot(destination.Path)));
        Assert.False(File.Exists(destination.Database));
        var keys = new TestDataRootSecretStore(backup.Path);
        keys.Delete(Assert.Single(keys.Names()));
        Assert.Throws<DurableStoreMaintenanceException>(() => DurableCommandStore.RestoreBackup(backup.Path, backupSecrets,
            source.Path, NodeSecretStores.ForTestDataRoot(source.Path), destination.Path, NodeSecretStores.ForTestDataRoot(destination.Path)));
        Assert.False(File.Exists(destination.Database));
    }
}
