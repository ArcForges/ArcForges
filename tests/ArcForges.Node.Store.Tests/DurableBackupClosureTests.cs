// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Store.Tests;

public sealed partial class DurableCommandStoreTests
{
    [Fact]
    public void CompleteBackupPreservesEveryOwnerAndProtectedEpochKey()
    {
        using var source = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var destination = new TemporaryDataRoot();
        var clock = new ManualClock();
        var backupSecrets = NodeSecretStores.ForTestDataRoot(backup.Path);
        DurableIntent first;
        DurableIntent second;
        using (var store = source.Open(clock))
        using (var owner = Commands(store, source.Path))
        {
            first = Intent(owner);
            owner.Admit(first);
            owner.SetResult(first.CommandId, "SUCCEEDED", 2, "{\"synthetic_observation\":1}");
            using (var other = new DurableCommandStore(store, "second-owner", NodeSecretStores.ForTestDataRoot(source.Path), Capacity))
            {
                second = Intent(other);
                other.Admit(second);
                other.SetResult(second.CommandId, "UNKNOWN", 3, "{\"fixture\":\"uncertain_second_owner\"}");
                // A full snapshot cannot silently omit another currently owned namespace.
                Assert.Throws<DurableStoreMaintenanceException>(() => owner.CreateBackup(backup.Path, backupSecrets));
            }
            Assert.False(Directory.Exists(backup.Path));
            owner.CreateBackup(backup.Path, backupSecrets);
        }
        DurableCommandStore.RestoreBackup(backup.Path, backupSecrets, source.Path, NodeSecretStores.ForTestDataRoot(source.Path),
            destination.Path, NodeSecretStores.ForTestDataRoot(destination.Path));
        using var restored = destination.Open(clock);
        using var restoredFirst = Commands(restored, destination.Path);
        using var restoredSecond = new DurableCommandStore(restored, "second-owner", NodeSecretStores.ForTestDataRoot(destination.Path), Capacity);
        Assert.Equal(DurableDecision.Replay, restoredFirst.Admit(first).Decision);
        Assert.Equal(DurableDecision.InProgress, restoredSecond.Admit(second).Decision);
        Assert.Contains("uncertain_second_owner", restoredSecond.Inspect(second.CommandId)!.ResponseJson, StringComparison.Ordinal);
        Assert.Equal(2, new TestDataRootSecretStore(destination.Path).Names().Count);
    }

    [Fact]
    public void ANewOwnerAdmittedAfterBackupCannotDisappearFromRestoreChecks()
    {
        using var source = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var destination = new TemporaryDataRoot();
        var clock = new ManualClock();
        var backupSecrets = NodeSecretStores.ForTestDataRoot(backup.Path);
        using (var store = source.Open(clock))
        {
            using (var owner = Commands(store, source.Path))
            {
                var intent = Intent(owner);
                owner.Admit(intent);
                owner.SetResult(intent.CommandId, "FAILED", 1, "{\"synthetic_effect\":\"did_not_happen\"}");
                owner.CreateBackup(backup.Path, backupSecrets);
            }
            using var later = new DurableCommandStore(store, "second-owner", NodeSecretStores.ForTestDataRoot(source.Path), Capacity);
            Assert.Equal(DurableDecision.Execute, later.Admit(Intent(later)).Decision);
        }
        Assert.Throws<DurableStoreMaintenanceException>(() => DurableCommandStore.RestoreBackup(backup.Path, backupSecrets,
            source.Path, NodeSecretStores.ForTestDataRoot(source.Path), destination.Path, NodeSecretStores.ForTestDataRoot(destination.Path)));
        Assert.False(File.Exists(destination.Database));
    }

    [Fact]
    public void RolledBackLatestDatabaseCannotEraseItsNewerIndependentFence()
    {
        using var source = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var destination = new TemporaryDataRoot();
        var clock = new ManualClock();
        var backupSecrets = NodeSecretStores.ForTestDataRoot(backup.Path);
        using (var store = source.Open(clock))
        using (var commands = Commands(store, source.Path))
        {
            var intent = Intent(commands);
            commands.Admit(intent);
            commands.CreateBackup(backup.Path, backupSecrets);
            commands.SetResult(intent.CommandId, "SUCCEEDED", 2, "{\"synthetic_observation\":1}");
        }
        // A controlled old-DB restore input, leaving the independently retained newest fence untouched.
        File.Copy(backup.Database, source.Database, overwrite: true);
        Assert.Throws<DurableStoreMaintenanceException>(() => DurableCommandStore.RestoreBackup(backup.Path, backupSecrets,
            source.Path, NodeSecretStores.ForTestDataRoot(source.Path), destination.Path, NodeSecretStores.ForTestDataRoot(destination.Path)));
        Assert.False(File.Exists(destination.Database));
    }
}
