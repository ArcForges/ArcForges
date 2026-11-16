// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Store.Tests;

/// <summary>Real SQLite/protected-file primitives; the only effect is an explicitly synthetic admission counter.</summary>
[Trait("env", "windows-real")]
[Trait("env", "linux-real")]
public sealed partial class DurableCommandStoreTests
{
    private static DurableCapacity Capacity => new(12, 3, 1024, 65536);
    private static DurableCommandStore Commands(NodeStore store, string root) => new(store, "fixture-owner", NodeSecretStores.ForTestDataRoot(root), Capacity);
    private static DurableIntent Intent(DurableCommandStore commands, byte[]? id = null, string body = "synthetic-effect-argument",
        string method = "FixtureService.Mutate", byte[]? parent = null) =>
        new(id ?? RandomNumberGenerator.GetBytes(16), commands.OwnerEpoch.ToArray(), method, "fixture", "fixture-aggregate",
            Encoding.UTF8.GetBytes(body), SafetyParent: parent);

    [Fact]
    public void SettledAndCompactedReplayRetainsIdentityAcrossCloseReopen()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        DurableIntent original;
        byte[] epoch;
        int syntheticEffects = 0;
        using (var store = root.Open(clock))
        using (var commands = Commands(store, root.Path))
        {
            epoch = commands.OwnerEpoch.ToArray();
            Assert.Equal(16, epoch.Length);
            original = Intent(commands);
            if (commands.Admit(original).Decision == DurableDecision.Execute) syntheticEffects++;
            commands.SetResult(original.CommandId, "SUCCEEDED", 2, "{\"synthetic_observation\":1}");
            Assert.Equal(DurableDecision.Replay, commands.Admit(original).Decision);
            clock.Advance(TimeSpan.FromHours(24) - TimeSpan.FromTicks(1));
            Assert.Equal(0, commands.CompactKnownResponses());
            clock.Advance(TimeSpan.FromTicks(1));
            Assert.Equal(1, commands.CompactKnownResponses());
        }
        using (var store = root.Open(clock))
        using (var commands = Commands(store, root.Path))
        {
            Assert.Equal(epoch, commands.OwnerEpoch.ToArray());
            var replay = commands.Admit(original);
            if (replay.Decision == DurableDecision.Execute) syntheticEffects++;
            Assert.Equal(DurableDecision.Compacted, replay.Decision);
            Assert.Equal("SUCCEEDED", replay.Receipt!.State);
            Assert.Equal(2, replay.Receipt.Effect);
            Assert.Null(replay.Receipt.ResponseJson);
            Assert.True(commands.Inspect(original.CommandId)!.Compacted);
            Assert.Equal(DurableDecision.Conflict, commands.Admit(original with { CanonicalBody = Encoding.UTF8.GetBytes("different secret-bearing field") }).Decision);
            Assert.Equal(DurableDecision.Conflict, commands.Admit(original with { Method = "FixtureService.Other" }).Decision);
            Assert.Equal(1, syntheticEffects);
            Assert.Equal(1L, store.Read(r => r.Scalar("SELECT count(*) FROM command_receipt;")));
        }
    }

    [Fact]
    public void UnknownAndAcceptedBodiesRemainAndTerminalControlIsExcluded()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        DurableIntent uncertain;
        using (var store = root.Open(clock))
        using (var commands = Commands(store, root.Path))
        {
            uncertain = Intent(commands);
            commands.Admit(uncertain);
            commands.SetResult(uncertain.CommandId, "UNKNOWN", 3, "{\"fixture\":\"observation_ambiguous\"}");
            commands.Admit(Intent(commands));
            foreach (string method in new[] { "AcquireTerminal", "WriteTerminal", "ResizeTerminal", "DetachTerminal" })
                Assert.Throws<ArgumentException>(() => commands.Admit(Intent(commands, method: "RunService." + method)));
            clock.Advance(TimeSpan.FromDays(9));
            Assert.Equal(0, commands.CompactKnownResponses());
        }
        using (var store = root.Open(clock))
        using (var commands = Commands(store, root.Path))
        {
            Assert.Equal(DurableDecision.InProgress, commands.Admit(uncertain).Decision);
            Assert.Contains("observation_ambiguous", commands.Inspect(uncertain.CommandId)!.ResponseJson, StringComparison.Ordinal);
            Assert.Equal(2L, store.Read(r => r.Scalar("SELECT count(*) FROM command_receipt;")));
            Assert.Equal(DurableDecision.EpochRetired, commands.Admit(uncertain with { OwnerEpoch = RandomNumberGenerator.GetBytes(16) }).Decision);
        }
    }

    [Fact]
    public void MissingKeyAndMissingDatabaseNeverRecreateAuthority()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        byte[] epoch;
        using (var store = root.Open(clock))
        using (var commands = Commands(store, root.Path))
        {
            epoch = commands.OwnerEpoch.ToArray();
            commands.Admit(Intent(commands));
        }
        var files = new TestDataRootSecretStore(root.Path);
        string target = Assert.Single(files.Names());
        files.Delete(target);
        using (var store = root.Open(clock))
        using (var commands = Commands(store, root.Path))
        {
            Assert.Equal(epoch, commands.OwnerEpoch.ToArray());
            Assert.True(commands.MaintenanceRequired);
            Assert.Equal(DurableDecision.Maintenance, commands.Admit(Intent(commands)).Decision);
            Assert.Empty(files.Names());
        }
        File.Delete(root.Database);
        Assert.Throws<StoreIncompatibleException>(() => root.Open(clock));
        Assert.False(File.Exists(root.Database));
    }

    [Fact]
    public void BackupNeedsTheIndependentLatestAdmissionAndEffectHistory()
    {
        using var source = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var restored = new TemporaryDataRoot();
        using var oldRestore = new TemporaryDataRoot();
        var clock = new ManualClock();
        var backupKeys = NodeSecretStores.ForTestDataRoot(backup.Path);
        var sourceKeys = NodeSecretStores.ForTestDataRoot(source.Path);
        DurableIntent intent;
        DurableIntent known;
        DurableIntent unknown;
        using (var store = source.Open(clock))
        using (var commands = Commands(store, source.Path))
        {
            intent = Intent(commands);
            commands.Admit(intent);
            known = Intent(commands);
            commands.Admit(known);
            commands.SetResult(known.CommandId, "FAILED", 1, "{\"fixture\":\"known_no_effect\"}");
            unknown = Intent(commands);
            commands.Admit(unknown);
            commands.SetResult(unknown.CommandId, "UNKNOWN", 3, "{\"fixture\":\"unresolved\"}");
            commands.CreateBackup(backup.Path, backupKeys);
        }
        DurableCommandStore.RestoreBackup(backup.Path, backupKeys, source.Path, sourceKeys, restored.Path,
            NodeSecretStores.ForTestDataRoot(restored.Path));
        using (var store = restored.Open(clock))
        using (var commands = Commands(store, restored.Path))
        {
            Assert.Equal(DurableDecision.InProgress, commands.Admit(intent).Decision);
            Assert.Equal(DurableDecision.Replay, commands.Admit(known).Decision);
            Assert.Equal(DurableDecision.InProgress, commands.Admit(unknown).Decision);
            Assert.Contains("unresolved", commands.Inspect(unknown.CommandId)!.ResponseJson, StringComparison.Ordinal);
            Assert.Equal(3L, store.Read(r => r.Scalar("SELECT count(*) FROM command_receipt;")));
        }
        // No new command was admitted here: a later effect observation alone invalidates the old snapshot.
        using (var store = source.Open(clock))
        using (var commands = Commands(store, source.Path))
            commands.SetResult(intent.CommandId, "SUCCEEDED", 2, "{\"synthetic_observation\":1}");
        Assert.Throws<DurableStoreMaintenanceException>(() => DurableCommandStore.RestoreBackup(backup.Path, backupKeys,
            source.Path, sourceKeys, oldRestore.Path, NodeSecretStores.ForTestDataRoot(oldRestore.Path)));
        Assert.False(File.Exists(oldRestore.Database));
        Assert.Throws<DurableStoreMaintenanceException>(() => DurableCommandStore.RestoreBackup(backup.Path, backupKeys,
            backup.Path, backupKeys, oldRestore.Path, NodeSecretStores.ForTestDataRoot(oldRestore.Path)));
    }

    [Fact]
    public void ReservedCapacityRefusesNewWorkButKeepsOneConvergentSafetyIntent()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        using var commands = new DurableCommandStore(store, "fixture-owner", NodeSecretStores.ForTestDataRoot(root.Path), new(4, 1, 1024, 8192));
        var original = Intent(commands);
        Assert.Equal(DurableDecision.Execute, commands.Admit(original).Decision);
        Assert.Equal(DurableDecision.Capacity, commands.Admit(Intent(commands)).Decision);
        Assert.Equal(DurableDecision.InProgress, commands.Admit(original).Decision);
        var safety = Intent(commands, method: "FixtureService.Safety", parent: original.CommandId);
        Assert.Equal(DurableDecision.Execute, commands.Admit(safety).Decision);
        Assert.Equal(DurableDecision.InProgress, commands.Admit(safety with { CommandId = RandomNumberGenerator.GetBytes(16) }).Decision);
        Assert.Equal(2L, store.Read(r => r.Scalar("SELECT count(*) FROM command_receipt;")));
        Assert.NotNull(commands.Inspect(original.CommandId));
        commands.SetResult(safety.CommandId, "SUCCEEDED", 2, "{\"synthetic_safety_observation\":true}");
        Assert.Equal(DurableDecision.Replay, commands.Admit(safety).Decision);
    }
}
