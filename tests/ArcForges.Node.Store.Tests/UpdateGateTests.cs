// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.AccessControl;
using System.Security.Principal;
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Store.Tests;

public sealed class UpdateGateTests
{
    private static readonly NativeUpdateCheckpoint Checkpoint = new(20, 20, 20, new string('c', 64));

    [Fact]
    public void AFirstStartLeaseFencesPublicationUntilItsReceiptCanCommit()
    {
        using var root = new TemporaryDataRoot();
        StorePaths.CreatePrivateDirectory(root.Path);
        var (previous, candidate) = Cohorts(root);
        Guid operation = Guid.NewGuid();

        using (var fresh = NativeUpdateGate.TryEnterFreshStart(root.Path))
        {
            Assert.NotNull(fresh);
            Assert.Null(NativeUpdateGate.TryEnterFreshStart(root.Path));
            Assert.ThrowsAny<IOException>(() => NativeUpdateGate.Begin(root.Path, operation, previous, candidate));
            Assert.False(File.Exists(Path.Combine(root.Path, "native-update.json")));
        }

        Assert.True(NativeUpdateGate.IsUnchangedUnfenced(root.Path, expected: null));
        var fenced = NativeUpdateGate.Begin(root.Path, operation, previous, candidate);
        Assert.Equal(fenced, NativeUpdateGate.Read(root.Path));
        Assert.False(NativeUpdateGate.IsUnchangedUnfenced(root.Path, expected: null));
        Assert.False(NativeUpdateGate.IsUnchangedUnfenced(root.Path, fenced));
        Assert.Null(NativeUpdateGate.TryEnterFreshStart(root.Path));
    }

    [Fact]
    public void PreparedAndReadyUpdatesSurviveReopenAndReleaseOnlyTheMatchingOperation()
    {
        using var root = new TemporaryDataRoot();
        StorePaths.CreatePrivateDirectory(root.Path);
        var (previous, candidate) = Cohorts(root);
        Guid operation = Guid.NewGuid();
        _ = NativeUpdateGate.Begin(root.Path, operation, previous, candidate);
        Assert.Throws<StoreIncompatibleException>(() => NativeUpdateGate.Prepare(root.Path, operation,
            Checkpoint with { CandidateReader = 19 }));
        Assert.Equal(NativeUpdatePhase.Fenced, NativeUpdateGate.Read(root.Path)!.Phase);
        var checkpoint = NativeUpdateGate.Prepare(root.Path, operation, Checkpoint);
        Assert.Equal(checkpoint, NativeUpdateGate.Prepare(root.Path, operation, Checkpoint));
        Assert.Throws<StoreIncompatibleException>(() => NativeUpdateGate.Complete(root.Path, operation));
        Assert.Throws<StoreIncompatibleException>(() => NativeUpdateGate.MarkReady(root.Path, Guid.NewGuid()));
        Assert.Throws<StoreIncompatibleException>(() => NativeUpdateGate.Begin(root.Path, Guid.NewGuid(), previous, candidate));

        var ready = NativeUpdateGate.MarkReady(root.Path, operation);
        Assert.Equal(Checkpoint, ready.Checkpoint);
        Assert.Equal(ready, NativeUpdateGate.Begin(root.Path, operation, previous, candidate));
        Assert.Null(NativeUpdateGate.TryEnterFreshStart(root.Path));

        var completed = NativeUpdateGate.Complete(root.Path, operation);
        Assert.Equal(completed, NativeUpdateGate.Read(root.Path));
        Assert.True(NativeUpdateGate.IsUnchangedUnfenced(root.Path, completed));
        Assert.False(NativeUpdateGate.IsUnchangedUnfenced(root.Path, completed with { OperationId = Guid.NewGuid() }));
        Assert.Equal(completed, NativeUpdateGate.Complete(root.Path, operation));
        Assert.Throws<StoreIncompatibleException>(() => NativeUpdateGate.MarkRolledBack(root.Path, operation));
        using var fresh = NativeUpdateGate.TryEnterFreshStart(root.Path);
        Assert.NotNull(fresh);
    }

    [Fact]
    public void IncompleteLegacyRecoveryRemainsRecoverableUntilOriginalReadinessIsRecorded()
    {
        using var root = new TemporaryDataRoot();
        StorePaths.CreatePrivateDirectory(root.Path);
        var (previous, candidate) = Cohorts(root);
        previous = previous with { DigestManifestSha256 = new string('a', 64) };
        candidate = candidate with { DigestManifestSha256 = new string('b', 64) };
        Guid operation = Guid.NewGuid();
        var authority = new NativeUpdateAuthority(new string('c', 32), new string('d', 32), previous.ArchiveSha256, 20, 20, null);
        _ = NativeUpdateGate.Begin(root.Path, operation, previous, candidate, authority);

        var recovering = NativeUpdateGate.BeginPrecompletionRestore(root.Path, operation);
        Assert.Equal(NativeUpdatePhase.RestoringPredecessor, recovering.Phase);
        Assert.Equal(recovering, NativeUpdateGate.Read(root.Path));
        Assert.Equal(recovering, NativeUpdateGate.BeginPrecompletionRestore(root.Path, operation));
        Assert.Null(NativeUpdateGate.TryEnterFreshStart(root.Path));
        Assert.Throws<StoreIncompatibleException>(() => NativeUpdateGate.MarkRolledBack(root.Path, operation));
        Assert.Throws<StoreIncompatibleException>(() => NativeUpdateGate.BeginRollback(root.Path, operation));

        var proof = new NativeUpdateReadiness(previous.ArchiveSha256, "fixture-owner", Environment.ProcessId, 1);
        var recovered = NativeUpdateGate.MarkRolledBack(root.Path, operation, proof);
        Assert.Equal(proof, recovered.RestoredOwner);
        Assert.False(recovered.IsFenced);
        Assert.Throws<StoreIncompatibleException>(() => NativeUpdateGate.BeginPrecompletionRestore(root.Path, operation));
    }

    [Fact]
    public void FenceSurvivesDatabaseDirectoryReplacementAndCorruptMarkerRefusesFreshWork()
    {
        using var root = new TemporaryDataRoot();
        StorePaths.CreatePrivateDirectory(Path.GetDirectoryName(root.Database)!);
        var (previous, candidate) = Cohorts(root);
        Guid operation = Guid.NewGuid();
        _ = NativeUpdateGate.Begin(root.Path, operation, previous, candidate);
        Directory.Move(Path.GetDirectoryName(root.Database)!, Path.Combine(root.Path, "previous-store"));
        StorePaths.CreatePrivateDirectory(Path.GetDirectoryName(root.Database)!);
        Assert.Null(NativeUpdateGate.TryEnterFreshStart(root.Path));
        var rollback = NativeUpdateGate.MarkRolledBack(root.Path, operation);
        Assert.False(rollback.IsFenced);
        using (var fresh = NativeUpdateGate.TryEnterFreshStart(root.Path))
            Assert.NotNull(fresh);

        File.WriteAllText(Path.Combine(root.Path, "native-update.json"), "{\"format\":1,\"phase\":4}");
        Assert.Null(NativeUpdateGate.TryEnterFreshStart(root.Path));
        Assert.Throws<StoreIncompatibleException>(() => NativeUpdateGate.Begin(root.Path, Guid.NewGuid(), previous, candidate));
    }

    [Fact]
    public void OfflineSnapshotRetainsTheAuthenticatedOwnerEpochAndDetectsChangedBackupBytes()
    {
        using var parent = new TemporaryDataRoot();
        using var restored = new TemporaryDataRoot();
        string dataRoot = Path.Combine(parent.Path, "live");
        const string owner = "update-fixture-owner";
        const string boot = "stable-fixture-boot";
        var options = new NodeStoreOptions { DataRoot = dataRoot, BootIdentity = boot };
        var secrets = NodeSecretStores.ForTestDataRoot(dataRoot);
        NativeUpdateAuthority authority;
        using (var store = NodeStore.OpenForV2Runtime(options))
        using (var commands = new DurableCommandStore(store, owner, secrets))
        {
            authority = new(Convert.ToHexStringLower(store.Metadata.NodeId.Span), Convert.ToHexStringLower(commands.OwnerEpoch.Span),
                null, store.Metadata.SchemaVersion, store.Metadata.MinReaderVersion, null);
        }

        byte[] original = File.ReadAllBytes(StorePaths.Database(dataRoot));
        var floor = NodeStore.InspectNativeUpdateFloor(dataRoot);
        Assert.Equal(new NativeUpdateStoreFloor(20, 20), floor);
        Assert.Equal(floor, NodeStore.InspectNativeUpdateFloor(dataRoot, requireDrained: true, previousAuthority: authority));
        Assert.Throws<DurableStoreMaintenanceException>(() => NodeStore.InspectNativeUpdateFloor(dataRoot,
            previousAuthority: authority with { OwnerEpoch = new string('c', 32) }));
        Assert.Throws<DurableStoreMaintenanceException>(() => NodeStore.InspectNativeUpdateFloor(dataRoot,
            previousAuthority: authority with { NodeId = new string('c', 32) }));
        Assert.Equal(original, File.ReadAllBytes(StorePaths.Database(dataRoot)));
        Assert.Throws<StoreIncompatibleException>(() => NodeStore.CaptureNativeUpdateBackup(
            dataRoot, owner, boot, authority, Guid.NewGuid(), 19, testMode: true));
        Assert.Equal(original, File.ReadAllBytes(StorePaths.Database(dataRoot)));

        var checkpoint = NodeStore.CaptureNativeUpdateBackup(
            dataRoot, owner, boot, authority, Guid.NewGuid(), 20, testMode: true);
        Assert.NotNull(checkpoint.BackupRoot);
        Assert.True(checkpoint.DrainConfirmed);
        DurableCommandStore.VerifyNativeUpdateBackup(checkpoint, testMode: true);
        DurableCommandStore.RestoreBackup(checkpoint.BackupRoot, NodeSecretStores.ForTestDataRoot(checkpoint.BackupRoot), dataRoot, secrets,
            restored.Path, NodeSecretStores.ForTestDataRoot(restored.Path), verifyNativeOffline: true);
        using (var store = restored.Open(new ManualClock(), StoreMigrations.Released))
        using (var commands = new DurableCommandStore(store, owner, NodeSecretStores.ForTestDataRoot(restored.Path)))
        {
            Assert.Equal(authority.NodeId, Convert.ToHexStringLower(store.Metadata.NodeId.Span));
            Assert.Equal(authority.OwnerEpoch, Convert.ToHexStringLower(commands.OwnerEpoch.Span));
        }

        File.AppendAllText(StorePaths.Database(checkpoint.BackupRoot), "invalid fixture bytes");
        Assert.Throws<DurableStoreMaintenanceException>(() => DurableCommandStore.VerifyNativeUpdateBackup(checkpoint, testMode: true));
    }

    [Fact]
    public void AStartingRunRefusesBackupBeforeCreatingOutputOrWritingTheStore()
    {
        using var parent = new TemporaryDataRoot();
        string dataRoot = Path.Combine(parent.Path, "live");
        const string owner = "update-fixture-owner";
        const string boot = "stable-fixture-boot";
        var options = new NodeStoreOptions { DataRoot = dataRoot, BootIdentity = boot };
        string sandboxId = Guid.NewGuid().ToString("N");
        string runId = Guid.NewGuid().ToString("N");
        string epoch = Guid.NewGuid().ToString("N");
        string hash = new('a', 64);
        var now = DateTimeOffset.UtcNow;
        NativeUpdateAuthority authority;
        using (var store = NodeStore.OpenForV2Runtime(options))
        using (var commands = new DurableCommandStore(store, owner, NodeSecretStores.ForTestDataRoot(dataRoot)))
        {
            authority = new(Convert.ToHexStringLower(store.Metadata.NodeId.Span), Convert.ToHexStringLower(commands.OwnerEpoch.Span),
                null, store.Metadata.SchemaVersion, store.Metadata.MinReaderVersion, null);
            var sandbox = new StoredSandbox(sandboxId, owner, "fixture", "fixture", 1, StoredSandboxState.Creating,
                "sandboxes/" + sandboxId, SandboxRecords.PendingRootIdentity, 1, now, now, new("profile", "1", "{}", hash));
            var run = new StoredRun(runId, sandboxId, 1, 1, StoredRunState.Starting, epoch, hash, "{}", StoredPayloadStart.Unknown, now);
            store.Write(tx =>
            {
                SandboxRecords.Reserve(tx, sandbox);
                Assert.True(SandboxRecords.SettleCreation(tx, owner, sandboxId, "fixture-root", StoredSandboxState.Ready));
                Assert.True(RunRecords.InsertStarting(tx, owner, run));
            }, CommitDurability.Full);
        }

        byte[] before = File.ReadAllBytes(StorePaths.Database(dataRoot));
        var refusal = Assert.Throws<StoreIncompatibleException>(() => NodeStore.CaptureNativeUpdateBackup(
            dataRoot, owner, boot, authority, Guid.NewGuid(), 20, testMode: true));
        Assert.Equal("native_update_supervisor_drain_required", refusal.Message);
        Assert.Equal(before, File.ReadAllBytes(StorePaths.Database(dataRoot)));
        Assert.Single(Directory.EnumerateFileSystemEntries(parent.Path));
    }

    [Fact]
    public void PublishedGateRejectsStorePathWithoutVerifiedCustody()
    {
        using var parent = new TemporaryDataRoot();
        string dataRoot = Path.Combine(parent.Path, "live");
        StorePaths.CreatePrivateDirectory(dataRoot);
        using (var initial = NativeUpdateGate.TryEnterFreshStart(dataRoot))
            Assert.NotNull(initial);
        if (OperatingSystem.IsLinux())
        {
            File.SetUnixFileMode(parent.Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupWrite);
        }
        else if (OperatingSystem.IsWindows())
        {
            var leaf = new DirectoryInfo(dataRoot);
            var original = leaf.GetAccessControl();
            var overbroad = leaf.GetAccessControl();
            overbroad.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.Write, AccessControlType.Allow));
            leaf.SetAccessControl(overbroad);
            try { Assert.Null(NativeUpdateGate.TryEnterFreshStart(dataRoot)); }
            finally { leaf.SetAccessControl(original); }
            return;
        }

        Assert.Null(NativeUpdateGate.TryEnterFreshStart(dataRoot));
    }

    private static (NativeUpdateCohort Previous, NativeUpdateCohort Candidate) Cohorts(TemporaryDataRoot root) =>
        (new(new string('a', 40), new string('d', 40), new string('a', 64), Path.Combine(root.Path, "previous")),
         new(new string('b', 40), new string('e', 40), new string('b', 64), Path.Combine(root.Path, "candidate")));
}
