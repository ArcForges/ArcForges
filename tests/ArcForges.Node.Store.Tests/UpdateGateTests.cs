// SPDX-License-Identifier: AGPL-3.0-only
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

        var fenced = NativeUpdateGate.Begin(root.Path, operation, previous, candidate);
        Assert.Equal(fenced, NativeUpdateGate.Read(root.Path));
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
        Assert.Equal(completed, NativeUpdateGate.Complete(root.Path, operation));
        Assert.Throws<StoreIncompatibleException>(() => NativeUpdateGate.MarkRolledBack(root.Path, operation));
        using var fresh = NativeUpdateGate.TryEnterFreshStart(root.Path);
        Assert.NotNull(fresh);
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

    private static (NativeUpdateCohort Previous, NativeUpdateCohort Candidate) Cohorts(TemporaryDataRoot root) =>
        (new(new string('a', 40), new string('d', 40), new string('a', 64), Path.Combine(root.Path, "previous")),
         new(new string('b', 40), new string('e', 40), new string('b', 64), Path.Combine(root.Path, "candidate")));
}
