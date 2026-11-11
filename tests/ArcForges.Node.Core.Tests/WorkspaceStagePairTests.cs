// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real native synchronous stages plus in-process quota; no named approval, durable accounting or routed mutation.</summary>
public sealed class WorkspaceStagePairTests
{
    [Fact]
    public void ActualTwoStagesRetainTheirReservationUntilBothNodeHandlesClose()
    {
        using var fixture = new Fixture();
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        var budget = new FileStageBudget();
        var original = "original synthetic stage bytes"u8.ToArray();
        var intended = "intended synthetic stage bytes"u8.ToArray();
        using (var pair = WorkspaceStagePair.TryCreate(root, budget, original, intended, TestContext.Current.CancellationToken))
        {
            Assert.NotNull(pair);
            Assert.NotNull(pair.Original);
            Assert.Equal((1, (long)original.Length + intended.Length), budget.Snapshot());
            Assert.True(pair.Original.Verify(TestContext.Current.CancellationToken));
            Assert.True(pair.Intended.Verify(TestContext.Current.CancellationToken));
            Assert.Equal(SHA256.HashData(original), pair.Original.Sha256.ToArray());
            Assert.Equal(SHA256.HashData(intended), pair.Intended.Sha256.ToArray());
            Assert.False(pair.Original.ObjectIdentity.SameObject(pair.Intended.ObjectIdentity));
        }
        Assert.Equal((0, 0L), budget.Snapshot());
        Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.Root));
    }

    [Fact]
    public void ExhaustedBudgetRefusesBeforeCreatingAnActualStage()
    {
        using var fixture = new Fixture();
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        var budget = new FileStageBudget();
        var held = Enumerable.Range(0, 32).Select(_ =>
            budget.TryReserve(FileStageBudget.MaximumFileBytes, FileStageBudget.MaximumFileBytes)).ToArray();
        try
        {
            Assert.All(held, Assert.NotNull);
            Assert.Null(WorkspaceStagePair.TryCreate(root, budget, null, "small"u8.ToArray(), TestContext.Current.CancellationToken));
            Assert.Equal((32, FileStageBudget.MaximumBytes), budget.Snapshot());
            Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.Root));
        }
        finally
        {
            foreach (var reservation in held) reservation?.Dispose();
        }
        Assert.Equal((0, 0L), budget.Snapshot());
    }

    [Fact]
    public void AbsentOriginalUsesOneStageAndCanceledAdmissionCreatesNone()
    {
        using var fixture = new Fixture();
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        var budget = new FileStageBudget();
        var content = "new file synthetic bytes"u8.ToArray();
        using (var pair = WorkspaceStagePair.TryCreate(root, budget, null, content, TestContext.Current.CancellationToken))
        {
            Assert.NotNull(pair);
            Assert.Null(pair.Original);
            Assert.Equal((1, (long)content.Length), budget.Snapshot());
            Assert.True(pair.Intended.Verify(TestContext.Current.CancellationToken));
        }
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => WorkspaceStagePair.TryCreate(root, budget, null, content, canceled.Token));
        Assert.Equal((0, 0L), budget.Snapshot());
        Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.Root));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-stage-pair-");
        internal string Root => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
