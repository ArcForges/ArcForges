// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using ArcForges.Node.Core.Files;

namespace ArcForges.Node.Core.Tests;

/// <summary>Concurrent accounting only; real stage acquisition and crash recovery remain separate integration work.</summary>
public sealed class FileStageBudgetTests
{
    [Fact]
    public void SlotBoundAndIdempotentReleaseDoNotOvercommit()
    {
        var budget = new FileStageBudget();
        var held = Enumerable.Range(0, FileStageBudget.MaximumMutations).Select(_ => budget.TryReserve(0, 0)).ToArray();
        Assert.All(held, Assert.NotNull);
        Assert.Null(budget.TryReserve(0, 0));
        Assert.Equal((64, 0L), budget.Snapshot());
        held[0]!.Dispose();
        held[0]!.Dispose();
        Assert.Equal((63, 0L), budget.Snapshot());
        using var replacement = budget.TryReserve(0, 0);
        Assert.NotNull(replacement);
        Assert.Equal((64, 0L), budget.Snapshot());
        foreach (var lease in held.Skip(1)) lease!.Dispose();
        replacement!.Dispose();
        Assert.Equal((0, 0L), budget.Snapshot());
    }

    [Fact]
    public void ByteBoundCountsBothStagesBeforeAcquisition()
    {
        var budget = new FileStageBudget();
        var held = Enumerable.Range(0, 32).Select(_ =>
            budget.TryReserve(FileStageBudget.MaximumFileBytes, FileStageBudget.MaximumFileBytes)).ToArray();
        Assert.All(held, Assert.NotNull);
        Assert.Equal((32, FileStageBudget.MaximumBytes), budget.Snapshot());
        Assert.Null(budget.TryReserve(0, 1));
        held[0]!.Dispose();
        using var replacement = budget.TryReserve(FileStageBudget.MaximumFileBytes, FileStageBudget.MaximumFileBytes);
        Assert.NotNull(replacement);
        Assert.Null(budget.TryReserve(1, 0));
        foreach (var lease in held.Skip(1)) lease!.Dispose();
        replacement!.Dispose();
        Assert.Equal((0, 0L), budget.Snapshot());
        Assert.Throws<ArgumentOutOfRangeException>(() => budget.TryReserve(-1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => budget.TryReserve(0, FileStageBudget.MaximumFileBytes + 1));
    }

    [Fact]
    public void ConcurrentReservationsCannotExceedEitherBound()
    {
        var budget = new FileStageBudget();
        var held = new ConcurrentBag<FileStageBudget.Lease>();
        Parallel.For(0, 160, _ =>
        {
            var lease = budget.TryReserve(FileStageBudget.MaximumFileBytes, 0);
            if (lease is not null) held.Add(lease);
        });
        Assert.Equal(64, held.Count);
        Assert.Equal((64, FileStageBudget.MaximumBytes), budget.Snapshot());
        Parallel.ForEach(held, lease =>
        {
            lease.Dispose();
            lease.Dispose();
        });
        Assert.Equal((0, 0L), budget.Snapshot());
    }
}
