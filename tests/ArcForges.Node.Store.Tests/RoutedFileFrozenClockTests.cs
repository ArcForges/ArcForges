// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;

namespace ArcForges.Node.Store.Tests;

/// <summary>A deliberately frozen wall-time source while the actual native monotonic clock runs for over two minutes.</summary>
public sealed class RoutedFileFrozenClockTests
{
    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task FrozenWallTimeBecomesUnhealthyWithRealMonotonicElapsedTime()
    {
        var cancellation = TestContext.Current.CancellationToken;
        using var root = new TemporaryDataRoot();
        var clock = new FrozenSystemClock();
        using var store = root.Open(clock);
        var before = store.Write(RoutedFileValidationTime.Advance, CommitDurability.Full);
        Assert.True(before.Healthy);
        clock.Freeze();
        var started = Stopwatch.GetTimestamp();
        await Task.Delay(TimeSpan.FromSeconds(122), cancellation);
        var actualElapsed = Stopwatch.GetElapsedTime(started);
        Assert.True(actualElapsed >= TimeSpan.FromSeconds(121));
        var frozen = store.Write(RoutedFileValidationTime.Advance, CommitDurability.Full);
        Assert.False(frozen.Healthy);
        Assert.True(frozen.BoundaryMicroseconds > before.BoundaryMicroseconds + 120L * 1_000_000);
        Assert.Equal(frozen.BoundaryMicroseconds, store.Read(reader => reader.Scalar(
            "SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;")));
    }

    private sealed class FrozenSystemClock : TimeProvider
    {
        private DateTimeOffset? _frozen;

        internal void Freeze() => _frozen = TimeProvider.System.GetUtcNow();

        public override DateTimeOffset GetUtcNow() => _frozen ?? TimeProvider.System.GetUtcNow();

        public override long GetTimestamp() => TimeProvider.System.GetTimestamp();

        public override long TimestampFrequency => TimeProvider.System.TimestampFrequency;
    }
}
