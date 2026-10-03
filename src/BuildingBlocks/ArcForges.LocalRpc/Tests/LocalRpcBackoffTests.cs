// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.LocalRpc.Tests;

[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcBackoffTests
{
    [Fact]
    public void TheCeilingStartsAt250MillisecondsDoublesEveryAttemptAndStopsAtThirtySeconds()
    {
        long[] expectedMilliseconds = [250, 500, 1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000];

        for (var attempt = 1; attempt <= expectedMilliseconds.Length; attempt++)
        {
            Assert.Equal(
                TimeSpan.FromMilliseconds(expectedMilliseconds[attempt - 1]),
                LocalRpcBackoff.Ceiling(attempt, LocalRpcBackoff.DefaultInitial, LocalRpcBackoff.DefaultMaximum));
        }

        Assert.Equal(TimeSpan.FromMilliseconds(250), LocalRpcBackoff.DefaultInitial);
        Assert.Equal(TimeSpan.FromSeconds(30), LocalRpcBackoff.DefaultMaximum);
    }

    [Fact]
    public void ADoublingThatWouldPassTheMaximumIsCappedExactlyAndNeverRoundedDown()
    {
        // 7 ticks of maximum: 3 doubles to 6 (still below), the next doubling (12) is capped at 7. Half of 7 rounds down to 3, which a naive
        // "at least half of the maximum" test would cap one doubling too early.
        Assert.Equal(TimeSpan.FromTicks(3), LocalRpcBackoff.Ceiling(1, TimeSpan.FromTicks(3), TimeSpan.FromTicks(7)));
        Assert.Equal(TimeSpan.FromTicks(6), LocalRpcBackoff.Ceiling(2, TimeSpan.FromTicks(3), TimeSpan.FromTicks(7)));
        Assert.Equal(TimeSpan.FromTicks(7), LocalRpcBackoff.Ceiling(3, TimeSpan.FromTicks(3), TimeSpan.FromTicks(7)));

        // A first ceiling that already equals the maximum never grows, and one above it is brought down to it.
        Assert.Equal(TimeSpan.FromSeconds(5), LocalRpcBackoff.Ceiling(1, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5)));
        Assert.Equal(TimeSpan.FromSeconds(5), LocalRpcBackoff.Ceiling(9, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5)));
        Assert.Equal(TimeSpan.FromSeconds(5), LocalRpcBackoff.Ceiling(1, TimeSpan.FromSeconds(9), TimeSpan.FromSeconds(5)));

        // Doubling that lands exactly on the maximum is allowed and is not capped early.
        Assert.Equal(TimeSpan.FromSeconds(20), LocalRpcBackoff.Ceiling(2, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(20)));
    }

    [Fact]
    public void AnAbsurdAttemptNumberNeverOverflowsOrLoops()
    {
        var started = System.Diagnostics.Stopwatch.GetTimestamp();

        var ceiling = LocalRpcBackoff.Ceiling(int.MaxValue, TimeSpan.FromTicks(1), TimeSpan.FromSeconds(30));

        Assert.Equal(TimeSpan.FromSeconds(30), ceiling);
        Assert.True(System.Diagnostics.Stopwatch.GetElapsedTime(started) < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void TheWaitIsAUniformDrawBetweenZeroAndTheCeiling()
    {
        Assert.Equal(TimeSpan.Zero, new LocalRpcBackoff(random: () => 0.0).Next(3));
        Assert.Equal(TimeSpan.FromSeconds(1), new LocalRpcBackoff(random: () => 1.0).Next(3));
        Assert.Equal(TimeSpan.FromMilliseconds(500), new LocalRpcBackoff(random: () => 0.5).Next(3));
        Assert.Equal(TimeSpan.FromMilliseconds(125), new LocalRpcBackoff(random: () => 0.5).Next(1));
        Assert.Equal(TimeSpan.FromSeconds(15), new LocalRpcBackoff(random: () => 0.5).Next(40));
    }

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(-0.01)]
    [InlineData(1.01)]
    [InlineData(double.PositiveInfinity)]
    public void ARandomSourceOutsideZeroToOneIsRefusedInsteadOfProducingAWildWait(double draw)
    {
        var backoff = new LocalRpcBackoff(random: () => draw);

        _ = Assert.Throws<InvalidOperationException>(() => backoff.Next(1));
    }

    [Fact]
    public void TheDefaultRandomSourceVariesAndNeverExceedsTheCeiling()
    {
        var backoff = new LocalRpcBackoff();
        var draws = Enumerable.Range(0, 500).Select(_ => backoff.Next(4)).ToArray();

        Assert.All(draws, draw => Assert.InRange(draw, TimeSpan.Zero, TimeSpan.FromSeconds(2)));
        Assert.True(draws.Distinct().Count() > 100, "A full-jitter wait is spread over its range, not a constant.");
        Assert.True(draws.Any(draw => draw > TimeSpan.FromSeconds(1)) && draws.Any(draw => draw < TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public void BoundsAreValidated()
    {
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcBackoff(initial: TimeSpan.Zero));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcBackoff(initial: TimeSpan.FromSeconds(-1)));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcBackoff(initial: TimeSpan.FromSeconds(2), maximum: TimeSpan.FromSeconds(1)));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => LocalRpcBackoff.Ceiling(0, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2)));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcBackoff().Next(0));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcBackoff().Next(-3));

        var equal = new LocalRpcBackoff(TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3));
        Assert.Equal(TimeSpan.FromSeconds(3), equal.Initial);
        Assert.Equal(TimeSpan.FromSeconds(3), equal.Maximum);
    }
}
