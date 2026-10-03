// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.LocalRpc;

/// <summary>
/// The full-jitter wait before the next attempt or reconnect: uniform in zero through a ceiling that starts at 250 ms and
/// doubles with every attempt up to 30 seconds (annex 09, section 2). The random source is injectable so a test can pin it.
/// </summary>
public sealed class LocalRpcBackoff
{
    /// <summary>The ceiling of the first wait (250 ms).</summary>
    public static readonly TimeSpan DefaultInitial = TimeSpan.FromMilliseconds(250);

    /// <summary>The largest ceiling (30 s).</summary>
    public static readonly TimeSpan DefaultMaximum = TimeSpan.FromSeconds(30);

    private readonly Func<double> _random;

    /// <summary>Creates a schedule.</summary>
    /// <param name="initial">The ceiling of the first wait; positive. Default 250 ms.</param>
    /// <param name="maximum">The largest ceiling; at least <paramref name="initial"/>. Default 30 s.</param>
    /// <param name="random">A source of values in zero through one; default the shared random generator.</param>
    public LocalRpcBackoff(TimeSpan? initial = null, TimeSpan? maximum = null, Func<double>? random = null)
    {
        Initial = initial ?? DefaultInitial;
        Maximum = maximum ?? DefaultMaximum;
        if (Initial <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(initial), Initial, "The first ceiling is positive.");
        }

        if (Maximum < Initial)
        {
            throw new ArgumentOutOfRangeException(nameof(maximum), Maximum, "The largest ceiling is at least the first.");
        }

        _random = random ?? Random.Shared.NextDouble;
    }

    /// <summary>The ceiling of the first wait.</summary>
    public TimeSpan Initial { get; }

    /// <summary>The largest ceiling.</summary>
    public TimeSpan Maximum { get; }

    /// <summary>The ceiling of the wait after the given attempt (1 is the first): doubled each time and never above <paramref name="maximum"/>.</summary>
    public static TimeSpan Ceiling(int attempt, TimeSpan initial, TimeSpan maximum)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(attempt, 1);
        var ticks = initial.Ticks;
        for (var step = 1; step < attempt; step++)
        {
            if (ticks > maximum.Ticks - ticks)
            {
                return maximum;
            }

            ticks *= 2;
        }

        return ticks < maximum.Ticks ? TimeSpan.FromTicks(ticks) : maximum;
    }

    /// <summary>The wait after the given attempt (1 is the first): a random time in zero through <see cref="Ceiling"/>.</summary>
    public TimeSpan Next(int attempt)
    {
        var ceiling = Ceiling(attempt, Initial, Maximum);
        var draw = _random();
        if (!(draw >= 0.0 && draw <= 1.0))
        {
            throw new InvalidOperationException("The random source returns values in zero through one.");
        }

        return TimeSpan.FromTicks((long)(ceiling.Ticks * draw));
    }
}
