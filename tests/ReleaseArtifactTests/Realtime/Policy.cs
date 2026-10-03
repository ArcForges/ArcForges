// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;

namespace RealtimeAotProbe;

/// <summary>The stream and recovery limits of annex 10 section 5, as one immutable value.</summary>
/// <remarks>
/// Every number below is quoted from <c>contracts/10-application-scope-and-streams.md</c> section 5/8 or
/// <c>contracts/03-realtime-and-bridge.md</c> section 4, except <see cref="MaximumRetryAfter"/> and the
/// two page bounds, which are this probe's own client-side bounds and are named as such.
/// </remarks>
internal sealed record RealtimePolicy
{
    /// <summary>The client reconnects after this much silence (the server heartbeats every 15 seconds).</summary>
    public TimeSpan SilenceTimeout { get; init; } = TimeSpan.FromSeconds(45);

    /// <summary>The first reconnect ceiling; the ceiling doubles per consecutive failure.</summary>
    public TimeSpan ReconnectBase { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>The reconnect ceiling never exceeds this.</summary>
    public TimeSpan ReconnectCap { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>A connection that stayed up this long resets the reconnect ladder.</summary>
    public TimeSpan StableConnection { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Poll cadence of the browser-support fallback profile.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>ReadOutput cadence of the same fallback profile.</summary>
    public TimeSpan ReadOutputInterval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>The cadence jitter, as a fraction: 0.2 means plus or minus 20 percent.</summary>
    public double CadenceJitter { get; init; } = 0.2;

    /// <summary>The longest server supplied retry time this probe will wait (its own bound: the 5 minute stream lifetime).</summary>
    public TimeSpan MaximumRetryAfter { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>The largest <c>OutputChunk.data</c> a frame may carry (32 KiB, annex 10 section 2).</summary>
    public int MaximumChunkBytes { get; init; } = 32 * 1024;

    /// <summary>The most chunks one ReadOutput page may carry (annex 10 section 4: default and maximum 100).</summary>
    public int MaximumPageChunks { get; init; } = 100;

    /// <summary>The most chunk bytes one ReadOutput page may carry (annex 10 section 4: 256 KiB response).</summary>
    public int MaximumPageBytes { get; init; } = 256 * 1024;
}

/// <summary>Exponential full-jitter reconnect schedule from the base to the cap.</summary>
/// <remarks>
/// "Reconnect exponential full jitter from 0.5s to 30s, resets after 30s stable connectivity" is read as: the
/// ceiling of attempt <c>n</c> is <c>min(cap, base * 2^n)</c> and the delay is uniform in <c>[0, ceiling)</c>.
/// </remarks>
internal sealed class ReconnectBackoff(RealtimePolicy policy)
{
    private readonly RealtimePolicy _policy = policy;
    private int _attempt;

    /// <summary>The number of delays handed out since the ladder was last reset.</summary>
    public int Attempt => _attempt;

    /// <summary>The ceiling the next delay is drawn under.</summary>
    public TimeSpan NextCeiling()
    {
        double ticks = _policy.ReconnectBase.Ticks * Math.Pow(2, Math.Min(_attempt, 62));
        return TimeSpan.FromTicks((long)Math.Min(ticks, _policy.ReconnectCap.Ticks));
    }

    /// <summary>Draw the next delay and climb the ladder.</summary>
    /// <param name="random">A uniform value in [0, 1).</param>
    public TimeSpan NextDelay(Func<double> random)
    {
        ArgumentNullException.ThrowIfNull(random);
        TimeSpan ceiling = NextCeiling();
        double fraction = Math.Clamp(random(), 0d, 1d);
        if (_attempt < int.MaxValue)
        {
            _attempt++;
        }

        return TimeSpan.FromTicks((long)(ceiling.Ticks * fraction));
    }

    /// <summary>Report how long the connection that just ended had been up.</summary>
    public void ConnectionEnded(TimeSpan connectedFor)
    {
        if (connectedFor >= _policy.StableConnection)
        {
            _attempt = 0;
        }
    }

    /// <summary>A successful unary exchange is stable connectivity.</summary>
    public void Succeeded() => _attempt = 0;
}

/// <summary>The cadence of the periodic Poll/ReadOutput fallback with symmetric jitter.</summary>
internal static class Pacing
{
    /// <summary>The interval until the next call: <c>interval * (1 + jitter * (2r - 1))</c>.</summary>
    public static TimeSpan Next(TimeSpan interval, double jitter, Func<double> random)
    {
        ArgumentNullException.ThrowIfNull(random);
        double scale = 1d + (jitter * ((2d * Math.Clamp(random(), 0d, 1d)) - 1d));
        return TimeSpan.FromTicks((long)(interval.Ticks * scale));
    }
}

/// <summary>The randomness of jitter. It spreads reconnects and has no security role.</summary>
internal static class Jitter
{
    [SuppressMessage("Security", "CA5394", Justification = "Reconnect and poll jitter only spreads load; it is not a security decision.")]
    public static double Next() => Random.Shared.NextDouble();
}
