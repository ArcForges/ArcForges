// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Foundation;

/// <summary>A timestamp meaningful only inside the clock instance that issued it.</summary>
public readonly record struct MonotonicTimestamp
{
    internal MonotonicTimestamp(long ticks, object source)
    {
        Ticks = ticks;
        Source = source;
    }

    internal long Ticks { get; }
    internal object? Source { get; }
}

public interface IClock
{
    Instant GetCurrentInstant();
    MonotonicTimestamp GetTimestamp();
    TimeSpan GetElapsedTime(MonotonicTimestamp start, MonotonicTimestamp end);
}

/// <summary>Uses TimeProvider's independent wall and monotonic sources, allowing deterministic injection.</summary>
public sealed class Clock : IClock
{
    private readonly TimeProvider _provider;

    public Clock(TimeProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _provider = provider;
    }

    public static Clock System { get; } = new(TimeProvider.System);

    public Instant GetCurrentInstant() => Instant.FromDateTimeOffset(_provider.GetUtcNow());
    public MonotonicTimestamp GetTimestamp() => new(_provider.GetTimestamp(), this);

    public TimeSpan GetElapsedTime(MonotonicTimestamp start, MonotonicTimestamp end)
    {
        if (!ReferenceEquals(start.Source, this) || !ReferenceEquals(end.Source, this))
        {
            throw new ArgumentException("Timestamps must originate from this clock instance.", nameof(start));
        }

        var elapsed = _provider.GetElapsedTime(start.Ticks, end.Ticks);
        if (elapsed < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(end), "The end timestamp precedes the start.");
        }

        return elapsed;
    }
}
