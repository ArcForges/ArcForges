// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Foundation;

/// <summary>A canonical UTC instant, retaining the registry's nanosecond precision.</summary>
public readonly record struct Instant : IComparable<Instant>
{
    public Instant(long unixSeconds, uint nanoseconds)
    {
        if (unixSeconds is < -62135596800 or > 253402300799)
        {
            throw new ArgumentOutOfRangeException(nameof(unixSeconds));
        }

        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(nanoseconds, 1_000_000_000U);

        UnixSeconds = unixSeconds;
        Nanoseconds = nanoseconds;
    }

    public long UnixSeconds { get; }
    public uint Nanoseconds { get; }

    public static Instant FromDateTimeOffset(DateTimeOffset value)
    {
        var seconds = value.ToUnixTimeSeconds();
        var remainder = value.UtcTicks - DateTimeOffset.FromUnixTimeSeconds(seconds).UtcTicks;
        return new Instant(seconds, checked((uint)(remainder * 100)));
    }

    /// <summary>Refuses loss of sub-tick precision at the .NET boundary.</summary>
    public DateTimeOffset ToDateTimeOffset()
    {
        if (Nanoseconds % 100 != 0)
        {
            throw new InvalidOperationException("The instant cannot be represented exactly as .NET ticks.");
        }

        return DateTimeOffset.FromUnixTimeSeconds(UnixSeconds).AddTicks(Nanoseconds / 100);
    }

    public int CompareTo(Instant other)
    {
        var seconds = UnixSeconds.CompareTo(other.UnixSeconds);
        return seconds != 0 ? seconds : Nanoseconds.CompareTo(other.Nanoseconds);
    }

    public static bool operator <(Instant left, Instant right) => left.CompareTo(right) < 0;
    public static bool operator >(Instant left, Instant right) => left.CompareTo(right) > 0;
    public static bool operator <=(Instant left, Instant right) => left.CompareTo(right) <= 0;
    public static bool operator >=(Instant left, Instant right) => left.CompareTo(right) >= 0;

    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{UnixSeconds}:{Nanoseconds:D9}");
}
