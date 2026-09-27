// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using Xunit;

namespace ArcForges.Foundation.Tests;

public sealed class ClockTests
{
    [Fact]
    public void LocaleAndPresentationDoNotChangeCanonicalValue()
    {
        var instant = new Instant(1_700_000_000, 123_456_700);
        var saved = new ZonedInstant(instant, "Europe/London");
        var previous = CultureInfo.CurrentCulture;
        try
        {
            foreach (var locale in new[] { "en-GB", "fr-FR", "ar-SA" })
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(locale);
                Assert.Equal("1700000000:123456700", instant.ToString());
                _ = saved.Present(TimeZoneInfo.FindSystemTimeZoneById("Asia/Tokyo"));
                Assert.Equal(instant, saved.Instant);
                Assert.Equal("Europe/London", saved.ZoneId);
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }

    [Fact]
    public void DurationsSurviveBackwardWallClockAdjustment()
    {
        var provider = new ManualTimeProvider();
        var clock = new Clock(provider);
        var wall = clock.GetCurrentInstant();
        var start = clock.GetTimestamp();
        provider.Now = provider.Now.AddHours(-1);
        provider.Timestamp += 2 * TimeSpan.TicksPerSecond;
        var end = clock.GetTimestamp();
        Assert.True(clock.GetCurrentInstant() < wall);
        Assert.Equal(TimeSpan.FromSeconds(2), clock.GetElapsedTime(start, end));
        Assert.Throws<ArgumentException>(() => clock.GetElapsedTime(default, end));
        Assert.Throws<ArgumentException>(() => new Clock(provider).GetElapsedTime(start, end));
        Assert.Throws<ArgumentOutOfRangeException>(() => clock.GetElapsedTime(end, start));
    }

    [Fact]
    public void DaylightSavingGapRefusesAndOverlapRequiresSelection()
    {
        var london = TimeZoneInfo.FindSystemTimeZoneById("Europe/London");
        var gap = new DateTime(2026, 3, 29, 1, 30, 0, DateTimeKind.Unspecified);
        Assert.Throws<ArgumentException>(() => ZonedInstant.Resolve(gap, london));
        var overlap = new DateTime(2026, 10, 25, 1, 30, 0, DateTimeKind.Unspecified);
        Assert.Throws<ArgumentException>(() => ZonedInstant.Resolve(overlap, london));
        Assert.Throws<ArgumentException>(() => ZonedInstant.Resolve(overlap, london, TimeSpan.FromHours(2)));
        var earlier = ZonedInstant.Resolve(overlap, london, TimeSpan.FromHours(1));
        var later = ZonedInstant.Resolve(overlap, london, TimeSpan.Zero);
        Assert.Equal(3_600, later.Instant.UnixSeconds - earlier.Instant.UnixSeconds);
        Assert.Equal("Europe/London", earlier.ZoneId);
        Assert.Equal("Europe/London", later.ZoneId);
    }

    [Fact]
    public void InstantPreservesNanosecondsAndRefusesLossyConversion()
    {
        Assert.Throws<InvalidOperationException>(() => new Instant(0, 1).ToDateTimeOffset());
        Assert.Throws<ArgumentOutOfRangeException>(() => new Instant(0, 1_000_000_000));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Instant(-62_135_596_801, 0));
        foreach (var value in new[] { DateTimeOffset.MinValue, DateTimeOffset.UnixEpoch.AddTicks(-1), DateTimeOffset.MaxValue })
        {
            Assert.Equal(value, Instant.FromDateTimeOffset(value).ToDateTimeOffset());
        }
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UnixEpoch;
        public long Timestamp { get; set; }
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow() => Now;
        public override long GetTimestamp() => Timestamp;
    }
}
