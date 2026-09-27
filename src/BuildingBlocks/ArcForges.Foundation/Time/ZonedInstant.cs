// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Foundation;

/// <summary>Stores a resolved instant and its semantically meaningful originating zone.</summary>
public sealed record ZonedInstant
{
    public ZonedInstant(Instant instant, string zoneId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(zoneId);
        _ = TimeZoneInfo.FindSystemTimeZoneById(zoneId);
        Instant = instant;
        ZoneId = zoneId;
    }

    public Instant Instant { get; }
    public string ZoneId { get; }

    /// <summary>Refuses nonexistent local times; overlap resolution requires a valid explicit offset.</summary>
    public static ZonedInstant Resolve(DateTime localTime, TimeZoneInfo zone, TimeSpan? ambiguousOffset = null)
    {
        ArgumentNullException.ThrowIfNull(zone);
        if (localTime.Kind != DateTimeKind.Unspecified || zone.IsInvalidTime(localTime))
        {
            throw new ArgumentException("A valid unspecified local time is required.", nameof(localTime));
        }

        TimeSpan offset;
        if (zone.IsAmbiguousTime(localTime))
        {
            if (ambiguousOffset is not { } selected || !zone.GetAmbiguousTimeOffsets(localTime).Contains(selected))
            {
                throw new ArgumentException("An overlap requires an explicit valid offset.", nameof(ambiguousOffset));
            }

            offset = selected;
        }
        else
        {
            offset = zone.GetUtcOffset(localTime);
            if (ambiguousOffset is { } selected && selected != offset)
            {
                throw new ArgumentException("The offset does not match the zone.", nameof(ambiguousOffset));
            }
        }

        return new ZonedInstant(Instant.FromDateTimeOffset(new DateTimeOffset(localTime, offset)), zone.Id);
    }

    public DateTimeOffset Present(TimeZoneInfo zone)
    {
        ArgumentNullException.ThrowIfNull(zone);
        return TimeZoneInfo.ConvertTime(Instant.ToDateTimeOffset(), zone);
    }
}
