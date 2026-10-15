// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Node.Store;

/// <summary>
/// Store instants are microseconds since the Unix epoch (node-store.md section 1), the unit of the Cloud D1 model.
/// The clock is a <see cref="TimeProvider"/>: the node's <c>IClock</c> of 16-testing-strategy section 4, which tests
/// replace with a controllable clock.
/// </summary>
public static class StoreTime
{
    /// <summary>The current instant of <paramref name="clock"/> in microseconds since the Unix epoch.</summary>
    public static long NowMicroseconds(TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        return ToMicroseconds(clock.GetUtcNow());
    }

    /// <summary>Microseconds since the Unix epoch.</summary>
    public static long ToMicroseconds(DateTimeOffset instant) => (instant.UtcTicks - DateTime.UnixEpoch.Ticks) / 10;

    /// <summary>The instant of a microsecond timestamp.</summary>
    public static DateTimeOffset FromMicroseconds(long microseconds) =>
        new(DateTime.UnixEpoch.Ticks + (microseconds * 10), TimeSpan.Zero);

    /// <summary>RFC 3339 text of a microsecond timestamp, as shown in error details.</summary>
    public static string ToRfc3339(long microseconds) =>
        FromMicroseconds(microseconds).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
}

/// <summary>16-byte UUIDv7 identifiers in big-endian (RFC 9562) byte order, so they sort by creation time.</summary>
public static class StoreIds
{
    /// <summary>The length of every store ID.</summary>
    public const int Length = 16;

    /// <summary>A new UUIDv7 for the current instant of <paramref name="clock"/>.</summary>
    public static byte[] NewUuid7(TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        return Guid.CreateVersion7(clock.GetUtcNow()).ToByteArray(bigEndian: true);
    }

    /// <summary>Throws unless <paramref name="id"/> is a 16-byte ID.</summary>
    public static void Validate(ReadOnlySpan<byte> id, string parameterName)
    {
        if (id.Length != Length)
        {
            throw new ArgumentException("Store IDs are 16 bytes (UUIDv7).", parameterName);
        }
    }

    /// <summary>Lowercase hexadecimal text of an ID, for logs and file names.</summary>
    public static string ToHex(ReadOnlySpan<byte> id) => Convert.ToHexStringLower(id);
}
