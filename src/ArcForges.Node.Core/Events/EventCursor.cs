// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Node.Core.Events;

/// <summary>
/// A stream position as an opaque cursor (events.proto <c>StreamPosition.cursor</c>): the stream generation and the sequence number of
/// the last event a client applied, written <c>v1.&lt;generation&gt;.&lt;sequence&gt;</c>. Clients treat it as opaque text.
/// </summary>
public readonly record struct EventCursor(ulong Generation, ulong Sequence)
{
    private const string Prefix = "v1.";

    /// <summary>The cursor text.</summary>
    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{Prefix}{Generation}.{Sequence}");

    /// <summary>Parses a cursor; false when the text is not one this node wrote (<c>VALIDATION/invalid_cursor</c>).</summary>
    public static bool TryParse(string? text, out EventCursor cursor)
    {
        cursor = default;
        if (text is null || text.Length > 64 || !text.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var parts = text[Prefix.Length..].Split('.');
        if (parts.Length != 2
            || !ulong.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var generation) || generation == 0
            || !ulong.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var sequence))
        {
            return false;
        }

        cursor = new EventCursor(generation, sequence);
        return true;
    }
}
