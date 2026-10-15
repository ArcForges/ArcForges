// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Node.Core;

/// <summary>
/// The position of a newest-first listing: the creation time and ID of the last row returned, written
/// <c>&lt;created_at microseconds&gt;.&lt;id hex&gt;</c>. A page continues strictly after it.
/// </summary>
public readonly record struct PageCursor(long CreatedAt, byte[] Id)
{
    /// <summary>The cursor text.</summary>
    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{CreatedAt}.{Convert.ToHexStringLower(Id)}");

    /// <summary>Parses a cursor this node issued.</summary>
    public static bool TryParse(string? text, out PageCursor cursor)
    {
        cursor = default;
        if (string.IsNullOrEmpty(text) || text.Length > 64)
        {
            return false;
        }

        var dot = text.IndexOf('.', StringComparison.Ordinal);
        if (dot <= 0 || !long.TryParse(text.AsSpan(0, dot), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var created))
        {
            return false;
        }

        var hex = text[(dot + 1)..];
        if (hex.Length != 32)
        {
            return false;
        }

        try
        {
            cursor = new PageCursor(created, Convert.FromHexString(hex));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
