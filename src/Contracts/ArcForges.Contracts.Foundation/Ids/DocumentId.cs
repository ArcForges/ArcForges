// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Identifies a document independently of its path or filename.</summary>
/// <remarks>
/// <para>A document identity is not a file path. Renaming or moving a document does not change it, which is what lets a reference survive reorganisation (architecture §5.1).</para>
/// </remarks>
[JsonConverter(typeof(DocumentIdJsonConverter))]
public readonly record struct DocumentId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static DocumentId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static DocumentId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out DocumentId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new DocumentId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="DocumentId"/> as a bare canonical GUID string.</summary>
public sealed class DocumentIdJsonConverter : GuidIdJsonConverter<DocumentId>
{
    protected override DocumentId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(DocumentId value) => value.Value;
}
