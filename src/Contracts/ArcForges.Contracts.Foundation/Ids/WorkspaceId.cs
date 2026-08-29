// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>The single-user boundary for data, devices, billing, sync and permissions.</summary>
/// <remarks>
/// <para>V1 has no organisation membership, team workspace or shared seat. A workspace belongs to one user; it is a boundary, not a collaboration unit.</para>
/// </remarks>
[JsonConverter(typeof(WorkspaceIdJsonConverter))]
public readonly record struct WorkspaceId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static WorkspaceId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static WorkspaceId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out WorkspaceId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new WorkspaceId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="WorkspaceId"/> as a bare canonical GUID string.</summary>
public sealed class WorkspaceIdJsonConverter : GuidIdJsonConverter<WorkspaceId>
{
    protected override WorkspaceId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(WorkspaceId value) => value.Value;
}
