// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Identifies a Cloud Agent task for its whole life.</summary>
/// <remarks>
/// <para>The identity is permanently stable: it survives every retry, re-target and recovery. Local import/export/index/capture/render work is a product activity and never allocates one (README §2.2).</para>
/// </remarks>
[JsonConverter(typeof(TaskIdJsonConverter))]
public readonly record struct TaskId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static TaskId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static TaskId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out TaskId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new TaskId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="TaskId"/> as a bare canonical GUID string.</summary>
public sealed class TaskIdJsonConverter : GuidIdJsonConverter<TaskId>
{
    protected override TaskId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(TaskId value) => value.Value;
}
