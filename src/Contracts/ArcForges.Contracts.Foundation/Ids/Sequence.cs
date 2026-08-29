// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// The position of an entry in an event or change stream.
/// </summary>
/// <remarks>
/// <para>
/// Business events start at 1. <see cref="None"/> (zero) is a cursor or watermark meaning nothing has been
/// applied yet, not an event. Formats that number records inside a file from zero — an ArcScope capture, for
/// instance — are registered separately and keep their own convention (architecture §5.1).
/// </para>
/// <para>
/// A sequence is not a <see cref="Revision"/>. A sequence orders a stream; a revision versions one object.
/// After a disconnect the client resumes from the last confirmed sequence.
/// </para>
/// </remarks>
[JsonConverter(typeof(SequenceJsonConverter))]
public readonly record struct Sequence(long Value) : IComparable<Sequence>
{
    /// <summary>Nothing applied yet.</summary>
    public static readonly Sequence None = new(0);

    /// <summary>The first business event.</summary>
    public static readonly Sequence First = new(1);

    /// <summary>True when at least one entry has been applied.</summary>
    public bool HasValue => Value > 0;

    /// <summary>The next position in the stream.</summary>
    /// <exception cref="OverflowException">The sequence is at <see cref="long.MaxValue"/>.</exception>
    public Sequence Next() => Value == long.MaxValue
        ? throw new OverflowException("Sequence cannot advance past long.MaxValue.")
        : new Sequence(Value + 1);

    public int CompareTo(Sequence other) => Value.CompareTo(other.Value);

    public static bool operator <(Sequence left, Sequence right) => left.CompareTo(right) < 0;

    public static bool operator <=(Sequence left, Sequence right) => left.CompareTo(right) <= 0;

    public static bool operator >(Sequence left, Sequence right) => left.CompareTo(right) > 0;

    public static bool operator >=(Sequence left, Sequence right) => left.CompareTo(right) >= 0;

    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}
