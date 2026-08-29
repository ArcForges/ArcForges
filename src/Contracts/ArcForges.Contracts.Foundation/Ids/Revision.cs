// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// The optimistic-concurrency version of one authoritative object.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="None"/> (zero) means the object does not exist yet or has no committed version. The first
/// persisted version is 1 and the authoritative owner increments monotonically from there (architecture §5.1).
/// </para>
/// <para>
/// A revision is not a <see cref="Sequence"/>. A revision versions one object; a sequence orders a stream.
/// </para>
/// <para>
/// Every write command carries the revision it expects. A mismatch is a conflict the caller must resolve; it
/// is never resolved by silently taking the later write.
/// </para>
/// </remarks>
[JsonConverter(typeof(RevisionJsonConverter))]
public readonly record struct Revision(long Value) : IComparable<Revision>
{
    /// <summary>No committed version yet.</summary>
    public static readonly Revision None = new(0);

    /// <summary>The first persisted version.</summary>
    public static readonly Revision First = new(1);

    /// <summary>True when the object has at least one committed version.</summary>
    public bool Exists => Value > 0;

    /// <summary>The next revision in sequence.</summary>
    /// <exception cref="OverflowException">The revision is at <see cref="long.MaxValue"/>.</exception>
    public Revision Next() => Value == long.MaxValue
        ? throw new OverflowException("Revision cannot advance past long.MaxValue.")
        : new Revision(Value + 1);

    public int CompareTo(Revision other) => Value.CompareTo(other.Value);

    public static bool operator <(Revision left, Revision right) => left.CompareTo(right) < 0;

    public static bool operator <=(Revision left, Revision right) => left.CompareTo(right) <= 0;

    public static bool operator >(Revision left, Revision right) => left.CompareTo(right) > 0;

    public static bool operator >=(Revision left, Revision right) => left.CompareTo(right) >= 0;

    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}
