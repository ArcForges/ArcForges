// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Foundation;

/// <summary>A committed revision of one owner object; zero is only a new-root precondition.</summary>
public readonly record struct Revision
{
    public Revision(Guid objectId, CloudRevision value)
    {
        if (objectId == Guid.Empty)
        {
            throw new ArgumentException("An owner object identity is required.", nameof(objectId));
        }

        _ = value.ToWire();
        ObjectId = objectId;
        Value = value;
    }

    public Guid ObjectId { get; }
    public CloudRevision Value { get; }

    public static Revision FromWire(Guid objectId, ArcForges.Contracts.Foundation.V1.Revision value) => new(objectId, CloudRevision.FromWire(value));

    public ArcForges.Contracts.Foundation.V1.Revision ToWire() => Value.ToWire();

    public Revision Next() => new(ObjectId, new CloudRevision(checked(Value.Value + 1)));

    /// <summary>Optimistic precondition comparison never compares unrelated objects.</summary>
    public bool MatchesExpected(Revision expected)
    {
        EnsureSameObject(expected);
        return Value == expected.Value;
    }

    public int CompareTo(Revision other)
    {
        EnsureSameObject(other);
        return Value.Value.CompareTo(other.Value.Value);
    }

    private void EnsureSameObject(Revision other)
    {
        if (ObjectId == Guid.Empty || ObjectId != other.ObjectId)
        {
            throw new ArgumentException("Revision ordering requires the same owner object.", nameof(other));
        }
    }
}
