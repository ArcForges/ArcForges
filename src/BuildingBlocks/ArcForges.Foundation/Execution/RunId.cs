// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Foundation.Execution;

/// <summary>A distinct nonempty RunId backed by the canonical Contracts UUID boundary.</summary>
public readonly record struct RunId
{
    public RunId(Guid value)
    {
        _ = UuidBoundary.ToWire(value);
        Value = value;
    }

    public Guid Value { get; }
    public static RunId New() => new(Guid.NewGuid());
    public static RunId FromWire(Id value) => new(UuidBoundary.FromWire(value));
    public Id ToWire() => UuidBoundary.ToWire(Value);
}
