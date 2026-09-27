// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Foundation.Execution;

/// <summary>A distinct nonempty StepId backed by the canonical Contracts UUID boundary.</summary>
public readonly record struct StepId
{
    public StepId(Guid value)
    {
        _ = UuidBoundary.ToWire(value);
        Value = value;
    }

    public Guid Value { get; }
    public static StepId New() => new(Guid.NewGuid());
    public static StepId FromWire(Id value) => new(UuidBoundary.FromWire(value));
    public Id ToWire() => UuidBoundary.ToWire(Value);
}
