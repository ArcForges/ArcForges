// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Foundation.Execution;

/// <summary>A distinct nonempty TaskId backed by the canonical Contracts UUID boundary.</summary>
public readonly record struct TaskId
{
    public TaskId(Guid value)
    {
        _ = UuidBoundary.ToWire(value);
        Value = value;
    }

    public Guid Value { get; }
    public static TaskId New() => new(Guid.NewGuid());
    public static TaskId FromWire(Id value) => new(UuidBoundary.FromWire(value));
    public Id ToWire() => UuidBoundary.ToWire(Value);
}
