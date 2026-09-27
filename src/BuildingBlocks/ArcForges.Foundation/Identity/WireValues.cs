// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Foundation;

/// <summary>Separates unknown response values from strictly admitted mutation values.</summary>
public readonly record struct EnumProjection<T> where T : struct, Enum
{
    public EnumProjection(T value)
    {
        Value = value;
    }

    public T Value { get; }
    public bool IsKnown => Enum.IsDefined(Value) && Convert.ToInt64(Value, System.Globalization.CultureInfo.InvariantCulture) != 0;

    public T RequireKnown()
    {
        if (!IsKnown)
        {
            throw new InvalidOperationException("An unknown or unspecified value cannot authorize a mutation.");
        }

        return Value;
    }
}

/// <summary>Exact time conversion to the published protobuf model; absent components refuse.</summary>
public static class WireValues
{
    public static Instant ReadInstant(ArcForges.Contracts.Foundation.V1.Instant value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.HasUnixSeconds || !value.HasNanos)
        {
            throw new ArgumentException("Both instant components must be present.", nameof(value));
        }

        return new Instant(value.UnixSeconds, value.Nanos);
    }

    public static ArcForges.Contracts.Foundation.V1.Instant ToWire(Instant value) => new()
    {
        UnixSeconds = value.UnixSeconds,
        Nanos = value.Nanoseconds,
    };

    /// <summary>Unknown producer error classifications stay unknown and cannot permit retries.</summary>
    public static bool IsKnownEffect(EffectCertainty value) => new EnumProjection<EffectCertainty>(value).IsKnown;
}
