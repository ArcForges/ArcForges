// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;

namespace ArcForges.Observability;

public enum SignalLevel
{
    Trace = 0,
    Debug = 1,
    Information = 2,
    Warning = 3,
    Error = 4,
}

/// <summary>A typed structured event. It contains properties, never a preformatted log sentence.</summary>
public sealed class StructuredSignal
{
    internal StructuredSignal(string name, SignalLevel level, DateTimeOffset occurredAt, IDictionary<string, object?> properties, long? collectionEpoch = null)
    {
        Name = name;
        Level = level;
        OccurredAt = occurredAt;
        Properties = new ReadOnlyDictionary<string, object?>(new Dictionary<string, object?>(properties, StringComparer.Ordinal));
        CollectionEpoch = collectionEpoch;
    }

    public string Name { get; }
    public SignalLevel Level { get; }
    public DateTimeOffset OccurredAt { get; }
    public IReadOnlyDictionary<string, object?> Properties { get; }
    /// <summary>Collection provenance for a revocable host; never exported as an attribute or treated as authority.</summary>
    public long? CollectionEpoch { get; }
}

/// <summary>
/// Host-owned bridge to its structured logging provider. <see cref="Write"/> may be called concurrently from arbitrary
/// threads, so an implementation must be thread-safe.
/// </summary>
public interface IStructuredEventSink
{
    void Write(StructuredSignal signal);
}

/// <summary>Optional collection-time fence supplied by the actual revocable sink. Negative means collection was not granted.</summary>
public interface ITelemetryEpochSource
{
    long CollectionEpoch { get; }
}
