// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;

namespace ArcForges.Observability.Desktop;

/// <summary>
/// One entry of the local diagnostic log, as the local diagnostic view shows it. It holds only a reviewed event name,
/// a level and the reviewed telemetry fields (plus the support reference of a report event), because the store keeps
/// nothing else: never message text, paths, content or secrets.
/// </summary>
public sealed class LocalDiagnosticEntry
{
    internal LocalDiagnosticEntry(DateTimeOffset occurredAt, string name, SignalLevel level, DiagnosticTier tier,
        IDictionary<string, object?> fields)
    {
        OccurredAt = occurredAt;
        Name = name;
        Level = level;
        Tier = tier;
        Fields = new ReadOnlyDictionary<string, object?>(new Dictionary<string, object?>(fields, StringComparer.Ordinal));
    }

    public DateTimeOffset OccurredAt { get; }

    /// <summary>A dotted identifier of ASCII words, or <c>redacted</c>.</summary>
    public string Name { get; }

    public SignalLevel Level { get; }

    /// <summary>The tier that admitted the entry: verbose for detail below Information, a report event for a report, otherwise minimal.</summary>
    public DiagnosticTier Tier { get; }

    public IReadOnlyDictionary<string, object?> Fields { get; }
}
