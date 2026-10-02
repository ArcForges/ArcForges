// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using System.Diagnostics;

namespace ArcForges.Observability;

/// <summary>
/// Metric cardinality is bounded by construction (observability architecture SG-02, CC-01, TV-03). The only label a
/// metric point may carry is the reviewed, closed <c>service.name</c> dimension, so a metric has at most
/// <see cref="MaximumSeriesPerInstrument"/> series per scope. Every identifier that can grow without bound (workspace,
/// actor, task, run, resource, correlation, route parameter) lives on spans and structured events, never on a metric.
/// <see cref="CreateTags"/> is the typed way to build labels, which cannot express anything else, and
/// <see cref="ScrubLabels"/> is the second line of defence an exporter applies to metric points from any meter,
/// including foreign instrumentation.
/// </summary>
public static class MetricLabelPolicy
{
    /// <summary>The label names a metric point may carry.</summary>
    public static IReadOnlyList<string> PointLabelNames { get; } = Array.AsReadOnly(["service.name"]);

    /// <summary>
    /// The most distinct label sets one instrument can produce: one for each <see cref="SignalService"/> value, plus the
    /// unlabelled point used when the service dimension is absent.
    /// </summary>
    public static int MaximumSeriesPerInstrument { get; } = Enum.GetValues<SignalService>().Length + 1;

    /// <summary>Labels for one metric point. The optional service dimension is the only label that can be expressed.</summary>
    public static TagList CreateTags(SignalService? service)
    {
        TagList tags = default;
        if (service is { } known)
        {
            if (!Enum.IsDefined(known))
            {
                throw new ArgumentOutOfRangeException(nameof(service), "Only a registered, finite service value is a metric label.");
            }

            tags.Add("service.name", known.ToString());
        }

        return tags;
    }

    /// <summary>
    /// Returns only the labels of a foreign metric point that are in the reviewed allowlist and carry a reviewed value.
    /// A label that is not (an identifier, a route parameter, a path, free text) is removed, and so is a reviewed label
    /// name carrying a value outside its closed vocabulary. A name that appears more than once keeps its last value.
    /// </summary>
    public static IReadOnlyDictionary<string, object?> ScrubLabels(IEnumerable<KeyValuePair<string, object?>> labels)
    {
        ArgumentNullException.ThrowIfNull(labels);
        var kept = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, object?> label in labels)
        {
            if (label.Key is { Length: > 0 } name
                && PointLabelNames.Contains(name, StringComparer.Ordinal)
                && TelemetryFields.TryGetRule(name, out TelemetryFieldRule? rule)
                && TelemetryFields.IsValid(rule, label.Value))
            {
                kept[name] = label.Value;
            }
        }

        return new ReadOnlyDictionary<string, object?>(kept);
    }

    /// <summary>The attributes that identify the emitting application on an instrument's scope; they are not point labels.</summary>
    internal static IReadOnlyList<string> ScopeAttributeNames { get; } =
        Array.AsReadOnly(["application.id", "instance.id", "build.id", "deployment.environment"]);

    /// <summary>The scope attributes of one application instance, in the order of <see cref="ScopeAttributeNames"/> (SG-05).</summary>
    internal static KeyValuePair<string, object?>[] ScopeTags(string applicationId, string instanceId, string buildId,
        SignalEnvironment environment) =>
    [
        new("application.id", applicationId),
        new("instance.id", instanceId),
        new("build.id", buildId),
        new("deployment.environment", environment.ToString()),
    ];
}
