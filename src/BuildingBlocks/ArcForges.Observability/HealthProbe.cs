// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using ArcForges.Capabilities;

namespace ArcForges.Observability;

/// <summary>The three independent health probe kinds required by the observability contract.</summary>
public enum HealthProbeKind
{
    Liveness = 0,
    Readiness = 1,
    CapabilityHealth = 2,
}

/// <summary>A probe outcome. Unknown is deliberately distinct from healthy.</summary>
public enum HealthProbeStatus
{
    Unknown = 0,
    Healthy = 1,
    Degraded = 2,
    Unavailable = 3,
}

/// <summary>The observed availability of one declared readiness dependency.</summary>
public enum DependencyReadinessStatus
{
    Unknown = 0,
    Available = 1,
    Unavailable = 2,
}

/// <summary>A caller-supplied current observation for one required dependency.</summary>
public readonly record struct RequiredDependencyObservation(string DependencyId, DependencyReadinessStatus Status);

/// <summary>A caller-supplied observation for one contract-defined capability health dimension.</summary>
public readonly record struct HealthDimensionObservation(HealthDimension Dimension, HealthProbeStatus Status);

/// <summary>An immutable, typed probe result suitable for consuming capability/status decisions.</summary>
public sealed class HealthProbeResult
{
    internal HealthProbeResult(
        HealthProbeKind kind,
        HealthProbeStatus status,
        IDictionary<HealthDimension, HealthProbeStatus>? dimensionStatuses = null,
        IEnumerable<string>? notReadyDependencies = null)
    {
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        if (!Enum.IsDefined(status)) throw new ArgumentOutOfRangeException(nameof(status));

        Kind = kind;
        Status = status;
        DimensionStatuses = new ReadOnlyDictionary<HealthDimension, HealthProbeStatus>(
            dimensionStatuses is null
                ? new Dictionary<HealthDimension, HealthProbeStatus>()
                : new Dictionary<HealthDimension, HealthProbeStatus>(dimensionStatuses));
        NotReadyDependencies = Array.AsReadOnly((notReadyDependencies ?? [])
            .OrderBy(dependency => dependency, StringComparer.Ordinal)
            .ToArray());
    }

    public HealthProbeKind Kind { get; }
    public HealthProbeStatus Status { get; }
    public IReadOnlyDictionary<HealthDimension, HealthProbeStatus> DimensionStatuses { get; }
    public IReadOnlyList<string> NotReadyDependencies { get; }
}

/// <summary>
/// Pure probe projections over observations supplied by the owning host. This class does not
/// discover dependencies or invent health facts; missing observations remain explicitly not ready
/// or unknown.
/// </summary>
public static class HealthProbe
{
    private static readonly HealthDimension[] CapabilityDimensions = Enum.GetValues<HealthDimension>();

    /// <summary>Reports liveness only; executing this check makes no readiness or capability claim.</summary>
    public static HealthProbeResult CheckLiveness() => new(HealthProbeKind.Liveness, HealthProbeStatus.Healthy);

    /// <summary>
    /// Evaluates each declared dependency against this observation set. Every missing, unknown or
    /// unavailable required dependency fails readiness closed. Extra and duplicate observations are rejected.
    /// </summary>
    public static HealthProbeResult CheckReadiness(
        IEnumerable<string> requiredDependencyIds,
        IEnumerable<RequiredDependencyObservation> observations)
    {
        ArgumentNullException.ThrowIfNull(requiredDependencyIds);
        ArgumentNullException.ThrowIfNull(observations);

        string[] required = requiredDependencyIds.ToArray();
        if (required.Any(dependency => !IsValidDependencyId(dependency)))
        {
            throw new ArgumentException("Required dependency identifiers must be non-empty and already trimmed.", nameof(requiredDependencyIds));
        }

        var requiredSet = new HashSet<string>(required, StringComparer.Ordinal);
        if (requiredSet.Count != required.Length)
        {
            throw new ArgumentException("Required dependency identifiers must be unique.", nameof(requiredDependencyIds));
        }

        var observed = new Dictionary<string, DependencyReadinessStatus>(StringComparer.Ordinal);
        foreach (RequiredDependencyObservation observation in observations)
        {
            if (!IsValidDependencyId(observation.DependencyId))
            {
                throw new ArgumentException("Dependency observations require a non-empty, already-trimmed identifier.", nameof(observations));
            }

            if (!Enum.IsDefined(observation.Status))
            {
                throw new ArgumentOutOfRangeException(nameof(observations), "A dependency observation has an unknown status value.");
            }

            if (!requiredSet.Contains(observation.DependencyId))
            {
                throw new ArgumentException("Observations must correspond only to declared required dependencies.", nameof(observations));
            }

            if (!observed.TryAdd(observation.DependencyId, observation.Status))
            {
                throw new ArgumentException("A dependency may be observed only once per readiness check.", nameof(observations));
            }
        }

        string[] notReady = required
            .OrderBy(dependency => dependency, StringComparer.Ordinal)
            .Where(dependency => !observed.TryGetValue(dependency, out DependencyReadinessStatus status)
                || status != DependencyReadinessStatus.Available)
            .ToArray();
        HealthProbeStatus overall = notReady.Length == 0 ? HealthProbeStatus.Healthy : HealthProbeStatus.Unavailable;
        return new HealthProbeResult(HealthProbeKind.Readiness, overall, notReadyDependencies: notReady);
    }

    /// <summary>
    /// Projects observations across the five contract-defined dimensions. Omitted dimensions are
    /// retained as Unknown, never inferred healthy; duplicate or undefined values are rejected.
    /// </summary>
    public static HealthProbeResult EvaluateCapabilityHealth(IEnumerable<HealthDimensionObservation> observations)
    {
        ArgumentNullException.ThrowIfNull(observations);
        var observed = new Dictionary<HealthDimension, HealthProbeStatus>();
        foreach (HealthDimensionObservation observation in observations)
        {
            if (!Enum.IsDefined(observation.Dimension))
            {
                throw new ArgumentOutOfRangeException(nameof(observations), "A health observation uses an unknown dimension.");
            }

            if (!Enum.IsDefined(observation.Status))
            {
                throw new ArgumentOutOfRangeException(nameof(observations), "A health observation uses an unknown status.");
            }

            if (!observed.TryAdd(observation.Dimension, observation.Status))
            {
                throw new ArgumentException("Each capability health dimension must be observed at most once.", nameof(observations));
            }
        }

        var dimensionStatuses = new Dictionary<HealthDimension, HealthProbeStatus>();
        foreach (HealthDimension dimension in CapabilityDimensions)
        {
            dimensionStatuses.Add(dimension, observed.TryGetValue(dimension, out HealthProbeStatus status)
                ? status
                : HealthProbeStatus.Unknown);
        }

        HealthProbeStatus overall = dimensionStatuses.ContainsValue(HealthProbeStatus.Unavailable)
            ? HealthProbeStatus.Unavailable
            : dimensionStatuses.ContainsValue(HealthProbeStatus.Unknown)
                ? HealthProbeStatus.Unknown
                : dimensionStatuses.ContainsValue(HealthProbeStatus.Degraded)
                    ? HealthProbeStatus.Degraded
                    : HealthProbeStatus.Healthy;

        return new HealthProbeResult(HealthProbeKind.CapabilityHealth, overall, dimensionStatuses);
    }

    private static bool IsValidDependencyId(string? value) =>
        !string.IsNullOrWhiteSpace(value) && string.Equals(value, value.Trim(), StringComparison.Ordinal);
}
