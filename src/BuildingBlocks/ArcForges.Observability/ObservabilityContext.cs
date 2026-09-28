// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;

namespace ArcForges.Observability;

/// <summary>
/// Identity and optional operational dimensions carried with every signal. Optional dimensions are
/// omitted when absent; this type never invents placeholder values.
/// </summary>
public sealed record ObservabilityContext
{
    public ObservabilityContext(string applicationId, InstanceId instanceId, string buildId, string environment)
    {
        ApplicationId = RequireToken(applicationId, nameof(applicationId));
        if (instanceId.Value == Guid.Empty)
        {
            throw new ArgumentException("A non-empty instance identity is required.", nameof(instanceId));
        }

        InstanceId = instanceId;
        BuildId = RequireToken(buildId, nameof(buildId));
        Environment = RequireToken(environment, nameof(environment));
    }

    public string ApplicationId { get; }
    public InstanceId InstanceId { get; }
    public string BuildId { get; }
    public string Environment { get; }

    /// <summary>SHA-256 reference only; human-readable actor identity is not a signal dimension.</summary>
    public string? ActorReference { get; init; }
    public WorkspaceId? Workspace { get; init; }
    public string? Transport { get; init; }
    public string? Service { get; init; }
    public string? Interface { get; init; }
    public string? Method { get; init; }
    public string? Capability { get; init; }
    /// <summary>Must be a SHA-256 reference; raw resource identifiers are never accepted by this API.</summary>
    public string? RedactedResourceReference { get; init; }
    public CommandId? Command { get; init; }
    public TaskId? Task { get; init; }
    public RunId? Run { get; init; }
    public AttemptId? Attempt { get; init; }
    public CorrelationId? Correlation { get; init; }
    public Guid? CausationId { get; init; }
    public ulong? ExpectedRevision { get; init; }
    public ulong? ResultRevision { get; init; }
    public TimeSpan? Duration { get; init; }
    public TimeSpan? QueueTime { get; init; }
    public string? ResultCode { get; init; }
    public string? ReasonCode { get; init; }
    public string? NativeAbiVersion { get; init; }
    public string? NativeAbiBuildId { get; init; }
    public int? ReconnectCount { get; init; }
    public int? SequenceGapCount { get; init; }

    /// <summary>Build identity comes from the app assembly's build-policy stamp, never a guessed default.</summary>
    public static ObservabilityContext FromApplicationAssembly(
        string applicationId,
        InstanceId instanceId,
        string environment,
        Assembly? applicationAssembly = null)
    {
        applicationAssembly ??= Assembly.GetEntryAssembly()
            ?? throw new InvalidOperationException("The application assembly is not available for build identity lookup.");
        var buildId = applicationAssembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .SingleOrDefault(attribute => attribute.Key == "ArcForges.BuildId")?.Value;
        if (string.IsNullOrWhiteSpace(buildId))
        {
            throw new InvalidOperationException("The application assembly is missing its ArcForges.BuildId build-policy stamp.");
        }

        return new ObservabilityContext(applicationId, instanceId, buildId, environment);
    }

    internal Dictionary<string, object?> MaterializeDimensions()
    {
        var values = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["application.id"] = ApplicationId,
            ["instance.id"] = Format(InstanceId.Value),
            ["build.id"] = BuildId,
            ["deployment.environment"] = Environment,
        };

        AddText(values, "actor.ref", ActorReference);
        AddId(values, "workspace.id", Workspace?.Value);
        AddText(values, "transport", Transport);
        AddText(values, "service.name", Service);
        AddText(values, "interface.name", Interface);
        AddText(values, "method.name", Method);
        AddText(values, "capability.name", Capability);
        AddText(values, "resource.ref", RedactedResourceReference);
        AddId(values, "command.id", Command?.Value);
        AddId(values, "task.id", Task?.Value);
        AddId(values, "run.id", Run?.Value);
        AddId(values, "attempt.id", Attempt?.Value);
        AddId(values, "correlation.id", Correlation?.Value);
        AddId(values, "causation.id", CausationId);
        AddNumber(values, "expected.revision", ExpectedRevision);
        AddNumber(values, "result.revision", ResultRevision);
        AddDuration(values, "duration.ms", Duration);
        AddDuration(values, "queue.time.ms", QueueTime);
        AddText(values, "result.code", ResultCode);
        AddText(values, "reason.code", ReasonCode);
        AddText(values, "native.abi.version", NativeAbiVersion);
        AddText(values, "native.abi.build", NativeAbiBuildId);
        AddCount(values, "reconnect.count", ReconnectCount);
        AddCount(values, "sequence.gap.count", SequenceGapCount);
        return values;
    }

    private static string RequireToken(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128 || value.Any(character =>
                !(character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-' or '+' or ':')))
        {
            throw new ArgumentException("A bounded identifier token is required; free-form text is not accepted.", parameterName);
        }

        return value;
    }

    private static string RequireHashReference(string value, string parameterName)
    {
        if (value.Length != 71 || !value.StartsWith("sha256:", StringComparison.Ordinal))
        {
            throw new ArgumentException("A lowercase SHA-256 reference is required; raw identifiers are not accepted.", parameterName);
        }

        foreach (char character in value.AsSpan(7))
        {
            if (character is not (>= '0' and <= '9' or >= 'a' and <= 'f'))
            {
                throw new ArgumentException("A lowercase SHA-256 reference is required; raw identifiers are not accepted.", parameterName);
            }
        }

        return value;
    }

    private static string Format(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("A present identifier cannot be empty.");
        }

        return value.ToString("N", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static void AddId(Dictionary<string, object?> values, string name, Guid? value)
    {
        if (value is not null)
        {
            values.Add(name, Format(value.Value));
        }
    }

    private static void AddText(Dictionary<string, object?> values, string name, string? value)
    {
        if (value is not null)
        {
            values.Add(name, name is "actor.ref" or "resource.ref" ? RequireHashReference(value, name) : RequireToken(value, name));
        }
    }

    private static void AddNumber(Dictionary<string, object?> values, string name, ulong? value)
    {
        if (value is not null)
        {
            values.Add(name, value.Value);
        }
    }

    private static void AddDuration(Dictionary<string, object?> values, string name, TimeSpan? value)
    {
        if (value is not null)
        {
            if (value.Value < TimeSpan.Zero || !double.IsFinite(value.Value.TotalMilliseconds))
            {
                throw new ArgumentOutOfRangeException(name, "Durations must be finite and non-negative.");
            }

            values.Add(name, value.Value.TotalMilliseconds);
        }
    }

    private static void AddCount(Dictionary<string, object?> values, string name, int? value)
    {
        if (value is not null)
        {
            if (value.Value < 0)
            {
                throw new ArgumentOutOfRangeException(name, "Counts must be non-negative.");
            }

            values.Add(name, value.Value);
        }
    }
}
