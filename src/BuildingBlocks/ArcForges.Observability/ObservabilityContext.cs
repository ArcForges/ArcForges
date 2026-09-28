// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;

namespace ArcForges.Observability;

/// <summary>
/// Identity and optional operational dimensions carried with every signal. Optional dimensions are
/// omitted when absent; this type never invents placeholder values.
/// </summary>
public sealed record ObservabilityContext
{
    public ObservabilityContext(SignalApplicationDimension application, InstanceId instanceId, SignalEnvironment environment,
        Assembly? applicationAssembly = null)
    {
        if (!Enum.IsDefined(application)) throw new ArgumentOutOfRangeException(nameof(application));
        if (!Enum.IsDefined(environment)) throw new ArgumentOutOfRangeException(nameof(environment));
        if (instanceId.Value == Guid.Empty)
        {
            throw new ArgumentException("A non-empty instance identity is required.", nameof(instanceId));
        }

        Application = application;
        InstanceId = instanceId;
        BuildId = ReadBuildId(applicationAssembly ?? Assembly.GetEntryAssembly()
            ?? throw new InvalidOperationException("The application assembly is not available for build identity lookup."));
        Environment = environment;
    }

    public SignalApplicationDimension Application { get; }
    public string ApplicationId => Application switch
    {
        SignalApplicationDimension.ArcScope => "arcscope",
        SignalApplicationDimension.Companion => "companion",
        _ => string.Empty,
    };
    public InstanceId InstanceId { get; }
    public string BuildId { get; }
    public SignalEnvironment Environment { get; }

    /// <summary>SHA-256 reference only; human-readable actor identity is not a signal dimension.</summary>
    public string? ActorReference { get; init; }
    public WorkspaceId? Workspace { get; init; }
    public SignalTransport? Transport { get; init; }
    public SignalService? Service { get; init; }
    public SignalInterface? Interface { get; init; }
    public SignalMethod? Method { get; init; }
    public SignalCapability? Capability { get; init; }
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
    public SignalResultCode? ResultCode { get; init; }
    public ReasonCode? ReasonCode { get; init; }
    public NativeAbiVersion? NativeAbiVersion { get; init; }
    public string? NativeAbiBuildId { get; init; }
    public int? ReconnectCount { get; init; }
    public int? SequenceGapCount { get; init; }

    /// <summary>Build identity comes from the app assembly's build-policy stamp, never a guessed default.</summary>
    public static ObservabilityContext FromApplicationAssembly(
        SignalApplicationDimension application,
        InstanceId instanceId,
        SignalEnvironment environment,
        Assembly? applicationAssembly = null)
    {
        return new ObservabilityContext(application, instanceId, environment, applicationAssembly);
    }

    internal Dictionary<string, object?> MaterializeDimensions()
    {
        if (!Enum.IsDefined(Application)) throw new ArgumentOutOfRangeException(nameof(Application));
        var values = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["application.id"] = ApplicationId,
            ["instance.id"] = Format(InstanceId.Value),
            ["build.id"] = BuildId,
            ["deployment.environment"] = Environment.ToString(),
        };

        AddHashReference(values, "actor.ref", ActorReference);
        AddId(values, "workspace.id", Workspace?.Value);
        AddEnum(values, "transport", Transport);
        AddEnum(values, "service.name", Service);
        AddEnum(values, "interface.name", Interface);
        AddEnum(values, "method.name", Method);
        AddEnum(values, "capability.name", Capability);
        AddHashReference(values, "resource.ref", RedactedResourceReference);
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
        AddEnum(values, "result.code", ResultCode);
        if (ReasonCode is not null) values.Add("reason.code", ReasonCode.Code);
        if (NativeAbiVersion is { } nativeVersion) values.Add("native.abi.version", nativeVersion.ToString());
        AddBuildId(values, "native.abi.build", NativeAbiBuildId);
        AddCount(values, "reconnect.count", ReconnectCount);
        AddCount(values, "sequence.gap.count", SequenceGapCount);
        return values;
    }

    private static string ValidateBuildId(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        bool valid = value == "local.local" || IsLocalCommitBuild(value) || IsCiBuild(value);
        if (!valid)
        {
            throw new ArgumentException("Build identity must match a build-policy local or CI stamp.", nameof(value));
        }

        return value;
    }

    private static string ReadBuildId(Assembly assembly)
    {
        string? value = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .SingleOrDefault(attribute => attribute.Key == "ArcForges.BuildId")?.Value;
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException("The application assembly is missing its ArcForges.BuildId build-policy stamp.");
        }

        return ValidateBuildId(value);
    }

    private static bool IsLocalCommitBuild(string value)
    {
        const string prefix = "local.";
        if (!value.StartsWith(prefix, StringComparison.Ordinal) || value.Length != prefix.Length + 40) return false;
        foreach (char character in value.AsSpan(prefix.Length))
        {
            if (character is not (>= '0' and <= '9' or >= 'a' and <= 'f')) return false;
        }

        return true;
    }

    private static bool IsCiBuild(string value)
    {
        int separator = value.IndexOf('.', StringComparison.Ordinal);
        return separator > 0 && separator == value.LastIndexOf('.')
            && IsPositiveDecimal(value.AsSpan(0, separator)) && IsPositiveDecimal(value.AsSpan(separator + 1));
    }

    private static bool IsPositiveDecimal(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty || value.Length > 20 || value[0] == '0') return false;
        foreach (char character in value)
        {
            if (character is not (>= '0' and <= '9')) return false;
        }

        return true;
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

    private static void AddHashReference(Dictionary<string, object?> values, string name, string? value)
    {
        if (value is not null) values.Add(name, RequireHashReference(value, name));
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

    private static void AddBuildId(Dictionary<string, object?> values, string name, string? value)
    {
        if (value is not null) values.Add(name, ValidateBuildId(value));
    }

    private static void AddEnum<TEnum>(Dictionary<string, object?> values, string name, TEnum? value)
        where TEnum : struct, Enum
    {
        if (value is not { } known) return;
        if (!Enum.IsDefined(known)) throw new ArgumentOutOfRangeException(name, "Only a registered, finite telemetry value is accepted.");
        values.Add(name, known.ToString());
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

/// <summary>
/// Closed telemetry dimension vocabulary. This does not own product identity; composition maps a trusted
/// product identity to one of these reviewed values before installing the observability context.
/// </summary>
public enum SignalApplicationDimension { ArcScope, Companion }

/// <summary>Closed, finite telemetry vocabulary. Unknown values cannot be supplied as arbitrary strings.</summary>
public enum SignalEnvironment { Development, Test, Staging, Production }
public enum SignalTransport { LocalRpc, Http, Queue, Realtime, Worker, Provider }
public enum SignalService { Application, Storage, Security, Capabilities, Cloud, Device, Extensions, Sync }
public enum SignalInterface { ApplicationLifecycle, ResourceStore, SecretBroker, ConnectorHost, HealthProbe }
public enum SignalMethod { Read, Write, Create, Commit, Update, Delete, Execute, Start, Stop, Check, Emit }
public enum SignalCapability { ResourceRead, ResourceWrite, SecretUse, ConnectorInvoke, Egress }
public enum SignalResultCode { Succeeded, Failed, Refused, Cancelled, Unknown }
public enum SignalEventName { ApplicationStarted, StorageCommitted, SecretUsed, OperationCompleted, OperationFailed, HealthChanged }

/// <summary>Native ABI version as two numeric components, never a free-form string dimension.</summary>
public readonly record struct NativeAbiVersion(uint Major, uint Minor)
{
    public override string ToString() => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{Major}.{Minor}");
}
