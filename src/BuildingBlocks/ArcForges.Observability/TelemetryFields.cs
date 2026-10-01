// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Collections.ObjectModel;
using ArcForges.Foundation.Errors;

namespace ArcForges.Observability;

/// <summary>How the value of one reviewed telemetry field is validated before it may leave the process.</summary>
internal enum TelemetryFieldKind
{
    ApplicationId,
    Guid32,
    BuildId,
    Enum,
    Sha256Reference,
    UnsignedInteger,
    DurationMilliseconds,
    ReasonCode,
    NativeAbiVersion,
    Count,
    RouteTemplate,
    HttpMethod,
    HttpStatusCode,
}

internal sealed record TelemetryFieldRule(string Name, TelemetryFieldKind Kind, IReadOnlySet<string>? Members = null);

/// <summary>
/// The closed, reviewed export vocabulary (observability architecture section 2.2). Every field name and its value
/// class is also recorded in <c>eng/policy/telemetry-policy.json</c>; a test keeps the two identical. A field that is
/// not listed here is never exported by <see cref="RedactionProcessor"/>.
/// </summary>
internal static class TelemetryFields
{
    internal const string RouteParameterPrefix = "http.route.param.";

    private static readonly SearchValues<char> LowerHex = SearchValues.Create("0123456789abcdef");
    private static readonly SearchValues<char> Digits = SearchValues.Create("0123456789");
    private static readonly ReadOnlySet<string> HttpMethods = Members("GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "_OTHER");

    internal static IReadOnlyList<TelemetryFieldRule> Rules { get; } = Array.AsReadOnly<TelemetryFieldRule>(
    [
        new("application.id", TelemetryFieldKind.ApplicationId, Members("arcscope", "companion")),
        new("instance.id", TelemetryFieldKind.Guid32),
        new("build.id", TelemetryFieldKind.BuildId),
        new("deployment.environment", TelemetryFieldKind.Enum, Names<SignalEnvironment>()),
        new("actor.ref", TelemetryFieldKind.Sha256Reference),
        new("workspace.id", TelemetryFieldKind.Guid32),
        new("transport", TelemetryFieldKind.Enum, Names<SignalTransport>()),
        new("service.name", TelemetryFieldKind.Enum, Names<SignalService>()),
        new("interface.name", TelemetryFieldKind.Enum, Names<SignalInterface>()),
        new("method.name", TelemetryFieldKind.Enum, Names<SignalMethod>()),
        new("capability.name", TelemetryFieldKind.Enum, Names<SignalCapability>()),
        new("resource.ref", TelemetryFieldKind.Sha256Reference),
        new("command.id", TelemetryFieldKind.Guid32),
        new("task.id", TelemetryFieldKind.Guid32),
        new("run.id", TelemetryFieldKind.Guid32),
        new("attempt.id", TelemetryFieldKind.Guid32),
        new("correlation.id", TelemetryFieldKind.Guid32),
        new("causation.id", TelemetryFieldKind.Guid32),
        new("expected.revision", TelemetryFieldKind.UnsignedInteger),
        new("result.revision", TelemetryFieldKind.UnsignedInteger),
        new("duration.ms", TelemetryFieldKind.DurationMilliseconds),
        new("queue.time.ms", TelemetryFieldKind.DurationMilliseconds),
        new("result.code", TelemetryFieldKind.Enum, Names<SignalResultCode>()),
        new("reason.code", TelemetryFieldKind.ReasonCode),
        new("native.abi.version", TelemetryFieldKind.NativeAbiVersion),
        new("native.abi.build", TelemetryFieldKind.BuildId),
        new("reconnect.count", TelemetryFieldKind.Count),
        new("sequence.gap.count", TelemetryFieldKind.Count),
        new("http.route", TelemetryFieldKind.RouteTemplate),
        new("http.request.method", TelemetryFieldKind.HttpMethod, HttpMethods),
        new("http.response.status_code", TelemetryFieldKind.HttpStatusCode),
    ]);

    private static readonly Dictionary<string, TelemetryFieldRule> ByName = Rules.ToDictionary(rule => rule.Name, StringComparer.Ordinal);

    private static readonly TelemetryFieldRule RouteParameter = new(RouteParameterPrefix + "<slot>", TelemetryFieldKind.Guid32);

    internal static bool TryGetRule(string name, out TelemetryFieldRule rule)
    {
        if (ByName.TryGetValue(name, out TelemetryFieldRule? found))
        {
            rule = found;
            return true;
        }

        if (name.StartsWith(RouteParameterPrefix, StringComparison.Ordinal)
            && RouteTemplateSet.IsRegisteredSlotName(name.AsSpan(RouteParameterPrefix.Length)))
        {
            rule = RouteParameter;
            return true;
        }

        rule = null!;
        return false;
    }

    internal static string KindName(TelemetryFieldKind kind) => kind switch
    {
        TelemetryFieldKind.ApplicationId => "application-id",
        TelemetryFieldKind.Guid32 => "guid-32",
        TelemetryFieldKind.BuildId => "build-id",
        TelemetryFieldKind.Enum => "enum",
        TelemetryFieldKind.Sha256Reference => "sha256-reference",
        TelemetryFieldKind.UnsignedInteger => "unsigned-integer",
        TelemetryFieldKind.DurationMilliseconds => "duration-ms",
        TelemetryFieldKind.ReasonCode => "reason-code",
        TelemetryFieldKind.NativeAbiVersion => "native-abi-version",
        TelemetryFieldKind.Count => "count",
        TelemetryFieldKind.RouteTemplate => "route-template",
        TelemetryFieldKind.HttpMethod => "http-method",
        TelemetryFieldKind.HttpStatusCode => "http-status-code",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>True only when the value has exactly the reviewed shape of its field; nothing else is exportable.</summary>
    internal static bool IsValid(TelemetryFieldRule rule, object? value)
    {
        switch (rule.Kind)
        {
            case TelemetryFieldKind.Guid32:
                return value is string guid && IsGuid32(guid);
            case TelemetryFieldKind.BuildId:
                return value is string build && ObservabilityContext.IsValidBuildId(build);
            case TelemetryFieldKind.ApplicationId:
            case TelemetryFieldKind.Enum:
            case TelemetryFieldKind.HttpMethod:
                return value is string member && rule.Members!.Contains(member);
            case TelemetryFieldKind.Sha256Reference:
                return value is string reference && ObservabilityContext.IsSha256Reference(reference);
            case TelemetryFieldKind.UnsignedInteger:
                return value is ulong || (TryInteger(value, out long unsigned) && unsigned >= 0);
            case TelemetryFieldKind.DurationMilliseconds:
                return value is double duration && double.IsFinite(duration) && duration >= 0;
            case TelemetryFieldKind.ReasonCode:
                return value is string reason && ReasonCodes.TryGet(reason, out _);
            case TelemetryFieldKind.NativeAbiVersion:
                return value is string version && IsNativeAbiVersion(version);
            case TelemetryFieldKind.Count:
                return TryInteger(value, out long count) && count >= 0 && count <= int.MaxValue;
            case TelemetryFieldKind.RouteTemplate:
                return value is string template && RouteTemplateSet.IsValidRecordedTemplate(template);
            case TelemetryFieldKind.HttpStatusCode:
                return TryInteger(value, out long status) && status is >= 100 and <= 599;
            default:
                return false;
        }
    }

    internal static bool IsGuid32(string value)
    {
        if (value.Length != 32 || value.AsSpan().IndexOfAnyExcept(LowerHex) >= 0)
        {
            return false;
        }

        return value.AsSpan().IndexOfAnyExcept('0') >= 0;
    }

    private static bool IsNativeAbiVersion(string value)
    {
        int dot = value.IndexOf('.', StringComparison.Ordinal);
        return dot > 0 && dot == value.LastIndexOf('.') && IsDecimal(value.AsSpan(0, dot)) && IsDecimal(value.AsSpan(dot + 1));
    }

    private static bool IsDecimal(ReadOnlySpan<char> value) =>
        value.Length is > 0 and <= 10 && value.IndexOfAnyExcept(Digits) < 0;

    private static bool TryInteger(object? value, out long result)
    {
        switch (value)
        {
            case sbyte v:
                result = v;
                return true;
            case byte v:
                result = v;
                return true;
            case short v:
                result = v;
                return true;
            case ushort v:
                result = v;
                return true;
            case int v:
                result = v;
                return true;
            case uint v:
                result = v;
                return true;
            case long v:
                result = v;
                return true;
            default:
                result = 0;
                return false;
        }
    }

    private static ReadOnlySet<string> Names<TEnum>()
        where TEnum : struct, Enum => Members(Enum.GetNames<TEnum>());

    private static ReadOnlySet<string> Members(params string[] values) =>
        new(new HashSet<string>(values, StringComparer.Ordinal));
}
