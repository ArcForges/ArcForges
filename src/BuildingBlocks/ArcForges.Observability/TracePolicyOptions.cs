// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Observability;

/// <summary>A head-sampling ratio for the root spans of one reviewed signal (observability architecture CC-02).</summary>
public readonly record struct SignalSamplingRule(SignalEventName Signal, double Ratio);

/// <summary>A head-sampling ratio for the root spans that carry one registered route template (observability architecture CC-02).</summary>
public readonly record struct RouteSamplingRule(RecordedRoute Route, double Ratio);

/// <summary>
/// The sampling and buffering configuration of a <see cref="TracePolicy"/>. Design fixes the diagnostic buffer (8 MiB by
/// default, 16 MiB at most, 30 seconds per trace) but leaves the head ratio and the slow-span threshold to deployment,
/// so both are required parameters with no built-in default: a host cannot start sampling by accident.
/// </summary>
public sealed class TracePolicyOptions
{
    /// <summary>The diagnostic buffer size used when none is configured: 8 MiB.</summary>
    public const long DefaultBufferBytes = 8L * 1024 * 1024;

    /// <summary>The largest diagnostic buffer a host may configure: 16 MiB.</summary>
    public const long HardBufferLimitBytes = 16L * 1024 * 1024;

    /// <summary>The smallest diagnostic buffer a host may configure; below this one span cannot be held.</summary>
    public const long MinimumBufferBytes = 1024;

    private long _bufferBytes = DefaultBufferBytes;
    private IReadOnlyList<SignalSamplingRule> _signalRules = [];
    private IReadOnlyList<RouteSamplingRule> _routeRules = [];

    /// <param name="defaultTraceRatio">The fraction of root spans selected for export at the head, from 0 (none) to 1 (all).</param>
    /// <param name="slowSpanThreshold">A span that lasts at least this long promotes its trace out of the diagnostic buffer.</param>
    public TracePolicyOptions(double defaultTraceRatio, TimeSpan slowSpanThreshold)
    {
        DefaultTraceRatio = RequireRatio(defaultTraceRatio, nameof(defaultTraceRatio));
        if (slowSpanThreshold <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(slowSpanThreshold), "A slow-span threshold must be positive.");
        }

        SlowSpanThreshold = slowSpanThreshold;
    }

    public double DefaultTraceRatio { get; }

    public TimeSpan SlowSpanThreshold { get; }

    /// <summary>The diagnostic buffer budget in accounted bytes, from <see cref="MinimumBufferBytes"/> to <see cref="HardBufferLimitBytes"/>.</summary>
    public long BufferBytes
    {
        get => _bufferBytes;
        init
        {
            if (value is < MinimumBufferBytes or > HardBufferLimitBytes)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "The diagnostic buffer must be between its minimum and the 16 MiB hard limit.");
            }

            _bufferBytes = value;
        }
    }

    /// <summary>Per-signal ratios, used for a root span of that signal when no route rule applies. One rule per signal.</summary>
    public IReadOnlyList<SignalSamplingRule> SignalRules
    {
        get => _signalRules;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            var seen = new HashSet<SignalEventName>();
            foreach (SignalSamplingRule rule in value)
            {
                if (!Enum.IsDefined(rule.Signal))
                {
                    throw new ArgumentOutOfRangeException(nameof(value), "A sampling rule names a reviewed signal.");
                }

                RequireRatio(rule.Ratio, nameof(value));
                if (!seen.Add(rule.Signal))
                {
                    throw new ArgumentException("A signal has at most one sampling rule.", nameof(value));
                }
            }

            _signalRules = Array.AsReadOnly(value.ToArray());
        }
    }

    /// <summary>Per-route ratios, used for a root span carrying that registered template at creation. One rule per template; a route rule outranks a signal rule.</summary>
    public IReadOnlyList<RouteSamplingRule> RouteRules
    {
        get => _routeRules;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (RouteSamplingRule rule in value)
            {
                if (rule.Route is not { IsMatched: true })
                {
                    throw new ArgumentException("A route rule needs a route recorded through a RouteTemplateSet.", nameof(value));
                }

                RequireRatio(rule.Ratio, nameof(value));
                if (!seen.Add(rule.Route.Template))
                {
                    throw new ArgumentException("A route template has at most one sampling rule.", nameof(value));
                }
            }

            _routeRules = Array.AsReadOnly(value.ToArray());
        }
    }

    private static double RequireRatio(double ratio, string parameterName)
    {
        if (!double.IsFinite(ratio) || ratio is < 0d or > 1d)
        {
            throw new ArgumentOutOfRangeException(parameterName, "A sampling ratio is a finite number from 0 to 1.");
        }

        return ratio;
    }
}
