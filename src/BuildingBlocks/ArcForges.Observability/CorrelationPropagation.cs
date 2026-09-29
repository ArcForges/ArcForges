// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;

namespace ArcForges.Observability;

/// <summary>Finite local operation kinds; this is not a transport-header or wire-protocol vocabulary.</summary>
public enum ObservabilityHopKind { Http, Queue, Worker, Realtime, Provider }

/// <summary>Validated typed correlation plus the current BCL trace parent for an in-process hop.</summary>
public sealed class CorrelationTraceContext
{
    internal CorrelationTraceContext(CorrelationId correlation, ActivityContext activityContext)
    {
        Correlation = correlation;
        ActivityContext = activityContext;
    }

    public CorrelationId Correlation { get; }
    public ActivityContext ActivityContext { get; }
}

/// <summary>Owns the ambient observability context and local activity for one operation.</summary>
public sealed class CorrelationPropagationScope : IDisposable
{
    private readonly Activity? _activity;
    private readonly IDisposable _observabilityScope;
    private int _disposed;

    internal CorrelationPropagationScope(
        CorrelationTraceContext context,
        Activity? activity,
        IDisposable observabilityScope)
    {
        Context = context;
        _activity = activity;
        _observabilityScope = observabilityScope;
    }

    public CorrelationTraceContext Context { get; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            _observabilityScope.Dispose();
        }
        catch
        {
            Interlocked.Exchange(ref _disposed, 0);
            throw;
        }

        _activity?.Dispose();
    }
}

/// <summary>
/// Creates a correlation once at an origin and carries it through typed local hops. BCL activity
/// parentage records direct operation causality; correlation identity remains distinct from trace identity.
/// </summary>
public sealed class CorrelationPropagation
{
    private const string OriginOperationName = "observability.origin";
    private static readonly ActivitySource Activities = new(SignalEmitter.SourceName);
    private readonly TaskTraceIndex _taskTraceIndex;

    public CorrelationPropagation(TaskTraceIndex taskTraceIndex)
    {
        _taskTraceIndex = taskTraceIndex ?? throw new ArgumentNullException(nameof(taskTraceIndex));
    }

    /// <summary>
    /// Starts an origin operation. If client correlation bytes are supplied, the canonical Contracts
    /// UUID boundary validates them; otherwise a trusted typed value on the context is preserved or a
    /// new identity is generated. No string parsing or fallback occurs for malformed wire input.
    /// </summary>
    public CorrelationPropagationScope BeginOrigin(ObservabilityContext context, Id? clientCorrelation = null)
    {
        ArgumentNullException.ThrowIfNull(context);

        CorrelationId? supplied = clientCorrelation is { } wireValue
            ? CorrelationId.FromWire(wireValue)
            : null;
        if (supplied is { } accepted && context.Correlation is { } existing && accepted != existing)
        {
            throw new ArgumentException("The validated client correlation conflicts with the supplied context.", nameof(clientCorrelation));
        }

        CorrelationId correlation = supplied ?? context.Correlation ?? IdentityGeneration.NewCorrelation();
        ObservabilityContext effectiveContext = context with { Correlation = correlation };
        Activity? activity = Activities.StartActivity(OriginOperationName, ActivityKind.Internal, default(ActivityContext));
        return CreateScope(effectiveContext, activity, activity?.Context ?? default);
    }

    /// <summary>Starts a child operation using only the typed local context supplied by its parent.</summary>
    public CorrelationPropagationScope BeginLocalHop(
        CorrelationTraceContext parent,
        ObservabilityContext context,
        ObservabilityHopKind hopKind)
    {
        ArgumentNullException.ThrowIfNull(parent);
        ArgumentNullException.ThrowIfNull(context);
        if (!Enum.IsDefined(hopKind))
        {
            throw new ArgumentOutOfRangeException(nameof(hopKind));
        }

        if (parent.Correlation.Value == Guid.Empty)
        {
            throw new ArgumentException("A non-empty parent correlation is required.", nameof(parent));
        }

        if (context.Correlation is { } supplied && supplied != parent.Correlation)
        {
            throw new ArgumentException("A local hop cannot replace its parent's correlation.", nameof(context));
        }

        ObservabilityContext effectiveContext = context with { Correlation = parent.Correlation };
        Activity? activity = Activities.StartActivity(ActivityName(hopKind), ActivityKind.Internal, parent.ActivityContext);
        ActivityContext current = activity?.Context ?? parent.ActivityContext;
        return CreateScope(effectiveContext, activity, current);
    }

    private CorrelationPropagationScope CreateScope(
        ObservabilityContext context,
        Activity? activity,
        ActivityContext activityContext)
    {
        IDisposable? scope = null;
        try
        {
            if (activity is not null)
            {
                activity.SetTag("correlation.id", context.Correlation!.Value.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture));
                if (context.CausationId is { } causationId)
                {
                    activity.SetTag("causation.id", causationId.ToString("N", System.Globalization.CultureInfo.InvariantCulture));
                }
            }

            scope = ObservabilityScope.Push(context);
            if (activityContext.TraceId != default && !_taskTraceIndex.TryRecord(context.Task, context.Run, activityContext.TraceId))
            {
                throw new InvalidOperationException("A task or run identity is already bound to another trace.");
            }

            var propagated = new CorrelationTraceContext(context.Correlation!.Value, activityContext);
            return new CorrelationPropagationScope(propagated, activity, scope);
        }
        catch
        {
            scope?.Dispose();
            activity?.Dispose();
            throw;
        }
    }

    private static string ActivityName(ObservabilityHopKind hopKind) => hopKind switch
    {
        ObservabilityHopKind.Http => "observability.http",
        ObservabilityHopKind.Queue => "observability.queue",
        ObservabilityHopKind.Worker => "observability.worker",
        ObservabilityHopKind.Realtime => "observability.realtime",
        ObservabilityHopKind.Provider => "observability.provider",
        _ => throw new ArgumentOutOfRangeException(nameof(hopKind)),
    };
}
