// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;

namespace ArcForges.Observability.Desktop;

/// <summary>
/// Actual desktop composition: durable consent and local diagnostics, typed signals, bounded TracePolicy, scrubbed
/// OTLP delivery and bounded metric collection. The product owns this host and awaits its asynchronous shutdown.
/// </summary>
public sealed class DesktopObservabilityHost : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly CancellationTokenSource _collectionStop = new();
    private readonly OtlpMetricCollector _metrics;
    private readonly Task _collection;
    private Task? _shutdown;

    private DesktopObservabilityHost(DesktopDiagnostics diagnostics, TracePolicyOptions traceOptions,
        OtlpExporterOptions exportOptions, ObservabilityContext identity, Func<ActivitySource, bool> sources,
        OtlpHttpExporter exporter, TimeProvider time, string diagnosticsDirectory)
    {
        Diagnostics = diagnostics;
        Exporter = exporter;
        Telemetry = diagnostics.CreateTelemetry(exporter);
        Signals = new SignalEmitter(Telemetry);
        Traces = new TracePolicy(traceOptions, identity, exporter, Telemetry, diagnostics.Consent, time);
        // The immediate notification precedes disk persistence; a rapid revoke/re-grant cannot replay buffered traces.
        diagnostics.Consent.Revoking += Traces.PurgeBuffer;
        _metrics = new OtlpMetricCollector(exporter, diagnostics.Consent, identity, time);
        try { Traces.Attach(sources); }
        catch
        {
            diagnostics.Consent.Revoking -= Traces.PurgeBuffer;
            _metrics.Dispose();
            Signals.Dispose();
            Traces.Dispose();
            _collectionStop.Dispose();
            throw;
        }
        Readiness = new DependencyHealthMonitor([new DiagnosticDirectoryProbe(diagnosticsDirectory)], TimeSpan.FromSeconds(2), time);
        _collection = CollectAsync(exportOptions.MetricCollectionInterval, time);
    }

    public DesktopDiagnostics Diagnostics { get; }
    public OtlpHttpExporter Exporter { get; }
    public ConsentGatedTelemetry Telemetry { get; }
    public SignalEmitter Signals { get; }
    public TracePolicy Traces { get; }
    public DependencyHealthMonitor Readiness { get; }

    /// <summary>Opens the production composition. No collector connection is opened until consented data is available.</summary>
    public static DesktopObservabilityHost Open(DesktopDiagnosticsOptions diagnostics, TracePolicyOptions traces,
        OtlpExporterOptions export, Func<ActivitySource, bool> sources)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);
        ArgumentNullException.ThrowIfNull(traces);
        ArgumentNullException.ThrowIfNull(export);
        ArgumentNullException.ThrowIfNull(sources);
        export.Validate();
        DesktopDiagnostics local = DesktopDiagnostics.Open(diagnostics);
        OtlpHttpExporter? exporter = null;
        try
        {
            exporter = OtlpHttpExporter.Create(export, diagnostics.Identity, local.Consent);
            return new(local, traces, export, diagnostics.Identity, sources, exporter, diagnostics.TimeProvider, diagnostics.Directory);
        }
        catch
        {
            exporter?.DisposeAsync().AsTask().GetAwaiter().GetResult();
            local.Dispose();
            throw;
        }
    }

    internal static DesktopObservabilityHost OpenForTest(DesktopDiagnosticsOptions diagnostics, TracePolicyOptions traces,
        OtlpExporterOptions export, Func<ActivitySource, bool> sources, HttpMessageHandler handler)
    {
        DesktopDiagnostics local = DesktopDiagnostics.Open(diagnostics);
        return new(local, traces, export, diagnostics.Identity, sources,
            OtlpHttpExporter.CreateForTest(export, diagnostics.Identity, local.Consent, handler, diagnostics.TimeProvider), diagnostics.TimeProvider, diagnostics.Directory);
    }

    /// <summary>Dependency health derived from actual exporter lifecycle/failure facts; unknown before any successful delivery.</summary>
    public RequiredDependencyObservation CollectorReadiness => Exporter.CollectorReadiness;

    public ValueTask DisposeAsync()
    {
        lock (_gate) return new ValueTask(_shutdown ??= ShutdownAsync());
    }

    private async Task CollectAsync(TimeSpan interval, TimeProvider time)
    {
        using var timer = new PeriodicTimer(interval, time);
        try
        {
            while (await timer.WaitForNextTickAsync(_collectionStop.Token).ConfigureAwait(false)) _metrics.Collect();
        }
        catch (OperationCanceledException) when (_collectionStop.IsCancellationRequested) { }
    }

    private async Task ShutdownAsync()
    {
        await Task.Yield();
        await _collectionStop.CancelAsync().ConfigureAwait(false);
        await _collection.ConfigureAwait(false);
        _metrics.Dispose();
        await Readiness.DisposeAsync().ConfigureAwait(false);
        Signals.Dispose();
        Traces.Dispose();
        Diagnostics.Consent.Revoking -= Traces.PurgeBuffer;
        await Exporter.DisposeAsync().ConfigureAwait(false);
        Diagnostics.Dispose();
        _collectionStop.Dispose();
    }
}
