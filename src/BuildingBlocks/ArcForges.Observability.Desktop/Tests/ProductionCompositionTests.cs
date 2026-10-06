// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Text.Json;
using Xunit;

namespace ArcForges.Observability.Desktop.Tests;

[SuppressMessage("Reliability", "CA2007", Justification = "Offline xUnit lifecycle tests deliberately retain the test synchronization context; nested probes use explicit component-owned cancellation.")]
public sealed class ProductionCompositionTests
{
    private static readonly string[] UnavailableIds = ["error", "invalid", "unknown"];

    [Fact]
    public void FaultingPurgeCallbackCannotPreventDurableWithdrawalOrAnotherOwnersPurge()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        diagnostics.Consent.Revoking += () => throw new InvalidOperationException("faulting-cancellation-owner");
        bool nextCalled = false;
        diagnostics.Consent.Revoking += () => nextCalled = true;
        diagnostics.Consent.Revoke();
        Assert.True(nextCalled);
        Assert.False(diagnostics.Consent.IsGranted);
        using var reopened = Fixtures.Open(directory.Path);
        Assert.Equal(TelemetryConsentState.Revoked, reopened.Consent.State);
    }

    [Fact]
    public async Task RealProductionFactoryStartsWithoutGrantOrCollectorAvailability()
    {
        using var directory = new TestDirectory();
        DesktopDiagnosticsOptions options = Fixtures.Options(directory.Path);
        await using var host = DesktopObservabilityHost.Open(options, new(0, TimeSpan.FromDays(1)),
            new() { Collector = new("https://collector.invalid") }, _ => false);
        using (ObservabilityScope.Push(options.Identity)) host.Signals.Emit(SignalEventName.ApplicationStarted, SignalLevel.Information);
        Assert.False(host.Diagnostics.Consent.IsGranted);
        Assert.Equal(0, host.Exporter.Statistics.Accepted);
        Assert.Equal(DependencyReadinessStatus.Unknown, host.CollectorReadiness.Status);
        Assert.Equal(HealthProbeStatus.Healthy, (await host.Readiness.CheckAsync(TestContext.Current.CancellationToken)).Status);
        Assert.NotEmpty(host.Diagnostics.ReadRecent(10));
    }
    [Fact]
    public async Task ActualHostKeepsLocalDiagnosticsWithoutConsentAndPurgesTraceBufferOnWithdrawal()
    {
        using var directory = new TestDirectory();
        DesktopDiagnosticsOptions options = Fixtures.Options(directory.Path);
        string sourceName = "composition." + Guid.NewGuid().ToString("N");
        using var source = new ActivitySource(sourceName);
        using var handler = new OtlpExporterTests.Collector();
        await using var host = DesktopObservabilityHost.OpenForTest(options, new(0, TimeSpan.FromDays(1)),
            new() { Collector = new("https://collector.invalid") }, candidate => candidate.Name == sourceName, handler);
        using (ObservabilityScope.Push(options.Identity)) host.Signals.Emit(SignalEventName.OperationCompleted, SignalLevel.Information);
        Assert.NotEmpty(host.Diagnostics.ReadRecent(10));
        Assert.Equal(0, host.Exporter.Statistics.Accepted);
        host.Diagnostics.Consent.Grant();
        using (source.StartActivity("operation.before")) { }
        using Activity? crossingWithdrawal = source.StartActivity("operation.crossing");
        Assert.Equal(1, host.Traces.Statistics.BufferedSpans);
        host.Diagnostics.Consent.Revoke();
        Assert.Equal(0, host.Traces.Statistics.BufferedSpans);
        host.Diagnostics.Consent.Grant();
        crossingWithdrawal!.SetStatus(ActivityStatusCode.Error);
        crossingWithdrawal.Stop();
        using (Activity? activity = source.StartActivity("operation.failed")) activity!.SetStatus(ActivityStatusCode.Error, "secret-exception");
        await host.DisposeAsync();
        Assert.DoesNotContain(handler.Requests, request => request.Body.Contains("operation.before", StringComparison.Ordinal));
        Assert.DoesNotContain(handler.Requests, request => request.Body.Contains("operation.crossing", StringComparison.Ordinal));
        Assert.Contains(handler.Requests, request => request.Body.Contains("operation.failed", StringComparison.Ordinal));
        Assert.All(handler.Requests, request => Assert.DoesNotContain("secret-exception", request.Body, StringComparison.Ordinal));
        Assert.True(host.Exporter.Statistics.Stopped);
        Assert.Null(source.StartActivity("operation.after"));
    }

    [Fact]
    public async Task RealTypedEmissionProducesOtlpDeltaCountersAndHistogramsWithFiniteLabels()
    {
        using var directory = new TestDirectory();
        DesktopDiagnosticsOptions options = Fixtures.Options(directory.Path);
        using var handler = new OtlpExporterTests.Collector();
        await using var host = DesktopObservabilityHost.OpenForTest(options, new(0, TimeSpan.FromDays(1)),
            new() { Collector = new("https://collector.invalid") }, _ => false, handler);
        host.Diagnostics.Consent.Grant();
        using (ObservabilityScope.Push(options.Identity with { Duration = TimeSpan.FromMilliseconds(25), Service = SignalService.Storage }))
            host.Signals.Emit(SignalEventName.StorageCommitted, SignalLevel.Information);
        await host.DisposeAsync();
        RequestMetrics(handler, out JsonElement[] metrics);
        JsonElement counter = metrics.Single(item => item.GetProperty("name").GetString() == "arcf_signal_count");
        Assert.Equal(1, counter.GetProperty("sum").GetProperty("aggregationTemporality").GetInt32());
        Assert.Equal(1, counter.GetProperty("sum").GetProperty("dataPoints")[0].GetProperty("asDouble").GetDouble());
        JsonElement histogram = metrics.Single(item => item.GetProperty("name").GetString() == "arcf_signal_duration").GetProperty("histogram");
        Assert.Equal("1", histogram.GetProperty("dataPoints")[0].GetProperty("count").GetString());
        Assert.Equal(25, histogram.GetProperty("dataPoints")[0].GetProperty("sum").GetDouble());
        Assert.Equal("Storage", counter.GetProperty("sum").GetProperty("dataPoints")[0].GetProperty("attributes")[0]
            .GetProperty("value").GetProperty("stringValue").GetString());
    }

    [Fact]
    public async Task CollectorExcludesForeignInstrumentNamesIdentityAndUnboundedMetricLabels()
    {
        using var directory = new TestDirectory();
        DesktopDiagnosticsOptions options = Fixtures.Options(directory.Path);
        using var handler = new OtlpExporterTests.Collector();
        await using var host = DesktopObservabilityHost.OpenForTest(options, new(0, TimeSpan.FromDays(1)),
            new() { Collector = new("https://collector.invalid") }, _ => false, handler);
        host.Diagnostics.Consent.Grant();
        using var matching = new Meter(new MeterOptions(SignalEmitter.MeterName) { Tags = IdentityTags(options.Identity) });
        matching.CreateCounter<long>("user.private.secret").Add(7);
        matching.CreateCounter<long>("arcf_signal_count").Add(1,
            new KeyValuePair<string, object?>("user.id", "secret-user-never-export"),
            new KeyValuePair<string, object?>("service.name", "unbounded-private-service"));
        using var foreign = new Meter(new MeterOptions(SignalEmitter.MeterName) { Tags = IdentityTags(Fixtures.Identity()) });
        foreign.CreateCounter<long>("arcf_signal_count").Add(4);
        await host.DisposeAsync();
        RequestMetrics(handler, out JsonElement[] metrics);
        JsonElement metric = Assert.Single(metrics);
        Assert.Equal("arcf_signal_count", metric.GetProperty("name").GetString());
        Assert.Equal(1, metric.GetProperty("sum").GetProperty("dataPoints")[0].GetProperty("asDouble").GetDouble());
        Assert.Equal(0, metric.GetProperty("sum").GetProperty("dataPoints")[0].GetProperty("attributes").GetArrayLength());
        Assert.All(handler.Requests, request => Assert.DoesNotContain("private", request.Body, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ActualDiagnosticDirectoryReadWriteProbeDoesNotTouchExistingData()
    {
        using var directory = new TestDirectory();
        string data = Path.Combine(directory.Path, "existing.txt");
        await File.WriteAllTextAsync(data, "preserved-user-data", TestContext.Current.CancellationToken);
        await using var monitor = new DependencyHealthMonitor([new DiagnosticDirectoryProbe(directory.Path)], TimeSpan.FromSeconds(1));
        HealthProbeResult result = await monitor.CheckAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HealthProbeStatus.Healthy, result.Status);
        Assert.Equal("preserved-user-data", await File.ReadAllTextAsync(data, TestContext.Current.CancellationToken));
        Assert.Single(Directory.GetFiles(directory.Path));
        await using var missing = new DependencyHealthMonitor([new DiagnosticDirectoryProbe(Path.Combine(directory.Path, "absent"))], TimeSpan.FromSeconds(1));
        Assert.Equal(HealthProbeStatus.Unavailable, (await missing.CheckAsync(TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task DependencyFailuresUnknownAndInvalidStatusesFailClosed()
    {
        await using var monitor = new DependencyHealthMonitor([
            new Probe("error", _ => ValueTask.FromException<DependencyReadinessStatus>(new IOException("secret-error"))),
            new Probe("unknown", _ => ValueTask.FromResult(DependencyReadinessStatus.Unknown)),
            new Probe("invalid", _ => ValueTask.FromResult((DependencyReadinessStatus)999)),
        ], TimeSpan.FromSeconds(1));
        HealthProbeResult result = await monitor.CheckAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HealthProbeStatus.Unavailable, result.Status);
        Assert.Equal(UnavailableIds, result.NotReadyDependencies);
    }

    [Fact]
    public async Task UncooperativeDependencyIsBoundedToOneOutstandingCallAcrossRepeatedChecks()
    {
        var completion = new TaskCompletionSource<DependencyReadinessStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;
        await using var monitor = new DependencyHealthMonitor([new Probe("hung", _ =>
        {
            Interlocked.Increment(ref calls);
            return new ValueTask<DependencyReadinessStatus>(completion.Task);
        })], TimeSpan.FromMilliseconds(20));
        Assert.Equal(HealthProbeStatus.Unavailable, (await monitor.CheckAsync(TestContext.Current.CancellationToken)).Status);
        await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => monitor.CheckAsync(TestContext.Current.CancellationToken).AsTask()));
        Assert.Equal(1, calls);
        await monitor.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        completion.SetResult(DependencyReadinessStatus.Available);
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await monitor.CheckAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CallerCancellationAndConcurrentShutdownDoNotInventHealthOrLeakWaiters()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = new DependencyHealthMonitor([new Probe("cancellable", async token =>
        {
            started.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return DependencyReadinessStatus.Available;
        })], TimeSpan.FromSeconds(1));
        using var cancellation = new CancellationTokenSource();
        Task<HealthProbeResult> first = monitor.CheckAsync(cancellation.Token).AsTask();
        await started.Task.WaitAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Task<HealthProbeResult> second = monitor.CheckAsync(TestContext.Current.CancellationToken).AsTask();
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        await monitor.DisposeAsync();
        try { Assert.Equal(HealthProbeStatus.Unavailable, (await second).Status); }
        catch (OperationCanceledException) { } // Either admitted check observed the withdrawn adapter, or shutdown cancelled it.
    }

    private static KeyValuePair<string, object?>[] IdentityTags(ObservabilityContext identity) =>
    [
        new("application.id", identity.ApplicationId), new("instance.id", identity.InstanceId.Value.ToString("N")),
        new("build.id", identity.BuildId), new("deployment.environment", identity.Environment.ToString()),
    ];

    private static void RequestMetrics(OtlpExporterTests.Collector collector, out JsonElement[] metrics)
    {
        metrics = collector.Requests.Where(request => request.Path == "/v1/metrics").Select(request =>
        {
            using JsonDocument document = JsonDocument.Parse(request.Body);
            return document.RootElement.GetProperty("resourceMetrics")[0].GetProperty("scopeMetrics")[0].GetProperty("metrics")[0].Clone();
        }).ToArray();
    }

    private sealed class Probe(string id, Func<CancellationToken, ValueTask<DependencyReadinessStatus>> operation) : IRequiredDependencyProbe
    {
        public string DependencyId => id;
        public ValueTask<DependencyReadinessStatus> ProbeAsync(CancellationToken cancellationToken) => operation(cancellationToken);
    }
}
