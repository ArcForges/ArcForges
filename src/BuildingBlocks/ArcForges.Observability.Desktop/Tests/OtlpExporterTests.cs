// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace ArcForges.Observability.Desktop.Tests;

[SuppressMessage("Reliability", "CA2007", Justification = "Offline xUnit lifecycle tests deliberately retain the test synchronization context; nested transport callbacks use explicit component-owned cancellation.")]
public sealed class OtlpExporterTests
{
    [Fact]
    public async Task RealOtlpSerializationExportsReviewedSpansAndLogsWithExactWireShapes()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        using var handler = new Collector();
        await using var exporter = OtlpHttpExporter.CreateForTest(Options(), Fixtures.Identity(), diagnostics.Consent, handler);
        using var policy = new TracePolicy(new(1, TimeSpan.FromDays(1)), Fixtures.Identity(), exporter,
            diagnostics.LocalSink, diagnostics.Consent);
        using (var activity = new Activity("request.operation"))
        {
            activity.SetIdFormat(ActivityIdFormat.W3C).Start();
            activity.ActivityTraceFlags = ActivityTraceFlags.Recorded;
            policy.OnSpanStarted(activity);
            activity.SetTag("prompt", "secret-prompt-never-export");
            activity.SetTag("Authorization", "Bearer secret-token-never-export");
            activity.SetTag("http.response.status_code", 403);
            activity.SetTag("expected.revision", ulong.MaxValue);
            activity.AddEvent(new ActivityEvent("https://private.invalid/user", tags: new ActivityTagsCollection
                { { "file.path", "secret-path-never-export" } }));
            activity.SetStatus(ActivityStatusCode.Error, "secret-exception-never-export");
            activity.Stop();
            policy.OnSpanEnded(activity);
        }
        Emit(exporter);
        await exporter.DisposeAsync();
        Assert.Equal(2, exporter.Statistics.Delivered);
        Assert.Equal(0, exporter.Statistics.RetainedBytes);
        Assert.Contains(handler.Requests, item => item.Path == "/v1/traces");
        Assert.Contains(handler.Requests, item => item.Path == "/v1/logs");
        foreach (Request item in handler.Requests)
        {
            Assert.Equal("application/json", item.ContentType);
            Assert.DoesNotContain("secret-", item.Body, StringComparison.Ordinal);
            using JsonDocument json = JsonDocument.Parse(item.Body);
            Assert.Equal(JsonValueKind.Object, json.RootElement.ValueKind);
        }
        using JsonDocument trace = JsonDocument.Parse(handler.Requests.Single(item => item.Path == "/v1/traces").Body);
        JsonElement span = trace.RootElement.GetProperty("resourceSpans")[0].GetProperty("scopeSpans")[0].GetProperty("spans")[0];
        Assert.Equal(32, span.GetProperty("traceId").GetString()!.Length);
        Assert.Equal(16, span.GetProperty("spanId").GetString()!.Length);
        Assert.Equal(JsonValueKind.String, span.GetProperty("startTimeUnixNano").ValueKind);
        Assert.Equal(2, span.GetProperty("status").GetProperty("code").GetInt32());
        Assert.Equal("redacted", span.GetProperty("events")[0].GetProperty("name").GetString());
        JsonElement revision = span.GetProperty("attributes").EnumerateArray().Single(item => item.GetProperty("key").GetString() == "expected.revision");
        Assert.Equal(ulong.MaxValue.ToString(System.Globalization.CultureInfo.InvariantCulture), revision.GetProperty("value").GetProperty("stringValue").GetString());
    }

    [Fact]
    public async Task MissingConsentProducesNoTransportCallAndNoClaimOfReadiness()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        using var handler = new Collector();
        await using var exporter = OtlpHttpExporter.CreateForTest(Options(), Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        Assert.Equal(DependencyReadinessStatus.Unknown, exporter.CollectorReadiness.Status);
        await exporter.DisposeAsync();
        Assert.Empty(handler.Requests);
        Assert.Equal(1, exporter.Statistics.Rejected);
    }

    [Fact]
    public async Task RevocationCancelsInFlightAndPurgesQueuedRecordsAcrossImmediateRegrant()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var handler = new Collector(async (attempt, token) =>
        {
            if (attempt != 1) return Ok();
            entered.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            catch (OperationCanceledException) { cancelled.SetResult(); throw; }
            return Ok();
        });
        await using var exporter = OtlpHttpExporter.CreateForTest(Options(), Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        Emit(exporter);
        Emit(exporter);
        diagnostics.Consent.Revoke();
        diagnostics.Consent.Grant();
        await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        Emit(exporter);
        await exporter.DisposeAsync();
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(1, exporter.Statistics.Delivered);
        Assert.Equal(3, exporter.Statistics.Purged);
        Assert.Equal(0, exporter.Statistics.RetainedBytes);
    }

    [Fact]
    [SuppressMessage("Reliability", "CA2025", Justification = "The response is transferred in an already-completed Task.FromResult; the actual exporter awaits and disposes it before handler disposal.")]
    public async Task RevocationCancelsRetryAfterBackoffAndNeverRetainsOldEpochUntilDelayEnds()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        using var handler = new Collector((attempt, _) =>
        {
            if (attempt != 1) return Task.FromResult(Ok());
            var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(2));
            return Task.FromResult(response);
        });
        await using var exporter = OtlpHttpExporter.CreateForTest(Options(), Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        await EventuallyAsync(() => exporter.Statistics.Retries == 1);
        diagnostics.Consent.Revoke();
        diagnostics.Consent.Grant();
        Emit(exporter);
        await exporter.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.Equal(1, exporter.Statistics.Purged);
        Assert.Equal(1, exporter.Statistics.Delivered);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task ConcurrentProducersRespectBothQueueBudgetsAndKeepCallerNonblocking()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var handler = new Collector(async (_, token) => { entered.TrySetResult(); await release.Task.WaitAsync(token); return Ok(); });
        await using var exporter = OtlpHttpExporter.CreateForTest(new()
        {
            Collector = new("https://collector.invalid"),
            MaximumRetainedRecords = 2,
            MaximumRetainedBytes = 4096,
            MaximumRecordBytes = 1024,
        }, Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        await Task.WhenAll(Enumerable.Range(0, 40).Select(_ => Task.Run(() => Emit(exporter))));
        Assert.Equal(2, exporter.Statistics.RetainedRecords);
        Assert.InRange(exporter.Statistics.RetainedBytes, 1, 4096);
        Assert.Equal(39, exporter.Statistics.Overflow);
        release.SetResult();
        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => exporter.DisposeAsync().AsTask()));
        Assert.Equal(2, exporter.Statistics.Delivered);
        Assert.Equal(0, exporter.Statistics.RetainedRecords);
        Emit(exporter); // Refused after shutdown, with no disposed-resource or producer-thread exception.
        Assert.Equal(1, exporter.Statistics.Rejected);
    }

    [Theory]
    [InlineData(429)]
    [InlineData(502)]
    [InlineData(503)]
    [InlineData(504)]
    public async Task OnlyOtlpRetryableStatusesRetryTheSameSanitizedRecord(int status)
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        using var handler = new Collector((attempt, _) => Task.FromResult(attempt == 1 ? new HttpResponseMessage((HttpStatusCode)status) : Ok()));
        await using var exporter = OtlpHttpExporter.CreateForTest(Options(), Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        await exporter.DisposeAsync();
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(handler.Requests[0].Body, handler.Requests[1].Body);
        Assert.Equal(1, exporter.Statistics.Retries);
        Assert.Equal(1, exporter.Statistics.Delivered);
    }

    [Theory]
    [InlineData(302)]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(500)]
    public async Task RedirectsAuthorizationAndPermanentErrorsAreTerminal(int status)
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        using var handler = new Collector((_, _) => Task.FromResult(new HttpResponseMessage((HttpStatusCode)status)));
        await using var exporter = OtlpHttpExporter.CreateForTest(Options(), Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        await exporter.DisposeAsync();
        Assert.Single(handler.Requests);
        Assert.Equal(1, exporter.Statistics.Failures);
        Assert.Equal(0, exporter.Statistics.Retries);
    }

    [Theory]
    [InlineData("{\"partialSuccess\":{\"rejectedLogRecords\":\"1\",\"errorMessage\":\"secret-backend-message\"}}")]
    [InlineData("not-json")]
    [InlineData("[]")]
    [InlineData("{\"partialSuccess\":null}")]
    public async Task PartialAndMalformedSuccessNeverClaimFullDeliveryOrRetry(string body)
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        using var handler = new Collector((_, _) => Task.FromResult(Ok(body)));
        await using var exporter = OtlpHttpExporter.CreateForTest(Options(), Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        await exporter.DisposeAsync();
        Assert.Single(handler.Requests);
        Assert.Equal(0, exporter.Statistics.Delivered);
        Assert.Equal(1, exporter.Statistics.Rejected + exporter.Statistics.Failures);
    }

    [Fact]
    public async Task OversizedCollectorResponseIsBoundedAndNeverAccepted()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        using var handler = new Collector((_, _) => Task.FromResult(Ok("{\"unknown\":\"" + new string('x', 5000) + "\"}")));
        await using var exporter = OtlpHttpExporter.CreateForTest(Options(), Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        await exporter.DisposeAsync();
        Assert.Equal(1, exporter.Statistics.Rejected);
    }

    [Fact]
    public async Task PerAttemptTimeoutAndAttemptsBoundUnavailableTransport()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        using var handler = new Collector(async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Ok(); });
        await using var exporter = OtlpHttpExporter.CreateForTest(new()
        {
            Collector = new("https://collector.invalid"),
            RequestTimeout = TimeSpan.FromMilliseconds(20),
            RetryDelay = TimeSpan.Zero,
            MaximumAttempts = 2,
        }, Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        await exporter.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(1, exporter.Statistics.Failures);
        Assert.Equal(0, exporter.Statistics.RetainedRecords);
    }

    [Fact]
    public async Task ShutdownDeadlineCancelsAndDropsRemainingRecords()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        using var handler = new Collector(async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Ok(); });
        await using var exporter = OtlpHttpExporter.CreateForTest(new()
        {
            Collector = new("https://collector.invalid"),
            ShutdownTimeout = TimeSpan.FromMilliseconds(20),
        }, Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        Emit(exporter);
        await exporter.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        Assert.True(exporter.Statistics.Stopped);
        Assert.Equal(2, exporter.Statistics.Purged);
    }

    [Theory]
    [InlineData("http://collector.invalid")]
    [InlineData("https://user:password@collector.invalid")]
    [InlineData("https://collector.invalid/?token=value")]
    [InlineData("https://collector.invalid/#fragment")]
    public void CollectorConfigurationRejectsUnreviewedTransportTargets(string address)
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        Assert.Throws<ArgumentException>(() => OtlpHttpExporter.Create(new() { Collector = new(address) }, Fixtures.Identity(), diagnostics.Consent));
    }

    [Fact]
    public async Task CollectorCredentialIsRefreshedForEachAttemptAndNeverEntersExportedJson()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        var owner = new Credentials(_ => ValueTask.FromResult(new OtlpCollectorCredential("secret-bearer")));
        using var handler = new Collector((attempt, _) => Task.FromResult(attempt == 1 ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) : Ok()));
        await using var exporter = OtlpHttpExporter.CreateForTest(new()
        {
            Collector = new("https://collector.invalid"),
            Credentials = owner,
            RetryDelay = TimeSpan.Zero,
        }, Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        await exporter.DisposeAsync();
        Assert.Equal(2, owner.Calls);
        Assert.All(handler.Requests, item =>
        {
            Assert.Equal("Bearer secret-bearer", item.Authorization);
            Assert.DoesNotContain("secret-bearer", item.Body, StringComparison.Ordinal);
        });
        using var credential = new OtlpCollectorCredential("secret-bearer");
        Assert.Equal("OtlpCollectorCredential:[redacted]", credential.ToString());
        credential.Dispose();
        Assert.Throws<ObjectDisposedException>(() => credential.Materialize());
    }

    [Fact]
    public async Task UncooperativeCredentialOwnerIsBoundedAndCannotDelayShutdownOrLeakLateSecret()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        var completion = new TaskCompletionSource<OtlpCollectorCredential>(TaskCreationOptions.RunContinuationsAsynchronously);
        var owner = new Credentials(_ => new ValueTask<OtlpCollectorCredential>(completion.Task));
        using var handler = new Collector();
        await using var exporter = OtlpHttpExporter.CreateForTest(new()
        {
            Collector = new("https://collector.invalid"),
            Credentials = owner,
            RequestTimeout = TimeSpan.FromMilliseconds(20),
            MaximumAttempts = 2,
            RetryDelay = TimeSpan.Zero,
        }, Fixtures.Identity(), diagnostics.Consent, handler);
        Emit(exporter);
        Emit(exporter);
        await exporter.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.Equal(1, owner.Calls);
        Assert.Empty(handler.Requests);
        using var late = new OtlpCollectorCredential("late-secret-bearer");
        completion.SetResult(late);
        await EventuallyAsync(() =>
        {
            try { late.Materialize(); return false; }
            catch (ObjectDisposedException) { return true; }
        });
    }

    [Fact]
    public async Task ActualCollectorHealthRecoversAndExpiresWithoutInventingAnObservation()
    {
        using var directory = new TestDirectory();
        using var diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        var time = new HealthClock();
        using var handler = new Collector((attempt, _) => Task.FromResult(attempt == 1 ? new HttpResponseMessage(HttpStatusCode.Unauthorized) : Ok()));
        await using var exporter = OtlpHttpExporter.CreateForTest(Options(), Fixtures.Identity(), diagnostics.Consent, handler, time);
        Assert.Equal(DependencyReadinessStatus.Unknown, exporter.CollectorReadiness.Status);
        Emit(exporter);
        await EventuallyAsync(() => exporter.Statistics.Failures == 1);
        Assert.Equal(DependencyReadinessStatus.Unavailable, exporter.CollectorReadiness.Status);
        Emit(exporter);
        await EventuallyAsync(() => exporter.Statistics.Delivered == 1);
        Assert.Equal(DependencyReadinessStatus.Available, exporter.CollectorReadiness.Status);
        time.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(DependencyReadinessStatus.Unknown, exporter.CollectorReadiness.Status);
    }

    private static async Task EventuallyAsync(Func<bool> condition)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!condition()) await Task.Delay(5, deadline.Token);
    }

    private static OtlpExporterOptions Options() => new() { Collector = new("https://collector.invalid"), RetryDelay = TimeSpan.Zero };

    internal static void Emit(OtlpHttpExporter exporter) => Fixtures.Emit(new TransportSink(exporter), SignalEventName.OperationCompleted, SignalLevel.Information);

    internal static HttpResponseMessage Ok(string body = "{}") => new(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };

    private sealed class TransportSink(OtlpHttpExporter exporter) : IStructuredEventSink, ITelemetryEpochSource
    {
        public long CollectionEpoch => exporter.CollectionEpoch;
        public void Write(StructuredSignal signal) => exporter.Send(signal);
    }

    internal sealed record Request(string Path, string? ContentType, string Body, string? Authorization);

    internal sealed class Collector(Func<int, CancellationToken, Task<HttpResponseMessage>>? response = null) : HttpMessageHandler
    {
        private readonly ConcurrentQueue<Request> _requests = new();
        private int _attempt;
        internal IReadOnlyList<Request> Requests => _requests.ToArray();

        [SuppressMessage("Reliability", "CA2000", Justification = "The fake response is transferred to the actual HttpClient/exporter, which owns and disposes it.")]
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _requests.Enqueue(new(request.RequestUri!.AbsolutePath, request.Content!.Headers.ContentType?.MediaType,
                await request.Content.ReadAsStringAsync(cancellationToken), request.Headers.Authorization?.ToString()));
            int attempt = Interlocked.Increment(ref _attempt);
            return response is null ? Ok() : await response(attempt, cancellationToken);
        }
    }

    private sealed class Credentials(Func<CancellationToken, ValueTask<OtlpCollectorCredential>> acquire) : IOtlpCollectorCredentials
    {
        internal int Calls { get; private set; }
        public ValueTask<OtlpCollectorCredential> AcquireAsync(CancellationToken cancellationToken)
        {
            Calls++;
            return acquire(cancellationToken);
        }
    }

    private sealed class HealthClock : TimeProvider
    {
        private long _timestamp = 1;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref _timestamp);
        internal void Advance(TimeSpan span) => Interlocked.Add(ref _timestamp, span.Ticks);
    }
}
