// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcForges.Observability.Desktop;

/// <summary>
/// Nonblocking, bounded, memory-only sanitized OTLP delivery. A single worker retries only transient failures;
/// an ambiguous delivery can be duplicated, so delivery is not exactly once. Revocation cancels uploads and purges
/// retained records, with an epoch fence preventing a quick re-grant from resurrecting earlier telemetry.
/// </summary>
public sealed class OtlpHttpExporter : IClientTelemetryTransport, IScrubbedSpanSink, ITelemetryEpochSource, IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly Queue<PendingRecord> _queue = new();
    private readonly SemaphoreSlim _ready = new(0, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly OtlpExporterOptions _options;
    private readonly ObservabilityContext _identity;
    private readonly TelemetryConsent _consent;
    private readonly HttpClient _client;
    private readonly TimeProvider _time;
    private readonly Task _worker;
    private CancellationTokenSource? _sending;
    private Task? _shutdown;
    private bool _stopping;
    private bool _stopped;
    private int _retainedRecords;
    private long _retainedBytes;
    private long _accepted, _delivered, _rejected, _overflow, _purged, _failures, _retries;
    private DependencyReadinessStatus _lastStatus;
    private long _lastObservation;
    private Task<OtlpCollectorCredential>? _credentialPending;

    private OtlpHttpExporter(OtlpExporterOptions options, ObservabilityContext identity, TelemetryConsent consent,
        HttpClient client, TimeProvider time)
    {
        options.Validate();
        using (ObservabilityScope.Push(identity)) { }
        _options = options;
        _identity = identity;
        _consent = consent;
        _client = client;
        _time = time;
        _consent.Revoking += Purge;
        _worker = Task.Run(RunAsync);
    }

    /// <summary>Creates the real HTTPS adapter. Redirects, cookies and automatic payload logging are disabled.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership is transferred to HttpClient with disposeHandler:true; both constructor and exporter initialization failures dispose their owner.")]
    public static OtlpHttpExporter Create(OtlpExporterOptions options, ObservabilityContext identity, TelemetryConsent consent)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(consent);
        options.Validate();
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = options.RequestTimeout,
            MaxConnectionsPerServer = 1,
        };
        HttpClient client;
        try { client = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan }; }
        catch { handler.Dispose(); throw; }
        try { return new OtlpHttpExporter(options, identity, consent, client, TimeProvider.System); }
        catch { client.Dispose(); throw; }
    }

    internal static OtlpHttpExporter CreateForTest(OtlpExporterOptions options, ObservabilityContext identity,
        TelemetryConsent consent, HttpMessageHandler handler, TimeProvider? time = null) =>
        new(options, identity, consent, new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan }, time ?? TimeProvider.System);

    public OtlpExportStatistics Statistics
    {
        get
        {
            lock (_gate) return new(_accepted, _delivered, _rejected, _overflow, _purged, _failures, _retries,
                _retainedRecords, _retainedBytes, _stopped);
        }
    }

    /// <summary>Capture at actual signal collection through an epoch-compatible sink; negative means no grant.</summary>
    public long CollectionEpoch
    {
        get
        {
            long epoch = _consent.CollectionEpoch;
            return _consent.IsGranted && epoch == _consent.CollectionEpoch ? epoch : -1L;
        }
    }

    /// <summary>Fresh, actual collector delivery health. Absence of observations is Unknown, not availability.</summary>
    public RequiredDependencyObservation CollectorReadiness
    {
        get
        {
            lock (_gate)
            {
                DependencyReadinessStatus status = _stopped ? DependencyReadinessStatus.Unavailable
                    : _lastStatus == DependencyReadinessStatus.Unknown
                        || _time.GetElapsedTime(_lastObservation) > _options.HealthFreshness
                        ? DependencyReadinessStatus.Unknown : _lastStatus;
                return new("observability.collector", status);
            }
        }
    }

    public void Send(StructuredSignal signal)
    {
        ArgumentNullException.ThrowIfNull(signal);
        if (signal.Level >= SignalLevel.Information)
            EncodeAndQueue("logs", () => OtlpJson.Log(signal, _identity, _options.MaximumRecordBytes), signal.CollectionEpoch);
    }

    public void Send(ScrubbedSpan span)
    {
        ArgumentNullException.ThrowIfNull(span);
        EncodeAndQueue("traces", () => OtlpJson.Span(span, _identity, _options.MaximumRecordBytes), span.CollectionEpoch);
    }

    public void Write(ScrubbedSpan span) => Send(span);

    internal void Metric(string name, MetricShape shape, double value, IReadOnlyDictionary<string, object?> labels,
        DateTimeOffset start, DateTimeOffset end, long epoch) => EncodeAndQueue("metrics", () =>
            OtlpJson.Metric(name, shape, value, labels, start, end, _identity, _options.MaximumRecordBytes), epoch);

    /// <summary>Drops queued records and cancels the in-flight request; no retained telemetry is written to disk.</summary>
    public void Purge()
    {
        CancellationTokenSource? sending;
        lock (_gate)
        {
            ClearQueue();
            sending = _sending;
            // Cancellation sources are disposed under this same gate after cancellation has been issued.
            sending?.Cancel();
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_shutdown is null)
            {
                _stopping = true;
                Wake();
                _shutdown = ShutdownAsync();
            }
            return new ValueTask(_shutdown);
        }
    }

    private void EncodeAndQueue(string path, Func<byte[]> encode, long? collectionEpoch = null)
    {
        // Serialize under the gate: even many concurrent callers cannot retain unaccounted record buffers.
        lock (_gate)
        {
            if (_stopping || !_consent.IsGranted) { _rejected++; return; }
            if (_retainedRecords >= _options.MaximumRetainedRecords) { _overflow++; return; }
            // An unstamped retained record has no trustworthy collection provenance. Never relabel it at send time.
            if (collectionEpoch is not long epoch) { _rejected++; return; }
            if (epoch != _consent.Revocations) { _purged++; return; }
            byte[] bytes;
            try { bytes = encode(); }
            catch (Exception error) when (error is InvalidDataException or ArgumentException or OverflowException)
            { _overflow++; return; }
            if (!_consent.IsGranted || epoch != _consent.Revocations) { _purged++; return; }
            if (_retainedBytes + bytes.Length > _options.MaximumRetainedBytes) { _overflow++; return; }
            _queue.Enqueue(new(path, bytes, epoch));
            _retainedBytes += bytes.Length;
            _retainedRecords++;
            _accepted++;
            Wake();
        }
    }

    private async Task RunAsync()
    {
        try
        {
            while (true)
            {
                PendingRecord? record;
                lock (_gate)
                {
                    record = _queue.TryDequeue(out PendingRecord? next) ? next : null;
                    if (record is null && _stopping) return;
                }
                if (record is null)
                {
                    await _ready.WaitAsync(_lifetime.Token).ConfigureAwait(false);
                    continue;
                }
                try { await DeliverAsync(record).ConfigureAwait(false); }
                finally
                {
                    lock (_gate)
                    {
                        _retainedBytes -= record.Bytes.Length;
                        _retainedRecords--;
                    }
                }
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        finally
        {
            lock (_gate) { ClearQueue(); _stopped = true; }
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "A failed host credential or transport adapter must not terminate telemetry lifecycle; its exception text never leaves this boundary.")]
    private async Task DeliverAsync(PendingRecord record)
    {
        for (int attempt = 0; attempt < _options.MaximumAttempts; attempt++)
        {
            CancellationTokenSource sending;
            lock (_gate)
            {
                if (!_consent.IsGranted || record.Epoch != _consent.Revocations || _lifetime.IsCancellationRequested)
                { _purged++; return; }
                sending = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
                _sending = sending;
            }
            using var deadline = new CancellationTokenSource(_options.RequestTimeout, _time);
            using var combined = CancellationTokenSource.CreateLinkedTokenSource(sending.Token, deadline.Token);
            TimeSpan delay = RetryDelay(attempt);
            bool retry = false;
            try
            {
                // Fence again immediately before transport hand-off; revocation also cancels the acquired token.
                if (!_consent.IsGranted || record.Epoch != _consent.Revocations) { CountPurged(); return; }
                combined.Token.ThrowIfCancellationRequested();
                using var request = new HttpRequestMessage(HttpMethod.Post,
                    new Uri(_options.Collector.AbsoluteUri.TrimEnd('/') + "/v1/" + record.Path))
                {
                    Content = new ByteArrayContent(record.Bytes),
                };
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                using OtlpCollectorCredential? credential = await CredentialAsync(combined.Token).ConfigureAwait(false);
                if (_options.Credentials is not null && credential is null)
                    throw new InvalidDataException("The collector credential owner returned no authorization.");
                if (credential is not null)
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential.Materialize());
                combined.Token.ThrowIfCancellationRequested();
                if (!_consent.IsGranted || record.Epoch != _consent.Revocations) { CountPurged(); return; }
                using HttpResponseMessage response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                    combined.Token).ConfigureAwait(false);
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    bool accepted = await AcceptResponseAsync(response, record.Path, combined.Token).ConfigureAwait(false);
                    lock (_gate)
                    {
                        if (accepted) _delivered++; else _rejected++;
                        ObserveHealth(accepted);
                    }
                    return;
                }
                // OTLP/HTTP defines precisely these retryable HTTP outcomes. Redirects and authentication refusals are terminal.
                retry = (int)response.StatusCode is 429 or 502 or 503 or 504;
                if (response.Headers.RetryAfter is { } after)
                {
                    TimeSpan requested = after.Delta ?? (after.Date is { } at ? at - _time.GetUtcNow() : delay);
                    delay = requested < TimeSpan.Zero ? TimeSpan.Zero : requested > _options.MaximumRetryDelay
                        ? _options.MaximumRetryDelay : requested;
                }
            }
            catch (HttpRequestException) { retry = true; }
            catch (OperationCanceledException)
            {
                if (sending.IsCancellationRequested || !_consent.IsGranted || record.Epoch != _consent.Revocations)
                { CountPurged(); return; }
                retry = true; // Per-attempt timeout; total attempts and shutdown are bounded.
            }
            catch (Exception error) when (error is JsonException or InvalidDataException or IOException)
            { retry = false; }
            catch (Exception) { retry = false; }
            finally
            {
                lock (_gate) { _sending = null; sending.Dispose(); }
            }
            if (!retry || attempt + 1 == _options.MaximumAttempts)
            {
                lock (_gate) { _failures++; ObserveHealth(false); }
                return;
            }
            lock (_gate) _retries++;
            CancellationTokenSource backoff;
            lock (_gate)
            {
                if (!_consent.IsGranted || record.Epoch != _consent.Revocations || _lifetime.IsCancellationRequested)
                { _purged++; return; }
                backoff = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
                _sending = backoff;
            }
            try { await Task.Delay(delay, _time, backoff.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (backoff.IsCancellationRequested) { CountPurged(); return; }
            finally { lock (_gate) { _sending = null; backoff.Dispose(); } }
        }
    }

    private static async Task<bool> AcceptResponseAsync(HttpResponseMessage response, string path, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentType?.MediaType != "application/json") return false;
        const int limit = 4096;
        if (response.Content.Headers.ContentLength is > limit) return false;
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        byte[] bytes = new byte[limit + 1];
        int length = 0;
        while (length < bytes.Length)
        {
            int count = await stream.ReadAsync(bytes.AsMemory(length), cancellationToken).ConfigureAwait(false);
            if (count == 0) break;
            length += count;
        }
        if (length > limit) return false;
        using JsonDocument json = JsonDocument.Parse(bytes.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 8 });
        if (json.RootElement.ValueKind != JsonValueKind.Object) return false;
        if (!json.RootElement.TryGetProperty("partialSuccess", out JsonElement partial)) return true;
        if (partial.ValueKind != JsonValueKind.Object) return false;
        string rejected = path == "traces" ? "rejectedSpans" : path == "logs" ? "rejectedLogRecords" : "rejectedDataPoints";
        if (!partial.TryGetProperty(rejected, out JsonElement countRejected)) return true;
        return countRejected.ValueKind == JsonValueKind.String ? countRejected.GetString() == "0"
            : countRejected.TryGetInt64(out long number) && number == 0;
    }

    private async Task<OtlpCollectorCredential?> CredentialAsync(CancellationToken cancellationToken)
    {
        IOtlpCollectorCredentials? owner = _options.Credentials;
        if (owner is null) return null;
        if (_credentialPending is { IsCompleted: false })
            throw new InvalidDataException("The collector credential owner has an outstanding cancelled operation.");
        Task<OtlpCollectorCredential> pending = Task.Run(async () =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await owner.AcquireAsync(cancellationToken).ConfigureAwait(false);
        }, CancellationToken.None);
        _credentialPending = pending;
        try
        {
            OtlpCollectorCredential credential = await pending.WaitAsync(cancellationToken).ConfigureAwait(false);
            _credentialPending = null;
            return credential;
        }
        catch
        {
            // At most one uncooperative secret lookup can remain. Its eventual secret is destroyed, not reused.
            _ = pending.ContinueWith(completed =>
            {
                if (completed.IsCompletedSuccessfully) completed.Result?.Dispose();
                else _ = completed.Exception;
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
    }

    private TimeSpan RetryDelay(int attempt)
    {
        double milliseconds = _options.RetryDelay.TotalMilliseconds * Math.Pow(2, attempt)
            * (RandomNumberGenerator.GetInt32(800, 1201) / 1000d);
        return TimeSpan.FromMilliseconds(Math.Min(milliseconds, _options.MaximumRetryDelay.TotalMilliseconds));
    }

    private async Task ShutdownAsync()
    {
        // Start asynchronously so this never executes cancellation callbacks while the caller owns _gate.
        await Task.Yield();
        try { await _worker.WaitAsync(_options.ShutdownTimeout, _time).ConfigureAwait(false); }
        catch (TimeoutException)
        {
            await _lifetime.CancelAsync().ConfigureAwait(false);
            await _worker.ConfigureAwait(false);
        }
        finally
        {
            _consent.Revoking -= Purge;
            _client.Dispose();
            lock (_gate) _sending?.Dispose();
            _lifetime.Dispose();
            _ready.Dispose();
        }
    }

    private void Wake()
    {
        if (_ready.CurrentCount == 0) _ready.Release();
    }

    private void CountPurged() { lock (_gate) _purged++; }

    private void ObserveHealth(bool accepted)
    {
        _lastStatus = accepted ? DependencyReadinessStatus.Available : DependencyReadinessStatus.Unavailable;
        _lastObservation = _time.GetTimestamp();
    }

    private void ClearQueue()
    {
        while (_queue.TryDequeue(out PendingRecord? record))
        {
            _retainedRecords--;
            _retainedBytes -= record.Bytes.Length;
            _purged++;
        }
    }

    private sealed record PendingRecord(string Path, byte[] Bytes, long Epoch);
}
