// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Globalization;
using System.Text.Json;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;

namespace ArcForges.Observability.Desktop;

/// <summary>Where and how the desktop diagnostics of one installation keep their local state.</summary>
public sealed record DesktopDiagnosticsOptions
{
    /// <summary>The host-owned local directory for the diagnostic log, the consent record and a pending crash record.</summary>
    public required string Directory { get; init; }

    /// <summary>The application identity put in every report: application, build, environment and instance.</summary>
    public required ObservabilityContext Identity { get; init; }

    /// <summary>The clock source, replaced in tests. Verbose-session expiry and approval expiry use its monotonic timer.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>The largest log segment before rotation (4 KiB to 16 MiB). Default 512 KiB.</summary>
    public long MaximumSegmentBytes { get; init; } = 512 * 1024;

    /// <summary>The most log segments kept (2 to 64). Default 8, so the log stays within about 4 MiB.</summary>
    public int MaximumSegments { get; init; } = 8;

    /// <summary>The oldest a log segment may be before it is deleted (1 hour to 90 days). Default 14 days.</summary>
    public TimeSpan MaximumAge { get; init; } = TimeSpan.FromDays(14);

    /// <summary>How long an approved report may wait to be sent (1 minute to 1 hour). Default 15 minutes.</summary>
    public TimeSpan ApprovalLifetime { get; init; } = TimeSpan.FromMinutes(15);
}

/// <summary>
/// The desktop diagnostics of one installation (WP-12.05, observability architecture section 9). Local diagnostics are
/// always available and never upload. Client telemetry needs revocable consent. A report is generated, shown in full and
/// sent only after approval. A verbose session is bounded and self-disabling. No memory dump is ever produced.
/// This type holds no uploader and no transport: the only ways out of the process are the transport given to
/// <see cref="CreateTelemetry"/>, called only while consent is granted, and the uploader given to
/// <see cref="ApprovedDiagnosticReport.SendAsync"/>, called only for an approved report.
/// </summary>
public sealed class DesktopDiagnostics : IDisposable
{
    internal const string CrashMarkerFileName = "pending-crash.json";
    private const int MarkerVersion = 1;

    private readonly DesktopDiagnosticsOptions _options;
    private readonly string _directory;
    private readonly Clock _clock;
    private readonly LocalDiagnosticStore _store;
    private bool _disposed;

    private DesktopDiagnostics(DesktopDiagnosticsOptions options)
    {
        _options = options;
        _directory = Path.GetFullPath(options.Directory);
        System.IO.Directory.CreateDirectory(_directory);
        _clock = new Clock(options.TimeProvider);
        Consent = new TelemetryConsent(_directory, _clock);
        Verbose = new VerboseDiagnosticSession(_clock, options.TimeProvider);
        _store = new LocalDiagnosticStore(_directory, options, _clock, Verbose);
        Consent.Changed += OnConsentChanged;
        Verbose.Changed += OnVerboseChanged;
    }

    /// <summary>The revocable consent to send client telemetry. Absent until the user grants it.</summary>
    public TelemetryConsent Consent { get; }

    /// <summary>The time-bounded verbose session. Read its state to show the indicator while it is active.</summary>
    public VerboseDiagnosticSession Verbose { get; }

    /// <summary>
    /// The sink for local diagnostics only. Install it where a host wants events kept on this device and never sent,
    /// whatever the consent. It is a structured-event sink for a <see cref="SignalEmitter"/>.
    /// </summary>
    public IStructuredEventSink LocalSink => _store;

    /// <summary>True when a crash recorded by an earlier run is waiting for the user to send or dismiss its report.</summary>
    public bool HasPendingCrashReport => ReadMarker() is not null;

    /// <summary>Opens the diagnostics in the host's directory, creating it if needed.</summary>
    public static DesktopDiagnostics Open(DesktopDiagnosticsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Directory);
        ArgumentNullException.ThrowIfNull(options.Identity);
        ArgumentNullException.ThrowIfNull(options.TimeProvider);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MaximumSegmentBytes, 4 * 1024L);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.MaximumSegmentBytes, 16 * 1024 * 1024L);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MaximumSegments, 2);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.MaximumSegments, 64);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MaximumAge, TimeSpan.FromHours(1));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.MaximumAge, TimeSpan.FromDays(90));
        ArgumentOutOfRangeException.ThrowIfLessThan(options.ApprovalLifetime, TimeSpan.FromMinutes(1));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.ApprovalLifetime, TimeSpan.FromHours(1));
        return new DesktopDiagnostics(options);
    }

    /// <summary>
    /// Creates the consent-gated telemetry path: install the result as the sink of a <see cref="SignalEmitter"/> and call
    /// its <c>Export</c> from the host's span exporter. Events are always kept locally; the transport sees them only while consent is granted.
    /// </summary>
    public ConsentGatedTelemetry CreateTelemetry(IClientTelemetryTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);
        return new ConsentGatedTelemetry(Consent, _store, transport);
    }

    /// <summary>The newest local diagnostic entries (1 to 1000), oldest first: the local diagnostic view. Nothing is uploaded.</summary>
    public IReadOnlyList<LocalDiagnosticEntry> ReadRecent(int maximumEntries)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumEntries, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumEntries, LocalDiagnosticStore.MaxEntriesPerRead);
        return _store.ReadRecent(maximumEntries, out _);
    }

    /// <summary>
    /// Records that the process is crashing, for a host's unhandled-exception handler. Only the registered reason code
    /// of the exception type is kept (never its message, data or stack), together with a support reference. It is stored
    /// locally; nothing is sent and no consent is consulted. A failure to store the record never throws (a handler must not fail while failing); only a null argument does.
    /// </summary>
    public void RecordCrash(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        ReasonCode reason = ExceptionReasonMapper.Default.Map(exception) ?? ReasonCodes.Get("internal.unexpected");
        var marker = new CrashMarker(reason.Code, _clock.GetCurrentInstant().ToDateTimeOffset(), SupportReference.Create());
        try
        {
            WriteMarker(marker);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // The local entry below still records the crash; a read-only disk cannot hold the marker.
        }

        _store.Record(DiagnosticEventKind.CrashRecorded,
        [
            new KeyValuePair<string, object?>("reason.code", reason.Code),
            new KeyValuePair<string, object?>(DiagnosticEntryFormat.SupportReferenceField, marker.SupportReference),
        ]);
    }

    /// <summary>Generates a report the user asked for. It is local until it is previewed, approved and sent.</summary>
    public DiagnosticReportDraft CreateReport(DiagnosticReportOptions? options = null) =>
        BuildDraft(options ?? new DiagnosticReportOptions(), DiagnosticReportOrigin.UserRequested, null);

    /// <summary>
    /// The report of a crash an earlier run recorded, or null when there is none. It keeps the support reference given at
    /// the crash and, like every report, is sent only after the user has seen and approved it.
    /// </summary>
    public DiagnosticReportDraft? TryGetPendingCrashReport(DiagnosticReportOptions? options = null)
    {
        CrashMarker? marker = ReadMarker();
        return marker is null ? null : BuildDraft(options ?? new DiagnosticReportOptions(), DiagnosticReportOrigin.PreviousCrash, marker);
    }

    /// <summary>Discards the pending crash report without sending anything.</summary>
    public void DismissPendingCrashReport() => DeleteMarker();

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Consent.Changed -= OnConsentChanged;
        Verbose.Changed -= OnVerboseChanged;
        Verbose.Close();
    }

    internal object SendGate => Consent.SendGate;

    internal ApprovedDiagnosticReport Approve(string supportReference, DiagnosticReportOrigin origin, string text, string digest)
    {
        _store.Record(DiagnosticEventKind.ReportApproved,
            [new KeyValuePair<string, object?>(DiagnosticEntryFormat.SupportReferenceField, supportReference)]);
        return new ApprovedDiagnosticReport(this, supportReference, digest, origin, text, Consent.Revocations, _clock.GetTimestamp());
    }

    /// <summary>Null when an approval may still be used; otherwise the typed refusal and the event to record.</summary>
    internal TypedFailure? VerifyApproval(long revocationsAtApproval, MonotonicTimestamp approvedAt, out DiagnosticEventKind? eventKind)
    {
        eventKind = DiagnosticEventKind.ReportCancelled;
        if (Consent.Revocations != revocationsAtApproval)
        {
            return TypedFailure.Create("perm.approval_required");
        }

        if (_clock.GetElapsedTime(approvedAt, _clock.GetTimestamp()) >= _options.ApprovalLifetime)
        {
            return TypedFailure.Create("perm.approval_expired");
        }

        eventKind = null;
        return null;
    }

    internal void RecordReportRefusal(DiagnosticEventKind? kind, string supportReference)
    {
        if (kind is { } value)
        {
            _store.Record(value, [new KeyValuePair<string, object?>(DiagnosticEntryFormat.SupportReferenceField, supportReference)]);
        }
    }

    internal void RecordReportSent(string supportReference, DiagnosticReportOrigin origin)
    {
        _store.Record(DiagnosticEventKind.ReportSent,
            [new KeyValuePair<string, object?>(DiagnosticEntryFormat.SupportReferenceField, supportReference)]);
        if (origin == DiagnosticReportOrigin.PreviousCrash && ReadMarker() is { } marker
            && string.Equals(marker.SupportReference, supportReference, StringComparison.Ordinal))
        {
            DeleteMarker();
        }
    }

    private DiagnosticReportDraft BuildDraft(DiagnosticReportOptions options, DiagnosticReportOrigin origin, CrashMarker? crash)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MaximumLogEntries, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.MaximumLogEntries, LocalDiagnosticStore.MaxEntriesPerRead);
        IReadOnlyList<LocalDiagnosticEntry>? entries = null;
        int skipped = 0;
        int omitted = 0;
        if (options.IncludeLogEntries)
        {
            IReadOnlyList<LocalDiagnosticEntry> read = _store.ReadRecent(options.MaximumLogEntries, out skipped);
            entries = DiagnosticReportWriter.FitToByteLimit(read, out omitted);
        }

        string reference = crash?.SupportReference ?? SupportReference.Create();
        (string text, string digest) = DiagnosticReportWriter.Build(_options.Identity, Consent.State, origin, reference,
            _clock.GetCurrentInstant().ToDateTimeOffset(), crash, entries, skipped, omitted);
        _store.Record(DiagnosticEventKind.ReportGenerated,
            [new KeyValuePair<string, object?>(DiagnosticEntryFormat.SupportReferenceField, reference)]);
        return new DiagnosticReportDraft(this, reference, origin, text, digest);
    }

    private void OnConsentChanged(object? sender, EventArgs e) =>
        _store.Record(Consent.State == TelemetryConsentState.Granted ? DiagnosticEventKind.ConsentGranted : DiagnosticEventKind.ConsentRevoked);

    private void OnVerboseChanged(object? sender, VerboseSessionChangedEventArgs e)
    {
        DiagnosticEventKind kind = e.Change switch
        {
            VerboseSessionChange.Started => DiagnosticEventKind.VerboseStarted,
            VerboseSessionChange.Stopped => DiagnosticEventKind.VerboseStopped,
            _ => DiagnosticEventKind.VerboseExpired,
        };
        _store.Record(kind);
    }

    private string MarkerPath => Path.Combine(_directory, CrashMarkerFileName);

    private void WriteMarker(CrashMarker marker)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema", MarkerVersion);
            writer.WriteString("reason.code", marker.ReasonCode);
            writer.WriteString("recordedAt", marker.RecordedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            writer.WriteString(DiagnosticEntryFormat.SupportReferenceField, marker.SupportReference);
            writer.WriteEndObject();
        }

        System.IO.Directory.CreateDirectory(_directory);
        string temporary = MarkerPath + ".tmp";
        File.WriteAllBytes(temporary, buffer.WrittenSpan.ToArray());
        File.Move(temporary, MarkerPath, overwrite: true);
    }

    private CrashMarker? ReadMarker()
    {
        try
        {
            if (!File.Exists(MarkerPath))
            {
                return null;
            }

            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(MarkerPath), new JsonDocumentOptions { MaxDepth = 2 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("schema", out JsonElement schema) || !schema.TryGetInt32(out int version) || version != MarkerVersion
                || !root.TryGetProperty("reason.code", out JsonElement reason) || reason.ValueKind != JsonValueKind.String
                || !ReasonCodes.TryGet(reason.GetString() ?? string.Empty, out _)
                || !root.TryGetProperty("recordedAt", out JsonElement recorded) || recorded.ValueKind != JsonValueKind.String
                || !DateTimeOffset.TryParse(recorded.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset at)
                || !root.TryGetProperty(DiagnosticEntryFormat.SupportReferenceField, out JsonElement reference) || reference.ValueKind != JsonValueKind.String
                || !SupportReference.IsValid(reference.GetString()))
            {
                return null;
            }

            return new CrashMarker(reason.GetString()!, at, reference.GetString()!);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private void DeleteMarker()
    {
        try
        {
            File.Delete(MarkerPath);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // A marker that cannot be removed is shown again at the next start rather than lost.
        }
    }
}
