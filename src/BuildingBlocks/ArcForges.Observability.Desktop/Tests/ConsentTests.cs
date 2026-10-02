// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Xunit;

namespace ArcForges.Observability.Desktop.Tests;

[SuppressMessage("Trimming", "IL2026", Justification = "Test-only reflection over this repository's own assembly; tests are never trimmed.")]
[SuppressMessage("Trimming", "IL2075", Justification = "Test-only reflection over this repository's own assembly; tests are never trimmed.")]
public sealed class ConsentTests
{
    private const string ConsentFile = "telemetry-consent.json";

    [Fact]
    public void ConsentAbsentSendsNoSignalOffTheDeviceYetLocalDiagnosticsStillRecord()
    {
        using var directory = new TestDirectory();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);
        var transport = new RecordingTransport();
        ConsentGatedTelemetry telemetry = diagnostics.CreateTelemetry(transport);
        using var source = new ActivitySource("arcforges.test.consent-absent");
        using ActivityListener listener = Fixtures.ListenTo(source.Name);

        Assert.Equal(TelemetryConsentState.Absent, diagnostics.Consent.State);
        Assert.False(diagnostics.Consent.IsGranted);
        Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Information, count: 3);
        Fixtures.Emit(telemetry, SignalEventName.OperationFailed, SignalLevel.Error);
        using (Activity span = Fixtures.RunningSpan(source, "operation.run"))
        {
            telemetry.Export(span);
        }

        Assert.Equal(0, transport.Total);
        IReadOnlyList<LocalDiagnosticEntry> local = diagnostics.ReadRecent(100);
        Assert.Equal(4, local.Count);
        Assert.Equal(3, local.Count(entry => entry.Name == "operation.completed"));
        Assert.Contains(local, entry => entry.Name == "operation.failed" && entry.Level == SignalLevel.Error);

        // The same holds after consent was granted and revoked: revoked is not granted, and local diagnostics continue.
        diagnostics.Consent.Grant();
        diagnostics.Consent.Revoke();
        Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Information);
        Assert.Equal(0, transport.Total);
        Assert.Equal(5, diagnostics.ReadRecent(100).Count(entry => entry.Name == "operation.completed" || entry.Name == "operation.failed"));
    }

    [Fact]
    public void TheLibraryReferencesNoNetworkAssemblyHasNoPInvokeAndHoldsNoUploaderOrTransportField()
    {
        Assembly library = typeof(DesktopDiagnostics).Assembly;
        Assert.DoesNotContain(library.GetReferencedAssemblies(),
            reference => reference.Name!.StartsWith("System.Net", StringComparison.Ordinal));

        // A tripwire, not a proof: it catches an added network reference, native call or typed uploader or transport field.
        foreach (Type type in library.GetTypes())
        {
            foreach (MethodInfo method in type.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            {
                Assert.False(method.Attributes.HasFlag(MethodAttributes.PinvokeImpl), method.Name);
            }
        }

        foreach (Type type in library.GetTypes().Where(type => !type.IsDefined(typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute), inherit: false)))
        {
            foreach (FieldInfo field in type.GetFields(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            {
                Assert.NotEqual(typeof(IDiagnosticReportUploader), field.FieldType);
            }
        }

        // The owner of the diagnostics keeps no transport and no uploader: both are handed in per use, so an upload
        // cannot start from anywhere but the gated telemetry path and an approved report.
        foreach (FieldInfo field in typeof(DesktopDiagnostics).GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
        {
            Assert.NotEqual(typeof(IClientTelemetryTransport), field.FieldType);
        }

        foreach (PropertyInfo property in typeof(DesktopDiagnostics).GetProperties())
        {
            Assert.NotEqual(typeof(IClientTelemetryTransport), property.PropertyType);
            Assert.NotEqual(typeof(IDiagnosticReportUploader), property.PropertyType);
        }
    }

    [Fact]
    public void GrantedConsentSendsEventsAndSpansAndRevocationStopsThemAtOnce()
    {
        using var directory = new TestDirectory();
        var transport = new RecordingTransport();
        using var source = new ActivitySource("arcforges.test.consent-granted");
        using ActivityListener listener = Fixtures.ListenTo(source.Name);
        int changes = 0;

        using (DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path))
        {
            diagnostics.Consent.Changed += (_, _) => changes++;
            ConsentGatedTelemetry telemetry = diagnostics.CreateTelemetry(transport);

            diagnostics.Consent.Grant();
            Assert.Equal(TelemetryConsentState.Granted, diagnostics.Consent.State);
            Assert.NotNull(diagnostics.Consent.ChangedAt);
            Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Information, count: 2);
            using (Activity span = Fixtures.RunningSpan(source, "operation.run"))
            {
                span.SetTag("http.url", "https://example.invalid/path?token=MARKER-QUERY-TOKEN");
                span.SetTag("user.note", "MARKER-NOTE-CONTENT");
                telemetry.Export(span);
            }

            Assert.Equal(2, transport.Signals.Count);
            ScrubbedSpan sent = Assert.Single(transport.Spans);
            Assert.DoesNotContain(sent.Tags, tag => tag.Key is "http.url" or "user.note");
            Assert.DoesNotContain(sent.Tags.Values, value => value is string text && text.Contains("MARKER", StringComparison.Ordinal));

            diagnostics.Consent.Revoke();
            Assert.Equal(TelemetryConsentState.Revoked, diagnostics.Consent.State);
            Assert.Equal(2, changes);
            Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Information, count: 5);
            using (Activity span = Fixtures.RunningSpan(source, "operation.run"))
            {
                telemetry.Export(span);
            }

            Assert.Equal(2, transport.Signals.Count);
            Assert.Single(transport.Spans);
            Assert.Equal(7, diagnostics.ReadRecent(100).Count(entry => entry.Name == "operation.completed"));
        }

        // Revocation is durable: a restart does not resume sending.
        using DesktopDiagnostics restarted = Fixtures.Open(directory.Path);
        Assert.Equal(TelemetryConsentState.Revoked, restarted.Consent.State);
        Fixtures.Emit(restarted.CreateTelemetry(transport), SignalEventName.OperationCompleted, SignalLevel.Information);
        Assert.Equal(2, transport.Signals.Count);
    }

    [Fact]
    public async Task RevocationWaitsForASendInProgressAndNoSendStartsAfterItReturns()
    {
        using var directory = new TestDirectory();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);
        var transport = new RecordingTransport();
        ConsentGatedTelemetry telemetry = diagnostics.CreateTelemetry(transport);
        diagnostics.Consent.Grant();

        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        transport.OnSend = () =>
        {
            entered.Set();
            release.Wait(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        };

        Task sending = Task.Run(() => Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Information), TestContext.Current.CancellationToken);
        Assert.True(entered.Wait(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken));
        Task revoking = Task.Run(diagnostics.Consent.Revoke, TestContext.Current.CancellationToken);

        // The state is already Revoked, so nothing new can start, but the revocation has not returned: a send is in flight.
        SpinWait.SpinUntil(() => diagnostics.Consent.State == TelemetryConsentState.Revoked, TimeSpan.FromSeconds(30));
        Assert.Equal(TelemetryConsentState.Revoked, diagnostics.Consent.State);
        await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.False(revoking.IsCompleted);

        release.Set();
        await sending.ConfigureAwait(true);
        await revoking.ConfigureAwait(true);
        int afterRevocation = transport.Total;
        transport.OnSend = null;
        Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Information, count: 10);
        Assert.Equal(afterRevocation, transport.Total);
    }

    [Fact]
    public void AMissingCorruptOrUnknownConsentRecordIsNeverConsent()
    {
        string[] unreadable =
        [
            "not json at all",
            "{}",
            "{\"schema\":1,\"state\":\"granted\"}",
            "{\"schema\":2,\"state\":\"granted\",\"changedAt\":\"2026-10-02T08:00:00.0000000Z\"}",
            "{\"schema\":1,\"state\":\"everything\",\"changedAt\":\"2026-10-02T08:00:00.0000000Z\"}",
            "{\"schema\":1,\"state\":\"granted\",\"changedAt\":\"yesterday\"}",
        ];
        foreach (string record in unreadable)
        {
            using var directory = new TestDirectory();
            File.WriteAllText(Path.Combine(directory.Path, ConsentFile), record);
            using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);
            Assert.Equal(TelemetryConsentState.Absent, diagnostics.Consent.State);
            Assert.False(diagnostics.Consent.IsGranted);
        }

        using var valid = new TestDirectory();
        File.WriteAllText(Path.Combine(valid.Path, ConsentFile),
            "{\"schema\":1,\"state\":\"granted\",\"changedAt\":\"2026-10-02T08:00:00.0000000Z\"}");
        using DesktopDiagnostics granted = Fixtures.Open(valid.Path);
        Assert.Equal(TelemetryConsentState.Granted, granted.Consent.State);
    }

    [Fact]
    public void AGrantThatCannotBeStoredIsNotAGrant()
    {
        using var directory = new TestDirectory();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);

        // A directory where the record belongs makes the durable write fail on every platform.
        Directory.CreateDirectory(Path.Combine(directory.Path, ConsentFile));
        Exception failure = Assert.ThrowsAny<Exception>(diagnostics.Consent.Grant);
        Assert.True(failure is IOException or UnauthorizedAccessException);
        Assert.Equal(TelemetryConsentState.Absent, diagnostics.Consent.State);
        Assert.False(diagnostics.Consent.IsGranted);
    }

    [Fact]
    public async Task AGrantOvertakenByARevocationCannotLeaveTheProcessGranted()
    {
        using var directory = new TestDirectory();
        var transport = new RecordingTransport();
        Task? revoking = null;
        using (DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path))
        {
            ConsentGatedTelemetry telemetry = diagnostics.CreateTelemetry(transport);

            // Between the grant being stored and taking effect, a revocation begins and sets the state.
            diagnostics.Consent.BeforeGrantCommit = () =>
            {
                revoking = Task.Run(diagnostics.Consent.Revoke, TestContext.Current.CancellationToken);
                Assert.True(SpinWait.SpinUntil(() => diagnostics.Consent.State == TelemetryConsentState.Revoked, TimeSpan.FromSeconds(30)));
            };
            diagnostics.Consent.Grant();
            Assert.NotNull(revoking);
            await revoking!.ConfigureAwait(true);

            Assert.Equal(TelemetryConsentState.Revoked, diagnostics.Consent.State);
            Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Information, count: 3);
            Assert.Equal(0, transport.Total);
        }

        // The stored record agrees with memory, so a restart does not resume sending either.
        using DesktopDiagnostics restarted = Fixtures.Open(directory.Path);
        Assert.Equal(TelemetryConsentState.Revoked, restarted.Consent.State);
    }

    [Fact]
    public void ARevocationThatCannotBeStoredRemovesTheRecordSoARestartIsNotGranted()
    {
        using var directory = new TestDirectory();
        using (DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path))
        {
            diagnostics.Consent.Grant();
            Assert.True(File.Exists(Path.Combine(directory.Path, ConsentFile)));

            // A directory where the temporary record belongs makes storing the revocation fail.
            Directory.CreateDirectory(Path.Combine(directory.Path, ConsentFile + ".tmp"));
            diagnostics.Consent.Revoke();

            Assert.Equal(TelemetryConsentState.Revoked, diagnostics.Consent.State);
            Assert.False(File.Exists(Path.Combine(directory.Path, ConsentFile)));
        }

        using DesktopDiagnostics restarted = Fixtures.Open(directory.Path);
        Assert.NotEqual(TelemetryConsentState.Granted, restarted.Consent.State);
        Assert.False(restarted.Consent.IsGranted);
    }

    [Fact]
    public void DetailBelowInformationStaysLocalEvenWhileConsentIsGrantedAndAVerboseSessionRuns()
    {
        using var directory = new TestDirectory();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);
        var transport = new RecordingTransport();
        ConsentGatedTelemetry telemetry = diagnostics.CreateTelemetry(transport);
        diagnostics.Consent.Grant();
        diagnostics.Verbose.Start(TimeSpan.FromMinutes(5));

        Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Debug);
        Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Trace);
        Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Warning);

        Assert.Equal([SignalLevel.Warning], transport.Signals.Select(signal => signal.Level).ToArray());
        Assert.Equal(3, diagnostics.ReadRecent(100).Count(entry => entry.Name == "operation.completed"));
    }

    [Fact]
    public void TheConsentIsTheLiveStateTheObservabilityTracePolicyReadsAndAnnouncesEachChange()
    {
        using var directory = new TestDirectory();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);
        var announced = new List<bool>();
        diagnostics.Consent.Changed += (_, _) => announced.Add(ReadLive(diagnostics.Consent));

        Assert.False(ReadLive(diagnostics.Consent));
        diagnostics.Consent.Grant();
        Assert.True(ReadLive(diagnostics.Consent));
        diagnostics.Consent.Revoke();
        Assert.False(ReadLive(diagnostics.Consent));

        // A host drops what it queued when it is told consent is no longer granted; each announcement already shows the new state.
        Assert.Equal([true, false], announced);
    }

    private static bool ReadLive(TelemetryConsent consent)
    {
        // Read through the interface the Observability trace policy consumes.
        ITelemetryConsent[] asInterface = [consent];
        return asInterface[0].IsGranted;
    }
}
