// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.Observability.Desktop.Tests;

public sealed class VerboseSessionTests
{
    [Fact]
    public void AVerboseSessionKeepsDetailLocallyOnlyWhileActiveAndEndsOnItsOwn()
    {
        using var directory = new TestDirectory();
        var time = new ManualTimeProvider();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path, time);
        var changes = new List<VerboseSessionChange>();
        diagnostics.Verbose.Changed += (_, change) => changes.Add(change.Change);

        Assert.False(diagnostics.Verbose.IsActive);
        Fixtures.Emit(diagnostics.LocalSink, SignalEventName.OperationCompleted, SignalLevel.Debug);
        Assert.DoesNotContain(diagnostics.ReadRecent(100), entry => entry.Level == SignalLevel.Debug);

        VerboseSessionState started = diagnostics.Verbose.Start(TimeSpan.FromMinutes(10));
        Assert.True(started.IsActive);
        Assert.Equal(TimeSpan.FromMinutes(10), started.Remaining);
        Assert.NotNull(started.ExpiresAt);
        Fixtures.Emit(diagnostics.LocalSink, SignalEventName.OperationCompleted, SignalLevel.Debug);
        LocalDiagnosticEntry detail = Assert.Single(diagnostics.ReadRecent(100), entry => entry.Level == SignalLevel.Debug);
        Assert.Equal(DiagnosticTier.VerboseSession, detail.Tier);

        time.Advance(TimeSpan.FromMinutes(4));
        Assert.Equal(TimeSpan.FromMinutes(6), diagnostics.Verbose.State.Remaining);

        // The period ends by itself: the timer fires, nobody has to poll or stop it.
        time.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal([VerboseSessionChange.Started, VerboseSessionChange.Expired], changes);
        Assert.False(diagnostics.Verbose.IsActive);
        Fixtures.Emit(diagnostics.LocalSink, SignalEventName.OperationCompleted, SignalLevel.Debug);
        Assert.Single(diagnostics.ReadRecent(100), entry => entry.Level == SignalLevel.Debug);
        Assert.Contains(diagnostics.ReadRecent(100), entry => entry.Name == "diagnostics.verbose.expired");
        Assert.Equal(2, changes.Count);
    }

    [Fact]
    public void AWallClockAdjustmentCannotExtendASessionAndExpiryNeedsNoTimer()
    {
        using var directory = new TestDirectory();
        var time = new ManualTimeProvider();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path, time);
        diagnostics.Verbose.Start(TimeSpan.FromMinutes(5));

        // The monotonic clock passes the period while the wall clock is set back an hour.
        time.Advance(TimeSpan.FromMinutes(5), TimeSpan.FromHours(-1));

        Assert.False(diagnostics.Verbose.IsActive);
        Fixtures.Emit(diagnostics.LocalSink, SignalEventName.OperationCompleted, SignalLevel.Trace);
        Assert.DoesNotContain(diagnostics.ReadRecent(100), entry => entry.Level == SignalLevel.Trace);
    }

    [Fact]
    public void DisposingTheDiagnosticsEndsAVerboseSessionAndRefusesANewOne()
    {
        using var directory = new TestDirectory();
        var time = new ManualTimeProvider();
        DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path, time);
        diagnostics.Verbose.Start(TimeSpan.FromMinutes(10));
        Assert.True(diagnostics.Verbose.IsActive);

        diagnostics.Dispose();
        diagnostics.Dispose();

        Assert.False(diagnostics.Verbose.IsActive);
        Assert.Throws<ObjectDisposedException>(() => diagnostics.Verbose.Start(TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void AVerboseSessionIsBoundedStoppableAndNeverEnablesUpload()
    {
        using var directory = new TestDirectory();
        var time = new ManualTimeProvider();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path, time);
        var transport = new RecordingTransport();
        ConsentGatedTelemetry telemetry = diagnostics.CreateTelemetry(transport);
        var changes = new List<VerboseSessionChange>();
        diagnostics.Verbose.Changed += (_, change) => changes.Add(change.Change);

        Assert.Throws<ArgumentOutOfRangeException>(() => diagnostics.Verbose.Start(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => diagnostics.Verbose.Start(TimeSpan.FromSeconds(-1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => diagnostics.Verbose.Start(VerboseDiagnosticSession.MaximumDuration + TimeSpan.FromTicks(1)));
        Assert.False(diagnostics.Verbose.IsActive);

        Assert.True(diagnostics.Verbose.Start(VerboseDiagnosticSession.MaximumDuration).IsActive);
        Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Debug, count: 3);
        Assert.Equal(3, diagnostics.ReadRecent(100).Count(entry => entry.Level == SignalLevel.Debug));
        Assert.Equal(0, transport.Total);
        Assert.Equal(TelemetryConsentState.Absent, diagnostics.Consent.State);

        Assert.False(diagnostics.Verbose.Stop().IsActive);
        Assert.False(diagnostics.Verbose.IsActive);
        Assert.Equal([VerboseSessionChange.Started, VerboseSessionChange.Stopped], changes);
        Fixtures.Emit(telemetry, SignalEventName.OperationCompleted, SignalLevel.Debug);
        Assert.Equal(3, diagnostics.ReadRecent(100).Count(entry => entry.Level == SignalLevel.Debug));
        Assert.Equal(0, transport.Total);
        Assert.Contains(diagnostics.ReadRecent(100), entry => entry.Name == "diagnostics.verbose.stopped");
    }
}
