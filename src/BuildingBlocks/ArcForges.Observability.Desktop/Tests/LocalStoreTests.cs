// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;
using Xunit;

namespace ArcForges.Observability.Desktop.Tests;

public sealed class LocalStoreTests
{
    private sealed class CapturingSink : IStructuredEventSink
    {
        public StructuredSignal? Signal { get; private set; }

        public void Write(StructuredSignal signal) => Signal = signal;
    }

    [Fact]
    public void TheLocalLogRotatesWithinItsSizeCountAndAgeBudget()
    {
        using var directory = new TestDirectory();
        var time = new ManualTimeProvider();
        DesktopDiagnosticsOptions options = Fixtures.Options(directory.Path, time) with
        {
            MaximumSegmentBytes = 4 * 1024,
            MaximumSegments = 3,
            MaximumAge = TimeSpan.FromHours(1),
        };

        using (DesktopDiagnostics diagnostics = DesktopDiagnostics.Open(options))
        {
            Fixtures.Emit(diagnostics.LocalSink, SignalEventName.OperationCompleted, SignalLevel.Information, count: 200);

            string[] segments = Directory.GetFiles(directory.Path, "diagnostics-*.jsonl");
            Assert.InRange(segments.Length, 2, 3);
            Assert.All(segments, segment => Assert.True(new FileInfo(segment).Length <= 4 * 1024));
            IReadOnlyList<LocalDiagnosticEntry> recent = diagnostics.ReadRecent(1000);
            Assert.InRange(recent.Count, 1, 199);
            Assert.True(recent.Zip(recent.Skip(1)).All(pair => pair.First.OccurredAt <= pair.Second.OccurredAt));
        }

        // Older than the age budget: the segments are removed when the diagnostics are next opened.
        foreach (string segment in Directory.GetFiles(directory.Path, "diagnostics-*.jsonl"))
        {
            File.SetLastWriteTimeUtc(segment, time.GetUtcNow().UtcDateTime - TimeSpan.FromHours(2));
        }

        using DesktopDiagnostics reopened = DesktopDiagnostics.Open(options);
        Assert.Empty(Directory.GetFiles(directory.Path, "diagnostics-*.jsonl"));
        Assert.Empty(reopened.ReadRecent(10));
    }

    [Fact]
    public void StoredEntriesRoundTripEveryReviewedDimension()
    {
        using var directory = new TestDirectory();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);
        ObservabilityContext context = new(SignalApplicationDimension.ArcScope, new InstanceId(Guid.NewGuid()), SignalEnvironment.Test)
        {
            ActorReference = "sha256:" + new string('a', 64),
            Workspace = new WorkspaceId(Guid.NewGuid()),
            Transport = SignalTransport.LocalRpc,
            Service = SignalService.Storage,
            Interface = SignalInterface.ResourceStore,
            Method = SignalMethod.Commit,
            Capability = SignalCapability.ResourceWrite,
            RedactedResourceReference = "sha256:" + new string('b', 64),
            Command = new CommandId(Guid.NewGuid()),
            Task = TaskId.New(),
            Run = RunId.New(),
            Attempt = AttemptId.New(),
            Correlation = new CorrelationId(Guid.NewGuid()),
            CausationId = Guid.NewGuid(),
            ExpectedRevision = 4,
            ResultRevision = 5,
            Duration = TimeSpan.FromMilliseconds(12.5),
            QueueTime = TimeSpan.FromMilliseconds(2),
            ResultCode = SignalResultCode.Succeeded,
            ReasonCode = ReasonCodes.Get("state.invalid_transition"),
            NativeAbiVersion = new NativeAbiVersion(1, 2),
            NativeAbiBuildId = "local.local",
            ReconnectCount = 1,
            SequenceGapCount = 2,
        };
        var capture = new CapturingSink();
        using var emitter = new SignalEmitter(capture);
        using (ObservabilityScope.Push(context))
        {
            emitter.Emit(SignalEventName.StorageCommitted, SignalLevel.Information);
        }

        diagnostics.LocalSink.Write(capture.Signal!);

        LocalDiagnosticEntry entry = Assert.Single(diagnostics.ReadRecent(10));
        Assert.Equal("storage.commit", entry.Name);
        Assert.Equal(SignalLevel.Information, entry.Level);
        Assert.Equal(DiagnosticTier.LocalMinimal, entry.Tier);
        Assert.Equal(capture.Signal!.Properties.Count, entry.Fields.Count);
        foreach (KeyValuePair<string, object?> expected in capture.Signal.Properties)
        {
            Assert.True(entry.Fields.TryGetValue(expected.Key, out object? actual), expected.Key);
            Assert.Equal(Convert.ToString(expected.Value, System.Globalization.CultureInfo.InvariantCulture),
                Convert.ToString(actual, System.Globalization.CultureInfo.InvariantCulture));
        }

        Assert.IsType<double>(entry.Fields["duration.ms"]);
        Assert.IsType<double>(entry.Fields["queue.time.ms"]);
    }

    [Fact]
    public void TheLocalViewIsBoundedAndOrderedOldestFirstAndOptionsAreValidated()
    {
        using var directory = new TestDirectory();
        var time = new ManualTimeProvider();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path, time);
        for (int index = 0; index < 5; index++)
        {
            Fixtures.Emit(diagnostics.LocalSink, SignalEventName.OperationCompleted, SignalLevel.Information);
            Fixtures.Emit(diagnostics.LocalSink, SignalEventName.HealthChanged, SignalLevel.Information);
        }

        IReadOnlyList<LocalDiagnosticEntry> last = diagnostics.ReadRecent(3);
        Assert.Equal(3, last.Count);
        Assert.Equal(["health.changed", "operation.completed", "health.changed"], last.Select(entry => entry.Name).ToArray());
        Assert.Throws<ArgumentOutOfRangeException>(() => diagnostics.ReadRecent(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => diagnostics.ReadRecent(1001));

        DesktopDiagnosticsOptions valid = Fixtures.Options(directory.Path);
        Assert.Throws<ArgumentOutOfRangeException>(() => DesktopDiagnostics.Open(valid with { MaximumSegmentBytes = 1 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => DesktopDiagnostics.Open(valid with { MaximumSegments = 1 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => DesktopDiagnostics.Open(valid with { MaximumAge = TimeSpan.FromDays(365) }));
        Assert.Throws<ArgumentOutOfRangeException>(() => DesktopDiagnostics.Open(valid with { ApprovalLifetime = TimeSpan.FromDays(1) }));
        Assert.Throws<ArgumentException>(() => DesktopDiagnostics.Open(valid with { Directory = " " }));
    }
}
