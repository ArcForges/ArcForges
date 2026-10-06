// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace ArcForges.Observability.Tests;

/// <summary>
/// WP-12.03 offline evidence for the head sample, the bounded diagnostic buffer, error and slow promotion of retained
/// spans only, explicit loss counters and the consent gate. Time is a hand-moved clock and exporters are capturing sinks;
/// nothing here talks to a telemetry backend.
/// </summary>
[SuppressMessage("Reliability", "CA2000", Justification = "Manual test spans are never listened to, hold no unmanaged resource and are collected with the test.")]
[Collection("Trace policy process listeners")]
public sealed class TracePolicyTests
{
    private static readonly TimeSpan Window = DiagnosticSpanBuffer.Retention;

    [Fact]
    public void HeadSelectionIsADeterministicFunctionOfTheTraceIdentifierAndTheRatio()
    {
        const int Traces = 1000;
        foreach (double ratio in new[] { 0d, 0.1d, 0.25d, 0.5d, 0.9d, 1d })
        {
            int selected = 0;
            for (int serial = 0; serial < Traces; serial++)
            {
                // Identifiers spread evenly over the whole 64-bit range the sampler reads.
                ulong low = (ulong)serial * (ulong.MaxValue / Traces);
                ActivityTraceId trace = TracePolicyRig.Trace(serial, low);
                bool first = TracePolicy.IsSelected(trace, ratio);
                Assert.Equal(first, TracePolicy.IsSelected(trace, ratio));
                if (first)
                {
                    selected++;
                }
            }

            Assert.InRange(selected, (int)Math.Floor(ratio * Traces) - 1, (int)Math.Ceiling(ratio * Traces) + 1);
        }

        Assert.False(TracePolicy.IsSelected(TracePolicyRig.Trace(1, 0), 0d));
        Assert.True(TracePolicy.IsSelected(TracePolicyRig.Trace(1, ulong.MaxValue), 1d));
        // A higher ratio never un-selects a trace a lower ratio selected.
        for (int serial = 0; serial < Traces; serial++)
        {
            ActivityTraceId trace = TracePolicyRig.Trace(serial, (ulong)serial * (ulong.MaxValue / Traces));
            Assert.True(!TracePolicy.IsSelected(trace, 0.3d) || TracePolicy.IsSelected(trace, 0.6d));
        }
    }

    [Fact]
    public void RatiosOutsideZeroToOneAndMissingRequiredSettingsAreRefused()
    {
        foreach (double bad in new[] { -0.01d, 1.01d, double.NaN, double.PositiveInfinity })
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new TracePolicyOptions(bad, TracePolicyRig.Slow));
            Assert.Throws<ArgumentOutOfRangeException>(() => new TracePolicyOptions(0.5d, TracePolicyRig.Slow)
            {
                SignalRules = [new SignalSamplingRule(SignalEventName.OperationFailed, bad)],
            });
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => new TracePolicyOptions(0.5d, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new TracePolicyOptions(0.5d, TimeSpan.FromSeconds(-1)));
        Assert.Throws<ArgumentException>(() => new TracePolicyOptions(0.5d, TracePolicyRig.Slow)
        {
            SignalRules = [new SignalSamplingRule(SignalEventName.OperationFailed, 0.1d), new SignalSamplingRule(SignalEventName.OperationFailed, 0.2d)],
        });
        Assert.Throws<ArgumentOutOfRangeException>(() => new TracePolicyOptions(0.5d, TracePolicyRig.Slow)
        {
            SignalRules = [new SignalSamplingRule((SignalEventName)99, 0.2d)],
        });
        Assert.Throws<ArgumentException>(() => new TracePolicyOptions(0.5d, TracePolicyRig.Slow)
        {
            RouteRules = [new RouteSamplingRule(RecordedRoute.Unmatched, 0.2d)],
        });
        Assert.Throws<ArgumentException>(() => new TracePolicyOptions(0.5d, TracePolicyRig.Slow)
        {
            RouteRules = [new RouteSamplingRule(null!, 0.2d)],
        });
        RecordedRoute route = RouteTemplateSet.Create(["/sampling/dup"]).Record("/sampling/dup");
        Assert.Throws<ArgumentException>(() => new TracePolicyOptions(0.5d, TracePolicyRig.Slow)
        {
            RouteRules = [new RouteSamplingRule(route, 0.1d), new RouteSamplingRule(route, 0.2d)],
        });
    }

    [Fact]
    public void TheDiagnosticBufferDefaultsToEightMebibytesAndNeverExceedsSixteen()
    {
        Assert.Equal(8L * 1024 * 1024, new TracePolicyOptions(0d, TracePolicyRig.Slow).BufferBytes);
        Assert.Equal(8L * 1024 * 1024, TracePolicyOptions.DefaultBufferBytes);
        Assert.Equal(16L * 1024 * 1024, TracePolicyOptions.HardBufferLimitBytes);
        Assert.Equal(TimeSpan.FromSeconds(30), DiagnosticSpanBuffer.Retention);

        Assert.Equal(TracePolicyOptions.HardBufferLimitBytes,
            new TracePolicyOptions(0d, TracePolicyRig.Slow) { BufferBytes = TracePolicyOptions.HardBufferLimitBytes }.BufferBytes);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new TracePolicyOptions(0d, TracePolicyRig.Slow) { BufferBytes = TracePolicyOptions.HardBufferLimitBytes + 1 });
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new TracePolicyOptions(0d, TracePolicyRig.Slow) { BufferBytes = TracePolicyOptions.MinimumBufferBytes - 1 });
    }

    [Fact]
    public void TheHeadRatioSelectsRootSpansAndAChildFollowsItsParent()
    {
        using var all = new TracePolicyRig(ratio: 1d);
        using var none = new TracePolicyRig(ratio: 0d);
        using var selectedSource = new ActivitySource("test.policy.head.on." + Guid.NewGuid().ToString("N"));
        using var unselectedSource = new ActivitySource("test.policy.head.off." + Guid.NewGuid().ToString("N"));
        using IDisposable selectedListener = all.Policy.Attach(candidate => ReferenceEquals(candidate, selectedSource));
        using IDisposable unselectedListener = none.Policy.Attach(candidate => ReferenceEquals(candidate, unselectedSource));

        using (Activity root = selectedSource.StartActivity("operation.completed")!)
        {
            Assert.True(root.Recorded);
            using Activity child = selectedSource.StartActivity("operation.completed")!;
            Assert.True(child.Recorded);
        }

        using (Activity root = unselectedSource.StartActivity("operation.completed")!)
        {
            Assert.False(root.Recorded);
            Assert.True(root.IsAllDataRequested);
            using Activity child = unselectedSource.StartActivity("operation.completed")!;
            Assert.False(child.Recorded);
        }

        Assert.Equal(2, all.Spans.Spans.Count);
        Assert.Equal(2, all.Statistics.HeadSampledSpans);
        Assert.Empty(none.Spans.Spans);
        Assert.Equal(2, none.Statistics.BufferedSpans);

        // A child continues the sampling decision of its (remote) parent, whatever this policy's own ratio is.
        var sampledParent = new ActivityContext(TracePolicyRig.Trace(1), ActivitySpanId.CreateRandom(), ActivityTraceFlags.Recorded, isRemote: true);
        var unsampledParent = new ActivityContext(TracePolicyRig.Trace(2), ActivitySpanId.CreateRandom(), ActivityTraceFlags.None, isRemote: true);
        using (Activity inherited = unselectedSource.StartActivity("operation.completed", ActivityKind.Server, sampledParent)!)
        {
            Assert.True(inherited.Recorded);
        }

        using (Activity inherited = selectedSource.StartActivity("operation.completed", ActivityKind.Server, unsampledParent)!)
        {
            Assert.False(inherited.Recorded);
        }

        Assert.Equal(1, none.Statistics.HeadSampledSpans);
        Assert.Single(none.Spans.Spans);
    }

    [Fact]
    public void ARootSpanIsHeadSelectedByItsRouteThenItsSignalThenTheDefaultRatio()
    {
        RecordedRoute route = RouteTemplateSet.Create(["/policy/route/{workspace}"]).Record("/policy/route/" + Guid.NewGuid().ToString("D"));
        using var rig = new TracePolicyRig(ratio: 0d,
            signalRules: [new SignalSamplingRule(SignalEventName.StorageCommitted, 1d)],
            routeRules: [new RouteSamplingRule(route, 1d)]);
        using var source = new ActivitySource("test.policy.rules." + Guid.NewGuid().ToString("N"));
        using IDisposable listening = rig.Policy.Attach(candidate => ReferenceEquals(candidate, source));
        KeyValuePair<string, object?>[] routeTag = [new("http.route", route.Template)];
        KeyValuePair<string, object?>[] otherRoute = [new("http.route", RecordedRoute.Unmatched.Template)];

        using (Activity? byDefault = source.StartActivity("operation.completed"))
        {
            Assert.False(byDefault!.Recorded);
            Assert.True(byDefault.IsAllDataRequested);
        }

        using (Activity? bySignal = source.StartActivity("storage.commit"))
        {
            Assert.True(bySignal!.Recorded);
        }

        using (Activity? byRoute = source.StartActivity("operation.completed", ActivityKind.Server, default(ActivityContext), routeTag))
        {
            Assert.True(byRoute!.Recorded);
        }

        using (Activity? unruledRoute = source.StartActivity("operation.completed", ActivityKind.Server, default(ActivityContext), otherRoute))
        {
            Assert.False(unruledRoute!.Recorded);
        }

        Assert.Equal(2, rig.Statistics.HeadSampledSpans);
        Assert.Equal(2, rig.Spans.Spans.Count);
        Assert.Equal(2, rig.Statistics.BufferedSpans);
    }

    [Fact]
    public void AnUnsampledHealthyTraceIsHeldNeverExportedAndDiscardedWhenItsRetentionEnds()
    {
        using var rig = new TracePolicyRig();
        ActivityTraceId trace = TracePolicyRig.Trace(1);
        for (int index = 0; index < 3; index++)
        {
            rig.Policy.OnSpanEnded(TracePolicyRig.Span(trace));
        }

        Assert.Empty(rig.Spans.Spans);
        Assert.Equal(3, rig.Statistics.BufferedSpans);
        Assert.True(rig.Statistics.BufferedBytes > 0);

        rig.Clock.Advance(Window - TimeSpan.FromMilliseconds(1));
        Assert.Equal(3, rig.Statistics.BufferedSpans);
        rig.Clock.Advance(TimeSpan.FromMilliseconds(1));

        TracePolicyStatistics expired = rig.Statistics;
        Assert.Equal(0, expired.BufferedSpans);
        Assert.Equal(3, expired.ExpiredUnpromotedSpans);
        Assert.Equal(1, expired.ClosedTraces);
        Assert.Equal(DiagnosticSpanBuffer.ClosedTraceOverhead, expired.BufferedBytes);
        Assert.Empty(rig.Spans.Spans);
        Assert.Equal(0, expired.SpansLostToOverflow);
        Assert.Equal(0, expired.LateSpans);
    }

    [Fact]
    public void AnErrorSpanPromotesOnlyTheSpansStillHeldAndThenTheRestOfItsTrace()
    {
        using var rig = new TracePolicyRig();
        ActivityTraceId trace = TracePolicyRig.Trace(2);
        Activity first = TracePolicyRig.Span(trace);
        Activity second = TracePolicyRig.Span(trace);
        Activity failing = TracePolicyRig.Span(trace, error: true);
        Activity unrelated = TracePolicyRig.Span(TracePolicyRig.Trace(3));
        Activity later = TracePolicyRig.Span(trace);

        rig.Policy.OnSpanEnded(first);
        rig.Policy.OnSpanEnded(unrelated);
        rig.Policy.OnSpanEnded(second);
        Assert.Empty(rig.Spans.Spans);

        rig.Policy.OnSpanEnded(failing);
        Assert.Equal([first.SpanId.ToHexString(), second.SpanId.ToHexString(), failing.SpanId.ToHexString()],
            rig.Spans.Spans.Select(span => span.SpanId));
        Assert.All(rig.Spans.Spans, span => Assert.Equal(trace.ToHexString(), span.TraceId));

        rig.Policy.OnSpanEnded(later);
        Assert.Equal(4, rig.Spans.Spans.Count);
        Assert.Equal(later.SpanId.ToHexString(), rig.Spans.Spans[3].SpanId);

        TracePolicyStatistics statistics = rig.Statistics;
        Assert.Equal(1, statistics.PromotedTraces);
        Assert.Equal(4, statistics.PromotedSpans);
        Assert.Equal(1, statistics.BufferedSpans);
        Assert.Equal(0, statistics.HeadSampledSpans);
        Assert.Equal(0, statistics.ErrorSpansNotRetained);
    }

    [Fact]
    public void ASlowSpanPromotesAndAFastOneDoesNot()
    {
        using var rig = new TracePolicyRig();
        ActivityTraceId slowTrace = TracePolicyRig.Trace(4);
        ActivityTraceId fastTrace = TracePolicyRig.Trace(5);

        rig.Policy.OnSpanEnded(TracePolicyRig.Span(fastTrace, duration: TracePolicyRig.Slow - TimeSpan.FromMilliseconds(1)));
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(slowTrace));
        Assert.Empty(rig.Spans.Spans);

        rig.Policy.OnSpanEnded(TracePolicyRig.Span(slowTrace, duration: TracePolicyRig.Slow));
        Assert.Equal(2, rig.Spans.Spans.Count);
        Assert.All(rig.Spans.Spans, span => Assert.Equal(slowTrace.ToHexString(), span.TraceId));
        Assert.Equal(1, rig.Statistics.PromotedTraces);
        Assert.Equal(1, rig.Statistics.BufferedSpans);
        Assert.Equal(0, rig.Statistics.ErrorFacts);
        Assert.Empty(rig.Events.Signals);
    }

    [Fact]
    public void ASampledTraceIsExportedWholeAndAnErrorInItStillRecordsItsFact()
    {
        using var rig = new TracePolicyRig();
        ActivityTraceId trace = TracePolicyRig.Trace(6);

        rig.Policy.OnSpanEnded(TracePolicyRig.Span(trace, sampled: true));
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(trace, sampled: true, error: true));

        Assert.Equal(2, rig.Spans.Spans.Count);
        Assert.Equal(2, rig.Statistics.HeadSampledSpans);
        Assert.Equal(0, rig.Statistics.BufferedSpans);
        Assert.Equal(1, rig.Statistics.ErrorFacts);
        Assert.Single(rig.Events.Signals);
    }

    [Fact]
    public void ThereIsNoAllErrorsRetentionGuaranteeAndEveryMissedErrorIsCountedAndStillRecordedAsAFact()
    {
        using var rig = new TracePolicyRig();
        ActivityTraceId expiredTrace = TracePolicyRig.Trace(7);
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(expiredTrace));
        rig.Clock.Advance(Window);

        // The trace's window has closed: its error span is late, so it is not exported and the loss is counted.
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(expiredTrace, error: true));
        Assert.Empty(rig.Spans.Spans);
        TracePolicyStatistics late = rig.Statistics;
        Assert.Equal(1, late.LateSpans);
        Assert.Equal(1, late.ErrorSpansNotRetained);
        Assert.Equal(1, late.ExpiredUnpromotedSpans);

        // The mandatory error fact is independent of that loss.
        Assert.Equal(1, late.ErrorFacts);
        StructuredSignal fact = Assert.Single(rig.Events.Signals);
        Assert.Equal(TracePolicy.ErrorFactEventName, fact.Name);
        Assert.Equal(SignalLevel.Error, fact.Level);

        // A healthy late span is also counted, but it is not an error span.
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(expiredTrace));
        Assert.Equal(2, rig.Statistics.LateSpans);
        Assert.Equal(1, rig.Statistics.ErrorSpansNotRetained);
    }

    [Fact]
    public void SpansEvictedByOverflowCannotBePromotedAndTheLossIsCounted()
    {
        Activity probe = TracePolicyRig.Span(TracePolicyRig.Trace(0));
        long cost = TracePolicyRig.Cost(probe);
        long budget = Math.Max(4 * (cost + DiagnosticSpanBuffer.EntryOverhead) + 10, TracePolicyOptions.MinimumBufferBytes);
        using var rig = new TracePolicyRig(bufferBytes: budget);
        const int Traces = 40;

        for (int serial = 0; serial < Traces; serial++)
        {
            rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(serial)));
            Assert.True(rig.Statistics.BufferedBytes <= budget);
        }

        TracePolicyStatistics full = rig.Statistics;
        Assert.True(full.SpansLostToOverflow > 0);
        Assert.Equal(Traces, full.BufferedSpans + full.SpansLostToOverflow);
        Assert.Equal(full.SpansLostToOverflow, full.TracesEvictedForOverflow);
        Assert.Equal(0, full.ExpiredUnpromotedSpans);

        // Oldest first: the first trace is gone, so promoting it exports only the promoting span; the newest is still held.
        Activity oldestError = TracePolicyRig.Span(TracePolicyRig.Trace(0), error: true);
        rig.Policy.OnSpanEnded(oldestError);
        Assert.Equal([oldestError.SpanId.ToHexString()], rig.Spans.Spans.Select(span => span.SpanId));

        Activity newestError = TracePolicyRig.Span(TracePolicyRig.Trace(Traces - 1), error: true);
        rig.Policy.OnSpanEnded(newestError);
        Assert.Equal(3, rig.Spans.Spans.Count);
        Assert.All(rig.Spans.Spans.Skip(1), span => Assert.Equal(TracePolicyRig.Trace(Traces - 1).ToHexString(), span.TraceId));
        Assert.True(rig.Statistics.BufferedBytes <= budget);
    }

    [Fact]
    public void ManyPromotedTracesStayInsideTheBufferBudgetBecauseTheirPromotionStateIsEvicted()
    {
        using var rig = new TracePolicyRig(bufferBytes: TracePolicyOptions.MinimumBufferBytes);
        for (int serial = 0; serial < 200; serial++)
        {
            rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(serial), error: true));
            Assert.True(rig.Statistics.BufferedBytes <= TracePolicyOptions.MinimumBufferBytes);
        }

        TracePolicyStatistics statistics = rig.Statistics;
        Assert.Equal(200, rig.Spans.Spans.Count);
        Assert.Equal(200, statistics.PromotedTraces);
        Assert.True(statistics.TracesEvictedForOverflow > 0);
        Assert.Equal(200, statistics.ErrorFacts);
    }

    [Fact]
    public void ASpanThatAloneCostsMoreThanTheBufferIsDroppedAndCounted()
    {
        using var rig = new TracePolicyRig(bufferBytes: TracePolicyOptions.MinimumBufferBytes);
        (string, object?)[] tags =
        [
            ("workspace.id", Guid.NewGuid().ToString("N")),
            ("task.id", Guid.NewGuid().ToString("N")),
            ("run.id", Guid.NewGuid().ToString("N")),
            ("command.id", Guid.NewGuid().ToString("N")),
            ("attempt.id", Guid.NewGuid().ToString("N")),
            ("correlation.id", Guid.NewGuid().ToString("N")),
            ("causation.id", Guid.NewGuid().ToString("N")),
            ("instance.id", Guid.NewGuid().ToString("N")),
        ];
        Activity big = TracePolicyRig.Span(TracePolicyRig.Trace(1), tags: tags);
        Assert.True(TracePolicyRig.Cost(big) + DiagnosticSpanBuffer.EntryOverhead > TracePolicyOptions.MinimumBufferBytes);

        rig.Policy.OnSpanEnded(big);
        Assert.Equal(1, rig.Statistics.OversizeSpans);
        Assert.Equal(0, rig.Statistics.BufferedSpans);
        Assert.Equal(0, rig.Statistics.BufferedBytes);

        // An oversize error span is still exported by promotion, because promotion never holds it.
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(2), error: true, tags: tags));
        Assert.Single(rig.Spans.Spans);
    }

    [Fact]
    public void ClosedTraceMarkersAreBoundedAndChargedToTheBuffer()
    {
        using var rig = new TracePolicyRig();
        int traces = DiagnosticSpanBuffer.MaximumClosedTraces + 76;
        for (int serial = 0; serial < traces; serial++)
        {
            rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(serial)));
        }

        rig.Clock.Advance(Window);
        TracePolicyStatistics statistics = rig.Statistics;

        Assert.Equal(DiagnosticSpanBuffer.MaximumClosedTraces, statistics.ClosedTraces);
        Assert.Equal(DiagnosticSpanBuffer.MaximumClosedTraces * DiagnosticSpanBuffer.ClosedTraceOverhead, statistics.BufferedBytes);
        Assert.Equal(traces, statistics.ExpiredUnpromotedSpans);
    }

    [Fact]
    public void WithConsentAbsentNothingIsExportedHeldCountedOrMeasured()
    {
        using var rig = new TracePolicyRig(consent: false);
        using TracePolicyRig.MeterReadings meters = rig.Listen();

        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(1), sampled: true));
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(2)));
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(3), sampled: true, error: true));
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(4), error: true));

        Assert.Empty(rig.Spans.Spans);
        Assert.Empty(rig.Events.Signals);
        Assert.Empty(meters.Collected);
        Assert.Empty(meters.Pull());
        TracePolicyStatistics statistics = rig.Statistics;
        Assert.Equal(4, statistics.ConsentSuppressedSpans);
        Assert.Equal(0, statistics.BufferedSpans);
        Assert.Equal(0, statistics.ErrorFacts);
        Assert.Equal(0, statistics.HeadSampledSpans);
        Assert.Equal(0, statistics.PromotedTraces);
    }

    [Fact]
    public void RevokingConsentPurgesWhatWasHeldAndGrantingItAgainDoesNotRestoreIt()
    {
        using var rig = new TracePolicyRig();
        ActivityTraceId trace = TracePolicyRig.Trace(1);
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(trace));
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(trace));
        Assert.Equal(2, rig.Statistics.BufferedSpans);

        rig.Consent.IsGranted = false;
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(trace, error: true));
        TracePolicyStatistics revoked = rig.Statistics;
        Assert.Equal(0, revoked.BufferedSpans);
        Assert.Equal(0, revoked.BufferedBytes);
        Assert.Equal(2, revoked.PurgedSpans);
        Assert.Equal(1, revoked.ConsentSuppressedSpans);
        Assert.Empty(rig.Spans.Spans);
        Assert.Empty(rig.Events.Signals);

        rig.Consent.IsGranted = true;
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(trace, error: true));
        Assert.Single(rig.Spans.Spans);
        Assert.Equal(1, rig.Statistics.ErrorFacts);
    }

    [Fact]
    public void ThePurgeCommandDiscardsEverythingHeldAtOnce()
    {
        using var rig = new TracePolicyRig();
        for (int serial = 0; serial < 5; serial++)
        {
            rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(serial)));
        }

        rig.Clock.Advance(Window);
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(100)));
        Assert.True(rig.Statistics.ClosedTraces > 0);

        rig.Policy.PurgeBuffer();
        TracePolicyStatistics statistics = rig.Statistics;
        Assert.Equal(0, statistics.BufferedSpans);
        Assert.Equal(0, statistics.BufferedBytes);
        Assert.Equal(0, statistics.ClosedTraces);
        Assert.Equal(1, statistics.PurgedSpans);
    }

    [Fact]
    public void ConsentIsReadLiveSoRevocationDuringAPromotionStopsTheRestOfTheExport()
    {
        var consent = new ToggleConsent(true);
        var sink = new RevokingSpanSink(consent);
        using var policy = new TracePolicy(new TracePolicyOptions(0d, TracePolicyRig.Slow),
            new ObservabilityContext(SignalApplicationDimension.ArcScope, new ArcForges.Contracts.Foundation.Values.InstanceId(Guid.NewGuid()), SignalEnvironment.Test),
            sink, new CapturingEventSink(), consent, new FakeClock());
        ActivityTraceId trace = TracePolicyRig.Trace(1);
        policy.OnSpanEnded(TracePolicyRig.Span(trace));
        policy.OnSpanEnded(TracePolicyRig.Span(trace));

        // The promotion releases three spans; consent is withdrawn while the first is being written.
        policy.OnSpanEnded(TracePolicyRig.Span(trace, error: true));

        Assert.Equal(1, sink.Written);
        Assert.Equal(2, policy.Statistics.ConsentSuppressedSpans);
        Assert.Equal(0, policy.Statistics.BufferedSpans);
    }

    [Fact]
    public void EveryErrorSpanRecordsOneRedactedFactWhateverItsSamplingOutcome()
    {
        const string Marker = "marker-secret-prompt-value-4711";
        using var rig = new TracePolicyRig();
        using TracePolicyRig.MeterReadings meters = rig.Listen();
        (string, object?)[] hostile =
        [
            ("authorization", "Bearer " + Marker),
            ("prompt", Marker),
            ("file.path", "C:/users/" + Marker),
            ("http.url", "https://host.test/" + Marker + "?q=" + Marker),
            ("exception.message", Marker),
            ("service.name", "Storage"),
            ("reason.code", "state.invalid_transition"),
        ];

        Activity sampled = TracePolicyRig.Span(TracePolicyRig.Trace(1), sampled: true, error: true, tags: hostile);
        sampled.SetStatus(ActivityStatusCode.Error, Marker);
        sampled.AddException(new InvalidOperationException(Marker));
        Activity unsampled = TracePolicyRig.Span(TracePolicyRig.Trace(2), error: true, tags: hostile);
        Activity heldFirst = TracePolicyRig.Span(TracePolicyRig.Trace(3), tags: hostile);
        Activity unsampledLate = TracePolicyRig.Span(TracePolicyRig.Trace(3), error: true, tags: hostile);

        rig.Policy.OnSpanEnded(sampled);
        rig.Policy.OnSpanEnded(unsampled);
        rig.Policy.OnSpanEnded(heldFirst);
        rig.Policy.OnSpanEnded(unsampledLate);

        Assert.Equal(3, rig.Statistics.ErrorFacts);
        Assert.Equal(3, rig.Events.Signals.Count);
        foreach (StructuredSignal fact in rig.Events.Signals)
        {
            Assert.Equal(TracePolicy.ErrorFactEventName, fact.Name);
            Assert.Equal(SignalLevel.Error, fact.Level);
            Assert.Equal("Storage", fact.Properties["service.name"]);
            Assert.Equal("state.invalid_transition", fact.Properties["reason.code"]);
            Assert.Equal(rig.Identity.BuildId, fact.Properties["build.id"]);
            Assert.Equal(rig.InstanceTag, fact.Properties["instance.id"]);
            Assert.Equal(fact.Properties.Count, RedactionProcessor.ScrubFields(fact.Properties).Count);
        }

        string exported = string.Concat(rig.Events.Signals.SelectMany(signal => signal.Properties.Select(property => property.Key + "=" + property.Value + ";"))
            .Concat(rig.Spans.Spans.SelectMany(span => span.Tags.Select(tag => tag.Key + "=" + tag.Value + ";")
                .Append(span.Name).Concat(span.Events.Select(item => item.Name)))));
        Assert.DoesNotContain(Marker, exported, StringComparison.Ordinal);
        Assert.DoesNotContain("authorization", exported, StringComparison.Ordinal);

        var counted = meters.Collected.Where(reading => reading.Instrument == "arcf_span_error_count").ToArray();
        Assert.Equal(3, counted.Length);
        Assert.All(counted, reading => Assert.Equal(["service.name=Storage"], reading.Labels));
    }

    [Fact]
    public void AnErrorFactCarriesAServiceLabelOnlyWhenTheSpanNamesAReviewedService()
    {
        using var rig = new TracePolicyRig();
        using TracePolicyRig.MeterReadings meters = rig.Listen();

        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(1), sampled: true, error: true));
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(2), sampled: true, error: true, tags: [("service.name", "C:/secret/path")]));
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(3), sampled: true, error: true, tags: [("service.name", "Cloud")]));

        var counted = meters.Collected.Where(reading => reading.Instrument == "arcf_span_error_count").ToArray();
        Assert.Equal(3, counted.Length);
        Assert.Equal(2, counted.Count(reading => reading.Labels.Length == 0));
        Assert.Single(counted, reading => reading.Labels.SequenceEqual(["service.name=Cloud"]));
    }

    [Fact]
    public void LossAndRetentionAreVisibleAsInstrumentsWithoutPointLabelsAndWithTheInstanceInTheirScope()
    {
        using var rig = new TracePolicyRig();
        using TracePolicyRig.MeterReadings meters = rig.Listen();
        ActivityTraceId expired = TracePolicyRig.Trace(1);
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(9), sampled: true));
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(expired));
        rig.Clock.Advance(Window);
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(expired, error: true));
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(2)));

        var readings = meters.Pull();
        Assert.Equal(TracePolicy.CounterNames.Append(TracePolicy.BufferBytesGaugeName).Order(StringComparer.Ordinal),
            readings.Select(reading => reading.Instrument).Order(StringComparer.Ordinal));
        Assert.All(readings, reading => Assert.Empty(reading.Labels));
        long Value(string name) => readings.Single(reading => reading.Instrument == name).Value;
        Assert.Equal(1, Value("arcf_trace_span_head_sampled"));
        Assert.Equal(1, Value("arcf_trace_span_lost_late"));
        Assert.Equal(1, Value("arcf_trace_error_span_not_retained"));
        Assert.Equal(0, Value("arcf_trace_span_lost_overflow"));
        Assert.Equal(rig.Statistics.BufferedBytes, Value(TracePolicy.BufferBytesGaugeName));
    }

    [Fact]
    public void AFailingExporterIsCountedAndNeverBreaksTheInstrumentedCode()
    {
        using var rig = new TracePolicyRig(ratio: 1d);
        rig.Spans.Fail = true;

        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(1), sampled: true));
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(2), error: true));

        Assert.Equal(2, rig.Statistics.ExportFailures);
        Assert.Equal(0, rig.Statistics.HeadSampledSpans);
        Assert.Empty(rig.Spans.Spans);
    }

    [Fact]
    public void ASignalEmitterSpanFlowsThroughTheAttachedPolicyAndAnErrorSignalLeavesItsFact()
    {
        using var rig = new TracePolicyRig(ratio: 1d);
        using IDisposable listening = rig.Policy.Attach(source => source.Name == SignalEmitter.SourceName);
        var sink = new CapturingEventSink();
        using var emitter = new SignalEmitter(sink);

        using (ObservabilityScope.Push(rig.Identity with { Service = SignalService.Sync }))
        {
            emitter.Emit(SignalEventName.OperationCompleted, SignalLevel.Information);
            emitter.Emit(SignalEventName.OperationFailed, SignalLevel.Error);
        }

        ScrubbedSpan[] mine = rig.Spans.Spans.Where(span => Equals(span.Tags.GetValueOrDefault("instance.id"), rig.InstanceTag)).ToArray();
        Assert.Equal(["operation.completed", "operation.failed"], mine.Select(span => span.Name).Order(StringComparer.Ordinal));
        Assert.Equal(ActivityStatusCode.Error, Assert.Single(mine, span => span.Name == "operation.failed").Status);
        StructuredSignal fact = Assert.Single(rig.Events.Signals,
            signal => Equals(signal.Properties.GetValueOrDefault("instance.id"), rig.InstanceTag));
        Assert.Equal(TracePolicy.ErrorFactEventName, fact.Name);
        Assert.Equal("Sync", fact.Properties["service.name"]);
    }

    [Fact]
    public void DisposingThePolicyStopsEveryListenerItCreatedAndRefusesNewWork()
    {
        var rig = new TracePolicyRig(ratio: 1d);
        using var source = new ActivitySource("test.policy.dispose." + Guid.NewGuid().ToString("N"));
        IDisposable listening = rig.Policy.Attach(candidate => ReferenceEquals(candidate, source));
        using (Activity? before = source.StartActivity("operation.completed"))
        {
            Assert.NotNull(before);
        }

        Assert.Single(rig.Spans.Spans);

        rig.Dispose();
        rig.Dispose();
        listening.Dispose();
        using (Activity? after = source.StartActivity("operation.completed"))
        {
            Assert.Null(after);
        }

        Assert.Single(rig.Spans.Spans);
        Assert.Throws<ObjectDisposedException>(() => rig.Policy.Attach(_ => true));
        Assert.Throws<ObjectDisposedException>(() => rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(1))));
    }
}

// This collection installs a listener on SignalEmitter's process-wide static ActivitySource. Running unrelated
// emitter tests concurrently would feed their real error activities into this policy and contaminate its facts.
[CollectionDefinition("Trace policy process listeners", DisableParallelization = true)]
[SuppressMessage("Maintainability", "CA1515", Justification = "xUnit requires collection definition classes to be public for discovery.")]
public sealed class TracePolicyProcessListeners;
