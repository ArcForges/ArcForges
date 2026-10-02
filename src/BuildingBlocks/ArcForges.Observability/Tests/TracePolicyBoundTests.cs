// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace ArcForges.Observability.Tests;

/// <summary>
/// The guards behind "bounded cost": each test drives one way the buffer could outgrow its budget, so that removing the
/// guard that stops it fails a test. Also the route-over-signal precedence, the consent revocation contract and the
/// concurrent invariants.
/// </summary>
[SuppressMessage("Reliability", "CA2000", Justification = "Manual test spans are never listened to, hold no unmanaged resource and are collected with the test.")]
public sealed class TracePolicyBoundTests
{
    private const long Budget = TracePolicyOptions.MinimumBufferBytes;
    private static readonly TimeSpan Window = DiagnosticSpanBuffer.Retention;

    [Fact]
    public void OneFloodingTraceNeverGrowsTheBufferPastItsBudgetAndItsOldestSpansAreCountedAsLost()
    {
        using var rig = new TracePolicyRig(bufferBytes: Budget);
        ActivityTraceId trace = TracePolicyRig.Trace(1);

        for (int span = 0; span < 200; span++)
        {
            rig.Policy.OnSpanEnded(TracePolicyRig.Span(trace));
            Assert.InRange(rig.Statistics.BufferedBytes, 1, Budget);
        }

        TracePolicyStatistics flooded = rig.Statistics;
        Assert.True(flooded.SpansLostToOverflow > 0);
        Assert.True(flooded.BufferedSpans > 0);
        Assert.Equal(200, flooded.BufferedSpans + flooded.SpansLostToOverflow);

        // The newest spans are the ones kept: promoting the trace exports exactly them, in order, and the promoting span.
        Activity failing = TracePolicyRig.Span(trace, error: true);
        rig.Policy.OnSpanEnded(failing);
        Assert.Equal(flooded.BufferedSpans + 1, rig.Spans.Spans.Count);
        Assert.Equal(failing.SpanId.ToHexString(), rig.Spans.Spans[^1].SpanId);
    }

    [Fact]
    public void ASpanTooLargeForTheBufferIsRefusedEvenWhenItsTraceAlreadyHoldsOthers()
    {
        using var rig = new TracePolicyRig(bufferBytes: Budget);
        ActivityTraceId trace = TracePolicyRig.Trace(1);
        Activity small = TracePolicyRig.Span(trace);
        Activity big = TracePolicyRig.Span(trace, tags: OversizeTags());
        Assert.True(TracePolicyRig.Cost(big) + DiagnosticSpanBuffer.EntryOverhead > Budget);

        rig.Policy.OnSpanEnded(small);
        long before = rig.Statistics.BufferedBytes;
        rig.Policy.OnSpanEnded(big);

        TracePolicyStatistics statistics = rig.Statistics;
        Assert.Equal(1, statistics.OversizeSpans);
        Assert.Equal(1, statistics.BufferedSpans);
        Assert.Equal(before, statistics.BufferedBytes);
        Assert.InRange(statistics.BufferedBytes, 1, Budget);
        Assert.Equal(0, statistics.SpansLostToOverflow);

        // The refused span did not disturb the span already held.
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(trace, error: true));
        Assert.Equal(2, rig.Spans.Spans.Count);
        Assert.Equal(small.SpanId.ToHexString(), rig.Spans.Spans[0].SpanId);
    }

    [Fact]
    public void ClosedTraceMarkersAreEvictedBeforeAnyHeldSpanWhenTheBufferNeedsRoom()
    {
        using var rig = new TracePolicyRig(bufferBytes: Budget);
        const int Cycles = 60;

        for (int cycle = 0; cycle < Cycles; cycle++)
        {
            rig.Clock.Advance(Window);
            Assert.InRange(rig.Statistics.BufferedBytes, 0, Budget);
            rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(cycle)));
            Assert.InRange(rig.Statistics.BufferedBytes, 1, Budget);
        }

        TracePolicyStatistics statistics = rig.Statistics;
        Assert.Equal(Cycles - 1, statistics.ExpiredUnpromotedSpans);
        Assert.Equal(0, statistics.SpansLostToOverflow);
        Assert.Equal(0, statistics.TracesEvictedForOverflow);
        Assert.Equal(1, statistics.BufferedSpans);
        Assert.True(statistics.ClosedTraces < Cycles - 1, "markers were forgotten to make room");
        Assert.True(statistics.ClosedTraces * DiagnosticSpanBuffer.ClosedTraceOverhead <= Budget);
    }

    [Fact]
    public void ConcurrentOfferingPromotionPurgingAndReadingKeepTheBoundAndAccountForEverySpan()
    {
        const int Threads = 8;
        const int Operations = 1500;
        const long Capacity = 8192;
        using var rig = new TracePolicyRig(bufferBytes: Capacity);
        long offered = 0;
        var failures = new ConcurrentBag<Exception>();

        [SuppressMessage("Design", "CA1031", Justification = "A worker thread must hand every failure back to the test thread, whatever its type.")]
        void Work(int seed)
        {
            try
            {
                uint state = (uint)seed * 2654435761u;
                int Next(int minimum, int maximum)
                {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    return minimum + (int)(state % (uint)(maximum - minimum));
                }

                for (int operation = 0; operation < Operations; operation++)
                {
                    ActivityTraceId trace = TracePolicyRig.Trace(Next(0, 60));
                    int choice = Next(0, 100);
                    if (choice < 80)
                    {
                        rig.Policy.OnSpanEnded(TracePolicyRig.Span(trace));
                        Interlocked.Increment(ref offered);
                    }
                    else if (choice < 90)
                    {
                        rig.Policy.OnSpanEnded(TracePolicyRig.Span(trace, error: true));
                        Interlocked.Increment(ref offered);
                    }
                    else if (choice < 93)
                    {
                        rig.Policy.PurgeBuffer();
                    }
                    else if (choice < 96)
                    {
                        rig.Clock.Advance(TimeSpan.FromSeconds(Next(1, 20)));
                    }
                    else
                    {
                        TracePolicyStatistics reading = rig.Statistics;
                        Assert.InRange(reading.BufferedBytes, 0, Capacity);
                        Assert.True(reading.BufferedSpans >= 0);
                    }
                }
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        Thread[] threads = Enumerable.Range(0, Threads).Select(index => new Thread(() => Work(index + 1))).ToArray();
        foreach (Thread thread in threads)
        {
            thread.Start();
        }

        foreach (Thread thread in threads)
        {
            thread.Join();
        }

        Assert.Empty(failures);
        TracePolicyStatistics statistics = rig.Statistics;
        Assert.InRange(statistics.BufferedBytes, 0, Capacity);
        Assert.Equal(offered,
            statistics.PromotedSpans + statistics.BufferedSpans + statistics.SpansLostToOverflow + statistics.ExpiredUnpromotedSpans
            + statistics.PurgedSpans + statistics.LateSpans + statistics.OversizeSpans);
        Assert.Equal(statistics.PromotedSpans, rig.Spans.Spans.Count);
        Assert.Equal(0, statistics.ExportFailures);
    }

    [Fact]
    public void ARouteRuleOutranksASignalRuleWhicheverRatioIsHigher()
    {
        RecordedRoute routeOn = RouteTemplateSet.Create(["/precedence/on/{workspace}"]).Record("/precedence/on/" + Guid.NewGuid().ToString("D"));
        RecordedRoute routeOff = RouteTemplateSet.Create(["/precedence/off/{workspace}"]).Record("/precedence/off/" + Guid.NewGuid().ToString("D"));

        using var routeWins = new TracePolicyRig(ratio: 0d,
            signalRules: [new SignalSamplingRule(SignalEventName.StorageCommitted, 0d)],
            routeRules: [new RouteSamplingRule(routeOn, 1d)]);
        using var signalWouldWin = new TracePolicyRig(ratio: 1d,
            signalRules: [new SignalSamplingRule(SignalEventName.StorageCommitted, 1d)],
            routeRules: [new RouteSamplingRule(routeOff, 0d)]);
        using var onSource = new ActivitySource("test.policy.precedence.on." + Guid.NewGuid().ToString("N"));
        using var offSource = new ActivitySource("test.policy.precedence.off." + Guid.NewGuid().ToString("N"));
        using IDisposable onListener = routeWins.Policy.Attach(candidate => ReferenceEquals(candidate, onSource));
        using IDisposable offListener = signalWouldWin.Policy.Attach(candidate => ReferenceEquals(candidate, offSource));

        // Both rules apply to the span; the route rule decides, in both directions.
        using (Activity? span = onSource.StartActivity("storage.commit", ActivityKind.Server, default(ActivityContext), [new("http.route", routeOn.Template)]))
        {
            Assert.True(span!.Recorded);
        }

        using (Activity? span = offSource.StartActivity("storage.commit", ActivityKind.Server, default(ActivityContext), [new("http.route", routeOff.Template)]))
        {
            Assert.False(span!.Recorded);
        }

        // With no route tag, the signal rule and then the default decide.
        using (Activity? span = onSource.StartActivity("storage.commit"))
        {
            Assert.False(span!.Recorded);
        }

        using (Activity? span = offSource.StartActivity("storage.commit"))
        {
            Assert.True(span!.Recorded);
        }
    }

    [Fact]
    public void RevokingAndRegrantingConsentWithNothingInBetweenKeepsHeldSpansSoTheHostMustPurgeAtRevocation()
    {
        ActivityTraceId trace = TracePolicyRig.Trace(1);

        // Consent has no change notification: with no span and no purge in between, nothing observes the revocation.
        using (var unobserved = new TracePolicyRig())
        {
            unobserved.Policy.OnSpanEnded(TracePolicyRig.Span(trace));
            unobserved.Policy.OnSpanEnded(TracePolicyRig.Span(trace));
            unobserved.Consent.IsGranted = false;
            unobserved.Consent.IsGranted = true;
            unobserved.Policy.OnSpanEnded(TracePolicyRig.Span(trace, error: true));
            Assert.Equal(3, unobserved.Spans.Spans.Count);
        }

        // The host's purge at revocation closes that gap.
        using (var purged = new TracePolicyRig())
        {
            purged.Policy.OnSpanEnded(TracePolicyRig.Span(trace));
            purged.Policy.OnSpanEnded(TracePolicyRig.Span(trace));
            purged.Consent.IsGranted = false;
            purged.Policy.PurgeBuffer();
            purged.Consent.IsGranted = true;
            purged.Policy.OnSpanEnded(TracePolicyRig.Span(trace, error: true));
            Assert.Single(purged.Spans.Spans);
            Assert.Equal(2, purged.Statistics.PurgedSpans);
        }

        // So does an exporter polling the instruments while consent is absent.
        using (var polled = new TracePolicyRig())
        using (TracePolicyRig.MeterReadings meters = polled.Listen())
        {
            polled.Policy.OnSpanEnded(TracePolicyRig.Span(trace));
            polled.Policy.OnSpanEnded(TracePolicyRig.Span(trace));
            polled.Consent.IsGranted = false;
            Assert.Empty(meters.Pull());
            polled.Consent.IsGranted = true;
            polled.Policy.OnSpanEnded(TracePolicyRig.Span(trace, error: true));
            Assert.Single(polled.Spans.Spans);
            Assert.Equal(2, polled.Statistics.PurgedSpans);
        }
    }

    [Fact]
    public void TheAttachedListenerKeepsRecordingAndPropagatingTheHeadFlagWhileConsentIsAbsentButExportsNothing()
    {
        using var rig = new TracePolicyRig(ratio: 1d, consent: false);
        using var source = new ActivitySource("test.policy.noconsent." + Guid.NewGuid().ToString("N"));
        using IDisposable listening = rig.Policy.Attach(candidate => ReferenceEquals(candidate, source));

        using (Activity? span = source.StartActivity("operation.completed"))
        {
            Assert.NotNull(span);
            Assert.True(span.Recorded);
            Assert.True(span.IsAllDataRequested);
        }

        Assert.Empty(rig.Spans.Spans);
        Assert.Empty(rig.Events.Signals);
        Assert.Equal(1, rig.Statistics.ConsentSuppressedSpans);
        Assert.Equal(0, rig.Statistics.HeadSampledSpans);
    }

    [Fact]
    public void AFailingEventSinkIsCountedAsAFailureNotAsARecordedFactAndTheSpanIsStillExported()
    {
        using var rig = new TracePolicyRig(ratio: 1d);
        using TracePolicyRig.MeterReadings meters = rig.Listen();
        rig.Events.Fail = true;

        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(1), sampled: true, error: true));

        TracePolicyStatistics statistics = rig.Statistics;
        Assert.Equal(0, statistics.ErrorFacts);
        Assert.Equal(1, statistics.ExportFailures);
        Assert.Equal(1, statistics.HeadSampledSpans);
        Assert.Single(rig.Spans.Spans);
        Assert.Empty(meters.Collected);

        rig.Events.Fail = false;
        rig.Policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace(2), sampled: true, error: true));
        Assert.Equal(1, rig.Statistics.ErrorFacts);
        Assert.Single(rig.Events.Signals);
    }

    private static (string, object?)[] OversizeTags() =>
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
}
