// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text.Json;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;
using Xunit;

namespace ArcForges.Observability.Tests;

/// <summary>
/// The cardinality negative fixture (TV-03, SG-02, CC-01): an unbounded identifier used as a metric label never survives the
/// label policy, the library's own meters never create one, and the number of series one instrument can produce is bounded.
/// </summary>
[SuppressMessage("Reliability", "CA2000", Justification = "Manual test spans are never listened to, hold no unmanaged resource and are collected with the test.")]
public sealed class MetricLabelPolicyTests
{
    private static readonly string[] UnboundedIdentifiers =
    [
        "instance.id", "actor.ref", "workspace.id", "resource.ref", "command.id", "task.id", "run.id", "attempt.id",
        "correlation.id", "causation.id", "http.route", "http.route.param.workspace", "http.request.method",
        "http.response.status_code", "expected.revision", "result.revision", "duration.ms", "queue.time.ms", "reason.code",
        "build.id", "native.abi.build", "reconnect.count", "sequence.gap.count",
    ];

    [Fact]
    public void AnUnboundedIdentifierUsedAsALabelNeverSurvivesTheLabelPolicy()
    {
        RouteTemplateSet.Create(["/labels/{workspace}"]);
        object?[] values =
        [
            Guid.NewGuid().ToString("N"), "sha256:" + new string('c', 64), "/labels/{workspace}", 12345, 12345UL, 1.5d, "state.gone",
            "local.local", "GET", 200, "C:/users/someone/notes.txt", "a free text note", null,
        ];

        foreach (string name in UnboundedIdentifiers)
        {
            foreach (object? value in values)
            {
                Assert.Empty(MetricLabelPolicy.ScrubLabels([new(name, value)]));
            }
        }

        // The one reviewed label name keeps only its closed vocabulary, never an identifier-shaped or path-shaped value.
        Assert.Empty(MetricLabelPolicy.ScrubLabels([new("service.name", Guid.NewGuid().ToString("N"))]));
        Assert.Empty(MetricLabelPolicy.ScrubLabels([new("service.name", "C:/users/someone/notes.txt")]));
        Assert.Empty(MetricLabelPolicy.ScrubLabels([new("service.name", "storage")]));
        Assert.Empty(MetricLabelPolicy.ScrubLabels([new("service.name", null)]));
        Assert.Empty(MetricLabelPolicy.ScrubLabels([new("service.name", 4)]));
        Assert.Empty(MetricLabelPolicy.ScrubLabels([new("SERVICE.NAME", "Storage")]));
        foreach (string service in Enum.GetNames<SignalService>())
        {
            Assert.Equal(service, Assert.Single(MetricLabelPolicy.ScrubLabels([new("service.name", service)])).Value);
        }

        // Mixed in one point, only the reviewed label remains; the identifiers are gone.
        var mixed = new List<KeyValuePair<string, object?>>
        {
            new("workspace.id", Guid.NewGuid().ToString("N")),
            new("service.name", "Cloud"),
            new("task.id", Guid.NewGuid().ToString("N")),
            new("", "Cloud"),
        };
        KeyValuePair<string, object?> kept = Assert.Single(MetricLabelPolicy.ScrubLabels(mixed));
        Assert.Equal("service.name", kept.Key);
        Assert.Equal("Cloud", kept.Value);
        Assert.Throws<ArgumentNullException>(() => MetricLabelPolicy.ScrubLabels(null!));
    }

    [Fact]
    public void AForeignMeterThatLabelsEveryPointWithAnIdentifierCollapsesToTheBoundedSeriesSet()
    {
        using var meter = new Meter("test.foreign.cardinality." + Guid.NewGuid().ToString("N"));
        Counter<long> requests = meter.CreateCounter<long>("foreign_requests");
        var series = new HashSet<string>(StringComparer.Ordinal);
        var raw = new HashSet<string>(StringComparer.Ordinal);
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, subscribed) =>
        {
            if (ReferenceEquals(instrument, requests))
            {
                subscribed.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            KeyValuePair<string, object?>[] labels = tags.ToArray();
            raw.Add(string.Join(',', labels.Select(label => label.Key + "=" + label.Value)));
            IReadOnlyDictionary<string, object?> scrubbed = MetricLabelPolicy.ScrubLabels(labels);
            series.Add(string.Join(',', scrubbed.Select(label => label.Key + "=" + label.Value)));
        });
        listener.Start();

        string[] services = Enum.GetNames<SignalService>();
        for (int request = 0; request < 2000; request++)
        {
            requests.Add(1,
                new KeyValuePair<string, object?>("workspace.id", Guid.NewGuid().ToString("N")),
                new KeyValuePair<string, object?>("task.id", Guid.NewGuid().ToString("N")),
                new KeyValuePair<string, object?>("actor.ref", "sha256:" + new string('d', 64)),
                new KeyValuePair<string, object?>("service.name", request % 3 == 0 ? Guid.NewGuid().ToString("N") : services[request % services.Length]));
        }

        Assert.True(raw.Count > 1000, "the fixture really is unbounded before the policy");
        Assert.True(series.Count <= MetricLabelPolicy.MaximumSeriesPerInstrument, $"{series.Count} series after the policy");
        Assert.All(series, line => Assert.True(line.Length == 0 || line.StartsWith("service.name=", StringComparison.Ordinal)));
    }

    [Fact]
    public void TheTypedLabelBuilderCanExpressOnlyTheClosedServiceDimension()
    {
        Assert.Empty(MetricLabelPolicy.CreateTags(null));
        var seen = new HashSet<string>(StringComparer.Ordinal) { string.Empty };
        foreach (SignalService service in Enum.GetValues<SignalService>())
        {
            TagList tags = MetricLabelPolicy.CreateTags(service);
            KeyValuePair<string, object?> tag = Assert.Single(tags);
            Assert.Equal("service.name", tag.Key);
            Assert.Equal(service.ToString(), tag.Value);
            seen.Add(service.ToString());
        }

        Assert.Equal(MetricLabelPolicy.MaximumSeriesPerInstrument, seen.Count);
        Assert.Equal(["service.name"], MetricLabelPolicy.PointLabelNames);
        Assert.Throws<ArgumentOutOfRangeException>(() => MetricLabelPolicy.CreateTags((SignalService)99));
    }

    [Fact]
    public void EveryMeterTheLibraryOwnsUsesOnlyReviewedLabelsAndTheScopeAttributesOfThePolicy()
    {
        ObservabilityContext context = RedactionProcessorTests.FullContext();
        string instanceTag = context.InstanceId.Value.ToString("N", CultureInfo.InvariantCulture);
        var points = new List<(string Meter, string Instrument, string[] Labels)>();
        var scopes = new HashSet<string>(StringComparer.Ordinal);
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, subscribed) =>
        {
            if (instrument.Meter.Name is SignalEmitter.MeterName or TracePolicy.MeterName
                && instrument.Meter.Tags?.Any(tag => tag.Key == "instance.id" && Equals(tag.Value, instanceTag)) == true)
            {
                subscribed.EnableMeasurementEvents(instrument);
                lock (scopes)
                {
                    scopes.Add(string.Join(',', instrument.Meter.Tags.Select(tag => tag.Key).Order(StringComparer.Ordinal)));
                }
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) => Record(points, instrument, tags));
        listener.SetMeasurementEventCallback<double>((instrument, _, tags, _) => Record(points, instrument, tags));
        listener.Start();

        using var exporter = new LocalTestExporter(context.InstanceId);
        using var emitter = new SignalEmitter(exporter);
        using var policy = new TracePolicy(new TracePolicyOptions(1d, TracePolicyRig.Slow), context, new CapturingSpanSink(), exporter,
            TelemetryConsent.NotRequired);
        using (ObservabilityScope.Push(context))
        {
            // Every identifier changes on every emission; none may reach a metric point label.
            for (int index = 0; index < 50; index++)
            {
                ObservabilityContext varied = context with
                {
                    Task = TaskId.New(),
                    Run = RunId.New(),
                    Attempt = AttemptId.New(),
                    Correlation = new CorrelationId(Guid.NewGuid()),
                    Workspace = new WorkspaceId(Guid.NewGuid()),
                    Command = new CommandId(Guid.NewGuid()),
                };
                using (ObservabilityScope.Push(varied))
                {
                    emitter.Emit(SignalEventName.OperationCompleted, SignalLevel.Information);
                }
            }
        }

        foreach (SignalService service in Enum.GetValues<SignalService>())
        {
            using (ObservabilityScope.Push(context with { Service = service }))
            {
                emitter.Emit(SignalEventName.OperationFailed, SignalLevel.Error);
            }

            policy.OnSpanEnded(TracePolicyRig.Span(TracePolicyRig.Trace((int)service), sampled: true, error: true,
                tags: [("service.name", service.ToString()), ("task.id", Guid.NewGuid().ToString("N"))]));
        }

        listener.RecordObservableInstruments();

        Assert.NotEmpty(points);
        Assert.Contains(points, point => point.Meter == SignalEmitter.MeterName);
        Assert.Contains(points, point => point.Meter == TracePolicy.MeterName);
        Assert.All(points, point => Assert.All(point.Labels, label => Assert.Contains(label, MetricLabelPolicy.PointLabelNames)));
        foreach (var instrument in points.GroupBy(point => (point.Meter, point.Instrument)))
        {
            int distinctSeries = instrument.Select(point => string.Join(',', point.Labels)).Distinct(StringComparer.Ordinal).Count();
            Assert.True(distinctSeries <= MetricLabelPolicy.MaximumSeriesPerInstrument, $"{instrument.Key}: {distinctSeries} series");
        }

        string expectedScope = string.Join(',', MetricLabelPolicy.ScopeAttributeNames.Order(StringComparer.Ordinal));
        Assert.NotEmpty(scopes);
        Assert.All(scopes, scope => Assert.Equal(expectedScope, scope));
    }

    [Fact]
    public void TheLabelPolicyEqualsTheMetricLabelSectionOfThePolicyFileAndRefusesEveryOtherDimension()
    {
        using JsonDocument policy = TelemetryPolicyTests.LoadPolicy();
        JsonElement labels = policy.RootElement.GetProperty("metricLabels");

        Assert.Equal(MetricLabelPolicy.PointLabelNames, labels.GetProperty("pointLabels").EnumerateArray().Select(label => label.GetString()!));
        Assert.Equal(MetricLabelPolicy.ScopeAttributeNames, labels.GetProperty("scopeAttributes").EnumerateArray().Select(label => label.GetString()!));
        Assert.Equal(MetricLabelPolicy.MaximumSeriesPerInstrument, labels.GetProperty("maximumSeriesPerInstrument").GetInt32());
        Assert.True(labels.GetProperty("unboundedIdentifiersAreNeverLabels").GetBoolean());
        Assert.Contains("every other dimension", labels.GetProperty("pointLabelRule").GetString(), StringComparison.Ordinal);

        // The whole reviewed vocabulary, each dimension with a value of its own reviewed shape: only the allowlisted label survives.
        string template = RouteTemplateSet.Create(["/labels/vocabulary"]).Record("/labels/vocabulary").Template;
        int refused = 0;
        foreach (JsonElement entry in policy.RootElement.GetProperty("dimensions").EnumerateArray())
        {
            string name = entry.GetProperty("name").GetString()!;
            object valid = TelemetryPolicyTests.SampleValue(entry, template);
            IReadOnlyDictionary<string, object?> kept = MetricLabelPolicy.ScrubLabels([new(name, valid)]);
            if (MetricLabelPolicy.PointLabelNames.Contains(name))
            {
                Assert.Equal(valid, Assert.Single(kept).Value);
            }
            else
            {
                Assert.Empty(kept);
                refused++;
            }
        }

        Assert.True(refused >= 25, "the identifiers and every other dimension are refused as labels");
    }

    private static void Record(List<(string Meter, string Instrument, string[] Labels)> points, Instrument instrument,
        ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        string[] labels = tags.ToArray().Select(tag => tag.Key).ToArray();
        lock (points)
        {
            points.Add((instrument.Meter.Name, instrument.Name, labels));
        }
    }
}
