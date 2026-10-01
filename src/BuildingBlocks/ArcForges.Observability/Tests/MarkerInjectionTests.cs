// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using ArcForges.Contracts.Foundation.Values;
using Xunit;

namespace ArcForges.Observability.Tests;

/// <summary>
/// The offline marker-injection redaction proof for WP-12.02 (PG-05, observability TV-01 and RD-06). Distinct marker
/// values stand for headers, tokens, prompts, note content, file paths, cookies, API keys and URL query strings. Each
/// is pushed into every input the telemetry pipeline can receive, and a local test exporter records everything an
/// external backend would be handed. The gate passes only when no marker, and no part of one, is found.
/// </summary>
public sealed class MarkerInjectionTests
{
    // Every marker shares this root, so any partial leak of any marker is detectable with one search.
    private const string Root = "zzmarker";

    private static readonly (string Kind, string Value)[] Markers =
    [
        ("header", $"Bearer {Root}-header-aaaa"),
        ("token", $"{Root}-bearer-bbbb"),
        ("prompt", $"{Root}-prompt tell me the {Root}-launch-codes"),
        ("note", $"{Root}-note private body of the note"),
        ("path", $"C:\\Users\\someone\\{Root}-path\\diary.txt"),
        ("cookie", $"session={Root}-cookie-cccc"),
        ("credential", $"{Root}-credential-dddd"),
        ("query", $"?access={Root}-query-eeee&file={Root}-file-ffff"),
    ];

    [Fact]
    public void MarkersInjectedAsHeadersTokensPromptsNotesAndPathsNeverAppearInAnyExportedSignal()
    {
        var instance = new InstanceId(Guid.NewGuid());
        const string foreignSource = "Test.Foreign.Http.Instrumentation";
        using var source = new ActivitySource(foreignSource);
        using var exporter = new LocalTestExporter(instance, foreignSource);
        using var emitter = new SignalEmitter(exporter);
        var routes = RouteTemplateSet.Create(["/v1/workspaces/{workspace}/notes/{entry}", "/v1/health"]);
        var baseContext = new ObservabilityContext(SignalApplicationDimension.ArcScope, instance, SignalEnvironment.Test);
        var surfaces = new List<(string Surface, int Injected)>();

        surfaces.Add(("exception messages mapped to reason codes", InjectExceptions(emitter, baseContext)));
        surfaces.Add(("request URLs recorded as route templates", InjectUrls(emitter, baseContext, routes)));
        surfaces.Add(("typed context fields", InjectContextFields(emitter, baseContext)));
        surfaces.Add(("foreign span instrumentation", InjectForeignSpans(source)));
        surfaces.Add(("raw field bags", InjectFieldBags()));

        string exported = exporter.ExportedText();
        var findings = new List<string>();
        foreach ((string kind, string value) in Markers)
        {
            foreach (string fragment in Fragments(value))
            {
                if (exported.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add($"{kind}: exported text contains '{fragment}'");
                }
            }
        }

        if (exported.Contains(Root, StringComparison.OrdinalIgnoreCase))
        {
            findings.Add("the shared marker root appears in the exported text");
        }

        Report(surfaces, exporter, findings);

        // The proof is not vacuous: the exporter received real signals of every kind it records.
        Assert.True(exporter.Signals.Count >= 10, "structured events were exported");
        Assert.True(exporter.Spans.Count >= 10, "spans were exported");
        Assert.Contains("metric ArcForges.Observability arcf_signal_count", exported, StringComparison.Ordinal);
        Assert.Contains("span " + foreignSource, exported, StringComparison.Ordinal);
        Assert.True(surfaces.Sum(surface => surface.Injected) >= 100, "markers were injected broadly");
        Assert.Empty(findings);
    }

    [Fact]
    public void TheMarkersAreReallyHostileInputToTheUnscrubbedSources()
    {
        // Control: without the processor the very same inputs would leak. This keeps the zero-findings gate honest.
        using var source = new ActivitySource("Test.Control.Instrumentation");
        using var listener = new ActivityListener
        {
            ShouldListenTo = candidate => candidate.Name == source.Name,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
        };
        ActivitySource.AddActivityListener(listener);
        using Activity activity = source.StartActivity("control")!;
        foreach ((string kind, string value) in Markers)
        {
            activity.SetTag("custom." + kind, value);
        }

        string raw = string.Join('|', activity.TagObjects.Select(tag => Convert.ToString(tag.Value, CultureInfo.InvariantCulture)));
        foreach ((string _, string value) in Markers)
        {
            Assert.Contains(value, raw, StringComparison.Ordinal);
        }

        string scrubbed = string.Join('|', RedactionProcessor.Scrub(activity).Tags.Select(tag => tag.Key + tag.Value));
        Assert.DoesNotContain(Root, scrubbed, StringComparison.OrdinalIgnoreCase);
    }

    private static int InjectExceptions(SignalEmitter emitter, ObservabilityContext baseContext)
    {
        int injected = 0;
        foreach ((string kind, string value) in Markers)
        {
            Exception[] exceptions =
            [
                new IOException($"{kind}: {value}"),
                new InvalidOperationException(value, new ArgumentException(value, value)),
                new AggregateException(value, new UnauthorizedAccessException(value)),
                new KeyNotFoundException(value) { Data = { ["secret"] = value } },
                new FileNotFoundException(value, value),
            ];
            foreach (Exception exception in exceptions)
            {
                using (ObservabilityScope.Push(baseContext.WithFailure(exception)))
                {
                    emitter.Emit(SignalEventName.OperationFailed, SignalLevel.Error);
                }

                injected++;
            }
        }

        return injected;
    }

    private static int InjectUrls(SignalEmitter emitter, ObservabilityContext baseContext, RouteTemplateSet routes)
    {
        int injected = 0;
        string id = "0123456789abcdef0123456789abcdef";
        foreach ((string _, string value) in Markers)
        {
            string escaped = Uri.EscapeDataString(value);
            string[] urls =
            [
                $"https://user:{escaped}@example.test/v1/workspaces/{id}/notes/{id}?token={escaped}#{escaped}",
                $"/v1/workspaces/{escaped}/notes/{id}",
                $"/v1/workspaces/{id}/notes/{escaped}?x={escaped}",
                $"/v1/{escaped}/health",
                $"https://example.test/v1/health?note={escaped}",
                $"/v1/workspaces/{id}/{value}",
            ];
            foreach (string url in urls)
            {
                using (ObservabilityScope.Push(baseContext with { Route = routes.Record(url) }))
                {
                    emitter.Emit(SignalEventName.OperationCompleted, SignalLevel.Information);
                }

                injected++;
            }
        }

        return injected;
    }

    private static int InjectContextFields(SignalEmitter emitter, ObservabilityContext baseContext)
    {
        int injected = 0;
        foreach ((string _, string value) in Markers)
        {
            // A typed dimension refuses free text outright, so the signal is never built and nothing is exported.
            Assert.Throws<ArgumentException>(() => ObservabilityScope.Push(baseContext with { ActorReference = value }));
            Assert.Throws<ArgumentException>(() => ObservabilityScope.Push(baseContext with { RedactedResourceReference = value }));
            Assert.Throws<ArgumentException>(() => ObservabilityScope.Push(baseContext with { NativeAbiBuildId = value }));
            injected += 3;
        }

        using (ObservabilityScope.Push(baseContext with { Service = SignalService.Security, Method = SignalMethod.Read }))
        {
            emitter.Emit(SignalEventName.SecretUsed, SignalLevel.Information);
        }

        return injected;
    }

    private static int InjectForeignSpans(ActivitySource source)
    {
        int injected = 0;
        foreach ((string kind, string value) in Markers)
        {
            using Activity activity = source.StartActivity($"GET /v1/notes{value}", ActivityKind.Client)!;
            activity.DisplayName = $"GET https://example.test/v1/notes/{value}";
            string[] names =
            [
                "http.request.header.authorization", "http.request.header.cookie", "http.response.header.set-cookie",
                "http.request.header.x-api-key", "url.full", "url.query", "url.path", "http.target", "file.path",
                "gen_ai.prompt", "gen_ai.completion", "note.body", "annotation.text", "report.content",
                "attachment.bytes", "exception.message", "exception.stacktrace", "db.statement", "custom." + kind,
                "serverAddress", value,
            ];
            foreach (string name in names)
            {
                activity.SetTag(name, value);
                injected++;
            }

            activity.SetTag("service.name", value);
            activity.SetTag("actor.ref", value);
            activity.SetTag("resource.ref", value);
            activity.SetTag("reason.code", value);
            activity.SetTag("http.route", value);
            activity.SetTag("http.request.method", value);
            activity.SetBaggage("session", value);
            activity.AddEvent(new ActivityEvent($"user typed {value}", tags: new ActivityTagsCollection
            {
                ["exception.message"] = value,
                ["exception.stacktrace"] = value,
                ["note"] = value,
                ["correlation.id"] = value,
            }));
            activity.AddLink(new ActivityLink(default, new ActivityTagsCollection { ["note"] = value }));
            activity.SetStatus(ActivityStatusCode.Error, value);
            injected += 9;
        }

        return injected;
    }

    private static int InjectFieldBags()
    {
        int injected = 0;
        foreach ((string kind, string value) in Markers)
        {
            var kept = RedactionProcessor.ScrubFields(
            [
                new("Authorization", value), new("AUTHORIZATION", value), new("cookie", value), new("x-api-key", value),
                new("apiKey", value), new("access_token", value), new("password", value), new("prompt", value),
                new("note", value), new("file.path", value), new("custom." + kind, value), new("url.full", value),
                new(value, value), new("instance.id", value), new("service.name", value), new("duration.ms", value),
                new("reconnect.count", value), new("build.id", value), new("native.abi.version", value),
                new("http.route.param.workspace", value), new("causation.id", value), new("expected.revision", value),
            ]);
            Assert.Empty(kept);
            injected += 22;
        }

        return injected;
    }

    private static IEnumerable<string> Fragments(string value)
    {
        yield return value;
        foreach (string word in value.Split([' ', ':', '\\', '?', '&', '=', ';'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (word.Contains(Root, StringComparison.OrdinalIgnoreCase))
            {
                yield return word;
            }
        }
    }

    private static void Report(List<(string Surface, int Injected)> surfaces, LocalTestExporter exporter, List<string> findings)
    {
        var output = TestContext.Current.TestOutputHelper;
        if (output is null)
        {
            return;
        }

        output.WriteLine("Marker-injection redaction report (offline, local test exporter, no live backend)");
        output.WriteLine($"Marker kinds: {string.Join(", ", Markers.Select(marker => marker.Kind))}");
        foreach ((string surface, int injected) in surfaces)
        {
            output.WriteLine($"Surface: {surface}; injections: {injected}");
        }

        output.WriteLine($"Exported: {exporter.Signals.Count} structured events, {exporter.Spans.Count} spans, {exporter.ExportedFieldCount()} exported fields");
        output.WriteLine($"Findings: {findings.Count}");
    }
}
