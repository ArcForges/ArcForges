// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;
using Xunit;

namespace ArcForges.Observability.Tests;

public sealed class RedactionProcessorTests
{
    private const string Hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Id = "0123456789abcdef0123456789abcdef";

    [Theory]
    [InlineData("Authorization")]
    [InlineData("authorization")]
    [InlineData("http.request.header.authorization")]
    [InlineData("Proxy-Authorization")]
    [InlineData("Cookie")]
    [InlineData("Set-Cookie")]
    [InlineData("http.response.header.set-cookie")]
    [InlineData("X-Api-Key")]
    [InlineData("apiKey")]
    [InlineData("API_KEY")]
    [InlineData("service.APIKey")]
    [InlineData("private-key")]
    [InlineData("accessToken")]
    [InlineData("refresh_token")]
    [InlineData("auth.bearer")]
    [InlineData("password")]
    [InlineData("passkey.material")]
    [InlineData("one.time.code")]
    [InlineData("otp")]
    [InlineData("byok.value")]
    [InlineData("client.secret")]
    [InlineData("prompt")]
    [InlineData("gen_ai.prompt")]
    [InlineData("model.completion")]
    [InlineData("chat.message")]
    [InlineData("note.body")]
    [InlineData("annotation.text")]
    [InlineData("report.content")]
    [InlineData("attachment.bytes")]
    [InlineData("file.contents")]
    [InlineData("file.path")]
    [InlineData("filePath")]
    [InlineData("directory")]
    [InlineData("url.full")]
    [InlineData("http.url")]
    [InlineData("url.query")]
    [InlineData("raw.sync.payload")]
    [InlineData("exception.message")]
    [InlineData("exception.stacktrace")]
    [InlineData("")]
    [InlineData("  ")]
    public void KnownSensitiveHeaderAndFieldNamesAreRecognised(string name)
    {
        Assert.True(RedactionProcessor.IsSensitiveFieldName(name), name);
    }

    [Theory]
    [InlineData("build.id")]
    [InlineData("correlation.id")]
    [InlineData("http.route")]
    [InlineData("http.response.status_code")]
    [InlineData("duration.ms")]
    [InlineData("native.abi.build")]
    [InlineData("service.name")]
    [InlineData("keyboard.layout")]
    [InlineData("sequence.gap.count")]
    public void ReviewedAndOrdinaryNamesAreNotSensitive(string name)
    {
        Assert.False(RedactionProcessor.IsSensitiveFieldName(name), name);
    }

    [Fact]
    public void NoReviewedExportFieldIsItselfAKnownSensitiveName()
    {
        foreach (TelemetryFieldRule rule in TelemetryFields.Rules)
        {
            Assert.False(RedactionProcessor.IsSensitiveFieldName(rule.Name), rule.Name);
        }

        Assert.False(RedactionProcessor.IsSensitiveFieldName(TelemetryFields.RouteParameterPrefix + "workspace"));
        Assert.Throws<ArgumentNullException>(() => RedactionProcessor.IsSensitiveFieldName(null!));
    }

    [Fact]
    public void OnlyReviewedFieldsWithTheirReviewedShapesAreExported()
    {
        var kept = RedactionProcessor.ScrubFields(
        [
            new("application.id", "arcscope"),
            new("instance.id", Id),
            new("actor.ref", Hash),
            new("service.name", "Storage"),
            new("reason.code", "state.not_found"),
            new("duration.ms", 12.5d),
            new("expected.revision", 7UL),
            new("reconnect.count", 3),
            new("http.route", RouteTemplateSet.Create(["/v1/workspaces/{workspace}"]).Record("/v1/workspaces/" + Id).Template),
            new("http.route.param.workspace", Id),
            new("http.request.method", "GET"),
            new("http.response.status_code", 204),
            new("Authorization", "Bearer marker"),
            new("http.request.header.cookie", "session=marker"),
            new("prompt", "marker"),
            new("note.body", "marker"),
            new("file.path", @"C:\Users\someone\marker.txt"),
            new("url.full", "https://example.test/a?token=marker"),
            new("exception.message", "marker"),
            new("custom.unreviewed", "marker"),
            new("custom.count", 5),
            new("", "marker"),
        ]);

        Assert.Equal(
            [
                "actor.ref", "application.id", "duration.ms", "expected.revision", "http.request.method", "http.response.status_code",
                "http.route", "http.route.param.workspace", "instance.id", "reason.code", "reconnect.count", "service.name",
            ],
            kept.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(12.5d, kept["duration.ms"]);
        Assert.DoesNotContain("marker", string.Join('|', kept.Values.Select(value => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture))), StringComparison.Ordinal);
        Assert.Throws<ArgumentNullException>(() => RedactionProcessor.ScrubFields(null!));
        Assert.Throws<NotSupportedException>(() => ((IDictionary<string, object?>)kept)["x"] = 1);
    }

    [Theory]
    [InlineData("application.id", "somebody")]
    [InlineData("application.id", 1)]
    [InlineData("instance.id", "not-an-id")]
    [InlineData("instance.id", "00000000000000000000000000000000")]
    [InlineData("instance.id", "0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("build.id", "free text")]
    [InlineData("deployment.environment", "Prod marker")]
    [InlineData("actor.ref", "alice@example.test")]
    [InlineData("actor.ref", "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("resource.ref", @"C:\Users\someone\notes.txt")]
    [InlineData("service.name", "Marker")]
    [InlineData("reason.code", "user typed this")]
    [InlineData("reason.code", "state.not_a_registered_code")]
    [InlineData("expected.revision", -1)]
    [InlineData("expected.revision", "7")]
    [InlineData("duration.ms", -1d)]
    [InlineData("duration.ms", double.NaN)]
    [InlineData("duration.ms", double.PositiveInfinity)]
    [InlineData("duration.ms", "12")]
    [InlineData("native.abi.version", "1.2.3")]
    [InlineData("native.abi.version", "one.two")]
    [InlineData("reconnect.count", -1)]
    [InlineData("reconnect.count", 2.5d)]
    [InlineData("http.route", "/files/C:/Users/someone/diary.txt")]
    [InlineData("http.route", "/users/someone/diary")]
    [InlineData("http.route", "https://example.test/v1/x?token=marker")]
    [InlineData("http.request.method", "FETCH marker")]
    [InlineData("http.response.status_code", 99)]
    [InlineData("http.response.status_code", 600)]
    [InlineData("http.route.param.workspace", "marker")]
    [InlineData("http.route.param.Workspace", "0123456789abcdef0123456789abcdef")]
    public void AReviewedFieldWithAnUnreviewedValueShapeIsRemoved(string name, object value)
    {
        Assert.Empty(RedactionProcessor.ScrubFields([new(name, value)]));
    }

    [Theory]
    [InlineData("http.route.param.token")]
    [InlineData("http.route.param.apikey")]
    [InlineData("http.route.param.path")]
    public void ARouteParameterWhoseSlotNameIsSensitiveIsRemovedEvenWithAValidIdentifier(string name)
    {
        Assert.Empty(RedactionProcessor.ScrubFields([new(name, Id)]));
    }

    [Fact]
    public void ARouteParameterFieldNameIsExportedOnlyForASlotARegisteredTemplateDeclares()
    {
        const string hostile = "zzmarkerslotname";
        Assert.Empty(RedactionProcessor.ScrubFields([new("http.route.param." + hostile, Id)]));

        RouteTemplateSet.Create(["/slots/{" + hostile + "}"]);
        Assert.Single(RedactionProcessor.ScrubFields([new("http.route.param." + hostile, Id)]));
        Assert.Empty(RedactionProcessor.ScrubFields([new("http.route.param." + hostile + "x", Id)]));

        var instance = new InstanceId(Guid.NewGuid());
        const string foreignSource = "Test.Foreign.SlotNames";
        using var source = new ActivitySource(foreignSource);
        using var exporter = new LocalTestExporter(instance, foreignSource);
        using (Activity activity = source.StartActivity("slots.probe")!)
        {
            activity.SetTag("http.route.param.zzunregisteredslotchosenbyanattacker", Id);
            activity.SetTag("http.route.param.zzunregisteredslotchosenbyanattackerb", Id);
        }

        Assert.DoesNotContain("zzunregistered", exporter.ExportedText(), StringComparison.Ordinal);
        Assert.Empty(Assert.Single(exporter.Spans).Tags);
    }

    [Fact]
    public void ObjectsWithoutAReviewedShapeNeverReachAnExporter()
    {
        var kept = RedactionProcessor.ScrubFields(
        [
            new("instance.id", new Marker()),
            new("service.name", new Marker()),
            new("actor.ref", new Marker()),
            new("duration.ms", new Marker()),
            new("reason.code", null),
            new("application.id", "arcscope"),
        ]);

        Assert.Equal("application.id", Assert.Single(kept.Keys));
    }

    [Fact]
    public void SpanExportKeepsOnlyReviewedFieldsAndTheSpanIdentity()
    {
        using var source = new ActivitySource("Test.Hostile.Instrumentation");
        using var listener = Listener(source.Name);
        Activity activity = source.StartActivity("Test.Operation", ActivityKind.Server)!;
        activity.DisplayName = "POST https://example.test/v1/notes?token=marker-in-name";
        activity.SetTag("http.request.method", "POST");
        activity.SetTag("http.response.status_code", 500);
        activity.SetTag("http.request.header.authorization", "Bearer marker");
        activity.SetTag("url.full", "https://example.test/v1/notes?token=marker");
        activity.SetTag("prompt", "marker prompt");
        activity.SetTag("custom.note", "marker note");
        activity.SetTag("correlation.id", Id);
        activity.SetBaggage("session", "marker-baggage");
        activity.AddLink(new ActivityLink(default, new ActivityTagsCollection { ["secret"] = "marker-link" }));
        activity.AddEvent(new ActivityEvent("exception", tags: new ActivityTagsCollection
        {
            ["exception.message"] = "marker exception",
            ["exception.stacktrace"] = "at marker",
            ["result.code"] = "Failed",
        }));
        activity.AddEvent(new ActivityEvent("user typed this event name"));
        activity.SetStatus(ActivityStatusCode.Error, "marker status description");
        activity.Stop();

        ScrubbedSpan span = RedactionProcessor.Scrub(activity);

        Assert.Equal(RedactionProcessor.RedactedName, span.Name);
        Assert.Equal("Test.Hostile.Instrumentation", span.SourceName);
        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Equal(ActivityKind.Server, span.Kind);
        Assert.Equal(activity.TraceId.ToHexString(), span.TraceId);
        Assert.Equal(activity.SpanId.ToHexString(), span.SpanId);
        Assert.Equal(["correlation.id", "http.request.method", "http.response.status_code"], span.Tags.Keys.Order(StringComparer.Ordinal));
        Assert.Collection(span.Events,
            first =>
            {
                Assert.Equal("exception", first.Name);
                Assert.Equal("result.code", Assert.Single(first.Tags.Keys));
            },
            second =>
            {
                Assert.Equal(RedactionProcessor.RedactedName, second.Name);
                Assert.Empty(second.Tags);
            });
        Assert.DoesNotContain("marker", Everything(span), StringComparison.Ordinal);
        Assert.Throws<ArgumentNullException>(() => RedactionProcessor.Scrub((Activity)null!));
    }

    [Fact]
    public void ARealActivityAddExceptionEventIsReducedToItsNameAndNothingElse()
    {
        using var source = new ActivitySource("Test.Real.AddException");
        using var listener = Listener(source.Name);
        using Activity activity = source.StartActivity("exception.probe")!;
        activity.AddException(new System.IO.IOException("zzmarker-message C:\\Users\\someone\\diary.txt"),
            new TagList { { "note", "zzmarker-note" }, { "result.code", "Failed" } });
        activity.Stop();

        // The live activity really holds the message and stack trace, which no API can remove from it.
        ActivityEvent live = Assert.Single(activity.Events);
        Assert.Contains(live.Tags, tag => tag.Key == "exception.message" && ((string?)tag.Value)!.Contains("zzmarker", StringComparison.Ordinal));
        Assert.Contains(live.Tags, tag => tag.Key == "exception.stacktrace");

        ScrubbedSpanEvent exported = Assert.Single(RedactionProcessor.Scrub(activity).Events);
        Assert.Equal("exception", exported.Name);
        Assert.Equal("result.code", Assert.Single(exported.Tags.Keys));
        Assert.DoesNotContain("zzmarker", Everything(RedactionProcessor.Scrub(activity)), StringComparison.Ordinal);
    }

    [Fact]
    public void SpanExportKeepsALibraryOperationNameAndItsParent()
    {
        using var source = new ActivitySource("Test.Library.Instrumentation");
        using var listener = Listener(source.Name);
        using Activity parent = source.StartActivity("storage.commit")!;
        using Activity child = source.StartActivity("storage.flush")!;
        child.Stop();

        ScrubbedSpan span = RedactionProcessor.Scrub(child);

        Assert.Equal("storage.flush", span.Name);
        Assert.Equal(parent.SpanId.ToHexString(), span.ParentSpanId);
        Assert.Null(RedactionProcessor.Scrub(parent).ParentSpanId);
    }

    [Fact]
    public void TheEmitterRunsEveryDimensionThroughTheProcessorWithoutLosingAnyOfThem()
    {
        var context = FullContext();
        using var exporter = new LocalTestExporter(context.InstanceId);
        using var emitter = new SignalEmitter(exporter);
        using (ObservabilityScope.Push(context))
        {
            emitter.Emit(SignalEventName.OperationFailed, SignalLevel.Error);
        }

        StructuredSignal signal = Assert.Single(exporter.Signals);
        string[] expected =
        [
            "actor.ref", "application.id", "attempt.id", "build.id", "capability.name", "causation.id", "command.id", "correlation.id",
            "deployment.environment", "duration.ms", "expected.revision", "http.route", "http.route.param.task", "http.route.param.workspace",
            "instance.id", "interface.name", "method.name", "native.abi.build", "native.abi.version", "queue.time.ms", "reason.code",
            "reconnect.count", "resource.ref", "result.code", "result.revision", "run.id", "sequence.gap.count", "service.name",
            "task.id", "transport", "workspace.id",
        ];
        Assert.Equal(expected, signal.Properties.Keys.Order(StringComparer.Ordinal));
        Assert.Equal("/v1/workspaces/{workspace}/tasks/{task}", signal.Properties["http.route"]);
    }

    internal static ObservabilityContext FullContext()
    {
        RecordedRoute route = RouteTemplateSet.Create(["/v1/workspaces/{workspace}/tasks/{task}"])
            .Record("https://example.test/v1/workspaces/" + Id + "/tasks/" + "fedcba9876543210fedcba9876543210" + "?token=ignored");
        return new ObservabilityContext(SignalApplicationDimension.ArcScope, new InstanceId(Guid.NewGuid()), SignalEnvironment.Test)
        {
            ActorReference = Hash,
            Workspace = new WorkspaceId(Guid.NewGuid()),
            Transport = SignalTransport.Http,
            Service = SignalService.Storage,
            Interface = SignalInterface.ResourceStore,
            Method = SignalMethod.Commit,
            Capability = SignalCapability.ResourceWrite,
            RedactedResourceReference = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
            ResultCode = SignalResultCode.Failed,
            ReasonCode = ReasonCodes.Get("state.invalid_transition"),
            NativeAbiVersion = new NativeAbiVersion(1, 2),
            NativeAbiBuildId = "local.local",
            ReconnectCount = 1,
            SequenceGapCount = 2,
            Route = route,
        };
    }

    private static ActivityListener Listener(string sourceName)
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    private static string Everything(ScrubbedSpan span) => string.Join('|',
        [span.Name, span.SourceName, span.TraceId, span.SpanId, .. span.Tags.Select(tag => tag.Key + "=" + tag.Value),
            .. span.Events.SelectMany(spanEvent => spanEvent.Tags.Select(tag => tag.Key + "=" + tag.Value).Append(spanEvent.Name))]);

    private sealed class Marker
    {
        public override string ToString() => "marker";
    }
}
