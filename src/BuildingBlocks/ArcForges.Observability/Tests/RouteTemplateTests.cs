// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.Observability.Tests;

public sealed class RouteTemplateTests
{
    private const string Workspace = "0123456789abcdef0123456789abcdef";
    private const string Task = "fedcba9876543210fedcba9876543210";

    private static readonly RouteTemplateSet Routes = RouteTemplateSet.Create(
    [
        "/v1/workspaces/{workspace}/tasks/{task}",
        "/v1/workspaces/{workspace}",
        "/v1/health",
        "/",
    ]);

    [Fact]
    public void AUrlIsRecordedAsItsTemplateAndTheOpaqueIdentifiersThatFilledItsSlots()
    {
        RecordedRoute route = Routes.Record($"/v1/workspaces/{Workspace}/tasks/{Task}");

        Assert.True(route.IsMatched);
        Assert.Equal("/v1/workspaces/{workspace}/tasks/{task}", route.Template);
        Assert.Collection(route.Identifiers,
            first =>
            {
                Assert.Equal("workspace", first.Slot);
                Assert.Equal(Guid.ParseExact(Workspace, "N"), first.Value);
            },
            second =>
            {
                Assert.Equal("task", second.Slot);
                Assert.Equal(Guid.ParseExact(Task, "N"), second.Value);
            });
        Assert.Equal("/v1/workspaces/{workspace}", Routes.Record($"/v1/workspaces/{Workspace}").Template);
        Assert.Equal("/v1/health", Assert.IsType<RecordedRoute>(Routes.Record("/v1/health")).Template);
        Assert.Empty(Routes.Record("/v1/health").Identifiers);
        Assert.Equal("/", Routes.Record("/").Template);
    }

    [Theory]
    [InlineData("https://example.test/v1/workspaces/0123456789abcdef0123456789abcdef/tasks/fedcba9876543210fedcba9876543210?access_token=marker&path=C:%5Cx")]
    [InlineData("http://user:marker@example.test:8443/v1/workspaces/0123456789abcdef0123456789abcdef/tasks/fedcba9876543210fedcba9876543210#marker")]
    [InlineData("HTTPS://EXAMPLE.TEST/v1/workspaces/0123456789ABCDEF0123456789ABCDEF/tasks/FEDCBA9876543210FEDCBA9876543210")]
    [InlineData("/v1/workspaces/01234567-89ab-cdef-0123-456789abcdef/tasks/fedcba98-7654-3210-fedc-ba9876543210?marker=1")]
    public void SchemeHostUserInformationQueryAndFragmentAreDiscardedUnread(string target)
    {
        RecordedRoute route = Routes.Record(target);

        Assert.Equal("/v1/workspaces/{workspace}/tasks/{task}", route.Template);
        Assert.Equal(2, route.Identifiers.Count);
        Assert.DoesNotContain("marker", route.Template, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("v1/workspaces/0123456789abcdef0123456789abcdef")]
    [InlineData("/v1/workspaces/my-private-workspace-name")]
    [InlineData("/v1/workspaces/0123456789abcdef0123456789abcdef/tasks/read-me.txt")]
    [InlineData("/v1/workspaces/C:/Users/someone/diary.txt")]
    [InlineData("/v1/workspaces/../../etc/passwd")]
    [InlineData("/v1/workspaces/00000000000000000000000000000000")]
    [InlineData("/v1/workspaces/0123456789abcdef0123456789abcde")]
    [InlineData("/v1/workspaces/0123456789abcdef0123456789abcdefff")]
    [InlineData("/v1/workspaces/0123456789abcdef0123456789abcdez")]
    [InlineData("/v1/workspaces/%30123456789abcdef0123456789abcdef")]
    [InlineData("/v1/workspaces/0123456789abcdef0123456789abcdef;jsessionid=marker")]
    [InlineData("/v1/workspaces/0123456789abcdef0123456789abcdef/")]
    [InlineData("/v1//workspaces/0123456789abcdef0123456789abcdef")]
    [InlineData("/V1/workspaces/0123456789abcdef0123456789abcdef")]
    [InlineData("/v1/unknown")]
    [InlineData("/v1/workspaces/0123456789abcdef0123456789abcdef/tasks")]
    [InlineData("\\v1\\workspaces\\0123456789abcdef0123456789abcdef")]
    [InlineData("/v1/workspaces/0123456789abcdef0123456789abcdef\r\nX-Injected: marker")]
    [InlineData("/v1/workspaces/0123456789abcdef0123456789abcdef marker")]
    [InlineData("ftp://example.test/v1/health")]
    [InlineData("javascript://v1/health")]
    [InlineData("//example.test/v1/health")]
    public void AUrlThatMatchesNoTemplateExactlyIsRecordedAsUnmatchedNeverAsText(string? target)
    {
        RecordedRoute route = Routes.Record(target);

        Assert.False(route.IsMatched);
        Assert.Same(RecordedRoute.Unmatched, route);
        Assert.Equal("{unmatched}", route.Template);
        Assert.Empty(route.Identifiers);
    }

    [Fact]
    public void ARouteDoesNotAcceptAnOverlongOrDeeplyNestedUrl()
    {
        Assert.False(Routes.Record("/v1/workspaces/" + new string('a', 3000)).IsMatched);
        Assert.False(Routes.Record("/v1/health?" + new string('q', 3000)).IsMatched);
        Assert.False(Routes.Record("/" + string.Join('/', Enumerable.Repeat("v1", 40))).IsMatched);
    }

    [Theory]
    [InlineData("")]
    [InlineData("v1/health")]
    [InlineData("/v1/health/")]
    [InlineData("/V1/health")]
    [InlineData("/v1/{workspace")]
    [InlineData("/v1/{}")]
    [InlineData("/v1/{Workspace}")]
    [InlineData("/v1/{work space}")]
    [InlineData("/v1/{workspace}/{workspace}")]
    [InlineData("/v1/{token}")]
    [InlineData("/v1/{path}")]
    [InlineData("/v1/{apikey}")]
    [InlineData("/v1/{file}")]
    [InlineData("/v1/hea lth")]
    [InlineData("/v1/health?x=1")]
    [InlineData("/v1//health")]
    [InlineData("/v1/{a}/{b}/{c}/{d}/{e}/{f}/{g}/{h}/{i}/{j}/{k}/{l}/{m}/{n}/{o}/{p}/{q}")]
    public void ATemplateMustBeAReviewedLowerCasePathWithSafeSlots(string template)
    {
        Assert.Throws<ArgumentException>(() => RouteTemplateSet.Create([template]));
    }

    [Fact]
    public void ATemplateSetRejectsNothingAmbiguousAndNothingEmpty()
    {
        Assert.Throws<ArgumentException>(() => RouteTemplateSet.Create([]));
        Assert.Throws<ArgumentException>(() => RouteTemplateSet.Create(["/a/{x}", "/a/{y}"]));
        Assert.Throws<ArgumentException>(() => RouteTemplateSet.Create(["/a/b", "/a/b"]));
        Assert.Throws<ArgumentNullException>(() => RouteTemplateSet.Create(null!));
        Assert.Equal("/a/{x}", RouteTemplateSet.Create(["/a/b", "/a/{x}"]).Record("/a/" + Workspace).Template);
        Assert.Equal("/a/b", RouteTemplateSet.Create(["/a/b", "/a/{x}"]).Record("/a/b").Template);
    }

    [Fact]
    public void ARouteInTheContextExportsOnlyTheTemplateAndOpaqueIdentifiers()
    {
        RecordedRoute route = Routes.Record($"https://example.test/v1/workspaces/{Workspace}/tasks/{Task}?token=marker");
        var instance = new ArcForges.Contracts.Foundation.Values.InstanceId(Guid.NewGuid());
        using var exporter = new LocalTestExporter(instance);
        using var emitter = new SignalEmitter(exporter);
        using (ObservabilityScope.Push(new ObservabilityContext(SignalApplicationDimension.ArcScope, instance, SignalEnvironment.Test) { Route = route }))
        {
            emitter.Emit(SignalEventName.OperationCompleted, SignalLevel.Information);
        }

        StructuredSignal signal = Assert.Single(exporter.Signals);
        Assert.Equal("/v1/workspaces/{workspace}/tasks/{task}", signal.Properties["http.route"]);
        Assert.Equal(Workspace, signal.Properties["http.route.param.workspace"]);
        Assert.Equal(Task, signal.Properties["http.route.param.task"]);
        Assert.DoesNotContain("example.test", exporter.ExportedText(), StringComparison.Ordinal);
        Assert.DoesNotContain("marker", exporter.ExportedText(), StringComparison.Ordinal);

        var unmatched = new ObservabilityContext(SignalApplicationDimension.ArcScope, instance, SignalEnvironment.Test)
        { Route = Routes.Record("/users/someone/diary") };
        using (ObservabilityScope.Push(unmatched))
        {
            emitter.Emit(SignalEventName.OperationCompleted, SignalLevel.Information);
        }

        Assert.Equal("{unmatched}", exporter.Signals[^1].Properties["http.route"]);
        Assert.DoesNotContain("diary", exporter.ExportedText(), StringComparison.Ordinal);
    }
}
