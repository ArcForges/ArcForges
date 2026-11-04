// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>N1-16 (ReportNodeInfo, MOCKED center) and N1-18 (the test-mode hooks, unit).</summary>
public sealed class ReporterAndHookTests
{
    private const string Report = "ReportNodeInfo";

    [Fact]
    public async Task TheNodeReportsItselfAfterSignInAndAfterARenameDebounced()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await Eventually.TrueAsync(() => link.Center.CallsOf(Report).Count == 1, "the report after sign-in");
        var first = NodeEnrollmentServiceReportNodeInfoRequest.Parser.ParseFrom(FakeCenter.Payload(link.Center.CallsOf(Report)[0].Body));
        Assert.Equal("buildbox", first.Node.Name);
        Assert.Equal(link.NodeId, first.Node.NodeId.Value.ToByteArray());
        Assert.Equal(16, first.Meta.CommandId.Value.Length);
        Assert.Equal("0.1.0-dev+0123456789abcdef0123456789abcdef01234567", first.Node.Version);
        await Eventually.TrueAsync(() => link.Storage.ReadLink()!.ReportedName == "buildbox", "the reported name is recorded");

        // A rename is reported once, 30 s later (debounced); an unchanged node reports nothing.
        link.NodeName = "renamed";
        link.Service.NodeInfoChanged();
        link.Service.NodeInfoChanged();
        link.Clock.Advance(TimeSpan.FromSeconds(20));
        await Task.Delay(150, TestContext.Current.CancellationToken);
        Assert.Single(link.Center.CallsOf(Report));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30), () => link.Center.CallsOf(Report).Count == 2, "the rename's report");
        link.Service.NodeInfoChanged();
        link.Clock.Advance(TimeSpan.FromMinutes(1));
        await Task.Delay(200, TestContext.Current.CancellationToken);
        Assert.Equal(2, link.Center.CallsOf(Report).Count);
    }

    [Fact]
    public async Task AnExpiredAccessTokenTakesAGatedRefreshAndTheReportIsRetriedWithTheSameCommandId()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Center.Script(Report, new FakeFault.Transport(16, "auth.token_expired"));
        await link.SignInAsync();
        await Eventually.TrueAsync(() => link.Center.CallsOf(Report).Count == 2, "the retried report");
        var calls = link.Center.CallsOf(Report);
        Assert.NotEqual(calls[0].Authorization, calls[1].Authorization);
        Assert.Equal(Request(calls[0]).Meta.CommandId, Request(calls[1]).Meta.CommandId);
        Assert.Equal(Request(calls[0]).Node, Request(calls[1]).Node);
        Assert.Single(link.Center.CallsOf("RefreshNodeSession"));
        Assert.True(link.Service.AccountLinked);
    }

    [Fact]
    public async Task ATransportRevocationNeverDeletesByItselfTheRefreshDecides()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Center.Script(Report, new FakeFault.Transport(16, "auth.credential_revoked"));
        await link.SignInAsync();

        // The refresh rotates (the session is live): the node stays signed in, nothing was deleted.
        await Eventually.TrueAsync(() => link.Center.CallsOf("RefreshNodeSession").Count == 1, "the gated refresh");
        await Eventually.TrueAsync(() => link.Center.CallsOf(Report).Count == 2, "the retried report");
        Assert.True(link.Service.AccountLinked);
        Assert.NotNull(link.StoredRecord());
    }

    [Fact]
    public async Task ARejectedReportIsAWarningAndIsNotRetriedUntilTheNodeChanges()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Center.Script(Report, new FakeFault.Refusal(new ArcError
        {
            Code = "invalid_argument",
            Category = ErrorCategory.Validation,
            MessageKey = "error.validation.invalid_argument",
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Effect = EffectCertainty.DidNotHappen,
            Details = new ErrorDetails { State = new StateFailure { State = "node.name", Reason = "node.name: pattern" } },
        }));
        await link.SignInAsync();
        await Eventually.TrueAsync(() => link.Service.Status().Warnings.Contains("node_info_rejected"), "node_info_rejected");
        link.Clock.Advance(TimeSpan.FromMinutes(10));
        await Task.Delay(150, TestContext.Current.CancellationToken);
        Assert.Single(link.Center.CallsOf(Report));
        Assert.True(link.Service.AccountLinked);
    }

    [Fact]
    public async Task ARestrictedAccountsNodeWarnsAndRetriesADayLater()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Center.Script(Report, new FakeFault.Refusal(new ArcError
        {
            Code = "permission_denied",
            Category = ErrorCategory.Authorization,
            MessageKey = "error.authorization.permission_denied",
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Effect = EffectCertainty.DidNotHappen,
        }));
        link.RefreshInterval = TimeSpan.FromHours(1);
        await link.SignInAsync();
        await Eventually.TrueAsync(() => link.Service.Status().Warnings.Contains("account_restricted"), "account_restricted");
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromHours(1), TimeSpan.FromHours(25), () => link.Center.CallsOf(Report).Count == 2, "the retry");
        await Eventually.TrueAsync(() => !link.Service.Status().Warnings.Contains("account_restricted"), "the warning clears");
    }

    [Fact]
    public async Task AnUnreachableReportIsRetriedWithTheSameCommandIdAndNeverBlocks()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Center.Script(Report, new FakeFault.HttpStatus(503));
        await link.SignInAsync();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(15), TimeSpan.FromMinutes(5), () => link.Center.CallsOf(Report).Count == 2, "the retry");
        var calls = link.Center.CallsOf(Report);
        Assert.Equal(Request(calls[0]).Meta.CommandId, Request(calls[1]).Meta.CommandId);
    }

    private static NodeEnrollmentServiceReportNodeInfoRequest Request(FakeCall call) =>
        NodeEnrollmentServiceReportNodeInfoRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body));

    [Theory]
    [InlineData(true, "http://127.0.0.1:18080/api", "http://127.0.0.1:18080/api")]
    [InlineData(false, "http://127.0.0.1:18080/api", null)]
    [InlineData(true, "http://127.0.0.1:18080/api/", null)]
    [InlineData(true, "http://example.org", null)]
    [InlineData(true, "", null)]
    [InlineData(true, null, null)]
    public void TheTestCenterHookAppliesOnlyInTestModeToACanonicalUrl(bool testMode, string? value, string? expected) =>
        Assert.Equal(expected, CloudLinkTestHooks.Center(testMode, value)?.Url);

    [Theory]
    [InlineData(true, "15", 15)]
    [InlineData(true, "3600", 3600)]
    [InlineData(true, "14", null)]
    [InlineData(true, "5", null)]
    [InlineData(true, "3601", null)]
    [InlineData(true, "020", null)]
    [InlineData(true, "20s", null)]
    [InlineData(true, "", null)]
    [InlineData(false, "20", null)]
    public void TheRefreshHookAppliesOnlyInTestModeFrom15To3600Seconds(bool testMode, string? value, int? seconds) =>
        Assert.Equal(seconds is null ? null : TimeSpan.FromSeconds(seconds.Value), CloudLinkTestHooks.Refresh(testMode, value));

    [Fact]
    public void TheConnectLogHookAppliesOnlyInTestModeToAnAbsolutePath()
    {
        var absolute = Path.Combine(Path.GetTempPath(), "connect.log");
        Assert.Equal(absolute, CloudLinkTestHooks.Connections(true, absolute));
        Assert.Null(CloudLinkTestHooks.Connections(false, absolute));
        Assert.Null(CloudLinkTestHooks.Connections(true, "connect.log"));
        Assert.Null(CloudLinkTestHooks.Connections(true, " "));
    }
}
