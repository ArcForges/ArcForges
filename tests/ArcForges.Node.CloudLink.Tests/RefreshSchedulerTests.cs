// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N1-6: the refresh scheduler and the revocation paths (CTR4-NODE-08 as amended: node-9, protocol-15, protocol-18; decisions G-1, G-8,
/// R-4). MOCKED center (FakeCenter over a real loopback listener), MOCKED time (<see cref="ManualClock"/>), ISOLATED store
/// (IsolatedSecretStore, with scripted write failures where named). What the manual clock proves: the scheduling arithmetic on the
/// monotonic clock and the independence from the wall clock; it proves nothing about a real clock across a suspend.
/// </summary>
public sealed class RefreshSchedulerTests
{
    private const string Refresh = "RefreshNodeSession";

    [Fact]
    public async Task TheNodeRefreshesAtTwoThirdsOfTheIssuedLifetimeLessJitter()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();
        var start = link.Clock.GetTimestamp();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(70), () => link.Center.CallsOf(Refresh).Count == 1,
            "the first refresh");
        var at = link.Clock.GetElapsedTime(start);

        // 60 minutes issued (access_lifetime_ms): two thirds is 40 minutes, less up to a tenth of jitter (6 minutes).
        Assert.InRange(at, TimeSpan.FromMinutes(34), TimeSpan.FromMinutes(40.5));
        await Eventually.TrueAsync(() => link.StoredRecord()?.RefreshToken is { } token && token != issued.RefreshToken, "the rotated record is stored");
        Assert.True(link.Center.IsLive(link.StoredRecord()!.RefreshToken));
        Assert.Equal(1, link.Service.Generation - 1);
    }

    [Fact]
    public async Task WithoutAnIssuedLifetimeTheNodeAssumesTheFifteenMinutePolicyMinimum()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var credentials = link.Center.Issue(link.NodeId);
        credentials.ClearAccessLifetimeMs();
        await link.Service.AdoptAsync(credentials, link.Center.Endpoint);
        var start = link.Clock.GetTimestamp();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(15), TimeSpan.FromMinutes(20), () => link.Center.CallsOf(Refresh).Count == 1,
            "the first refresh");
        Assert.InRange(link.Clock.GetElapsedTime(start), TimeSpan.FromMinutes(8.5), TimeSpan.FromMinutes(10.25));
    }

    [Theory]
    [InlineData(60)]
    [InlineData(10)]
    [InlineData(-60)]
    public async Task TestARefreshFloorStopsAClockLoop(int skewMinutes)
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Clock.SetWall(link.Clock.GetUtcNow() + TimeSpan.FromMinutes(skewMinutes));
        await link.SignInAsync();

        // Over 4 hours the cadence follows the issued lifetime, whatever the wall clock says: about 6 refreshes (one per 34..40 minutes),
        // never a loop.
        var start = link.Clock.GetTimestamp();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(30), TimeSpan.FromHours(4), () => link.Clock.GetElapsedTime(start) >= TimeSpan.FromHours(4),
            "four hours");
        Assert.InRange(link.Center.CallsOf(Refresh).Count, 5, 8);
    }

    [Fact]
    public async Task TestSkewWarning()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Center.CallsOf(Refresh).Count == 1, "a refresh");
        await Eventually.TrueAsync(() => !link.Service.Status().Warnings.Contains("clock_skew"), "no skew while the clocks agree");

        // The center's clock runs an hour ahead of the node's wall clock: the next refresh reports clock_skew; nothing else depends on it.
        link.Center.Clock = new ManualClock(link.Clock.GetUtcNow() + TimeSpan.FromHours(1));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Center.CallsOf(Refresh).Count == 2, "a refresh");
        await Eventually.TrueAsync(() => link.Service.Status().Warnings.Contains("clock_skew"), "clock_skew");
        Assert.True(link.Service.Status().SignedIn);
    }

    [Fact]
    public async Task ARevokedCredentialSignsTheNodeOutAndDeletesRecordKeySetsLinkAndKey()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        using (link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
        }

        var issued = await link.SignInAsync();
        link.Center.Revoke(issued.RefreshToken);
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Service.Phase == CloudLinkPhase.SignedOut,
            "signed out");
        Assert.Equal("credential_revoked", link.Service.LastError);
        Assert.Null(link.StoredRecord());
        Assert.False(File.Exists(link.Storage.LinkPath));
        Assert.False(File.Exists(link.Storage.KeysPath));
        Assert.Null(link.Keys.Recorded());
        Assert.Empty(link.Secrets.Names());
        var notice = Assert.Single(link.Notices());
        Assert.Contains("no longer accepts this node's credential", notice.Body, StringComparison.Ordinal);

        // The loop stops: no further center call.
        var calls = link.Center.Calls.Count;
        link.Clock.Advance(TimeSpan.FromHours(2));
        await Task.Delay(200, TestContext.Current.CancellationToken);
        Assert.Equal(calls, link.Center.Calls.Count);
    }

    [Fact]
    public async Task AnExpiredFamilySignsTheNodeOutWithItsOwnNotice()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();
        link.Center.Expire(issued.RefreshToken);
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Service.Phase == CloudLinkPhase.SignedOut,
            "signed out");
        Assert.Equal("token_expired", link.Service.LastError);
        Assert.Contains("unused for 90 days or at its absolute end", Assert.Single(link.Notices()).Body, StringComparison.Ordinal);
        Assert.Null(link.StoredRecord());
    }

    [Fact]
    public async Task TestALostRefreshReplyEndsInRefreshReplyLost()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();

        // The center applies the rotation and the reply is lost: the node retries with the same token (the only one it holds), which the
        // strict rotation treats as a reuse: the family is revoked and the node is signed out.
        link.Center.Script(Refresh, new FakeFault.DropReply());
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(20), TimeSpan.FromMinutes(50), () => link.Service.Phase == CloudLinkPhase.SignedOut,
            "signed out");
        var calls = link.Center.CallsOf(Refresh).Select(call => ArcForges.Contracts.Fleet.V1.NodeEnrollmentServiceRefreshNodeSessionRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body)).RefreshToken).ToList();
        Assert.Equal([issued.RefreshToken, issued.RefreshToken], calls);
        Assert.Equal("refresh_reply_lost", link.Service.LastError);
        Assert.Contains("refresh_reply_lost", Assert.Single(link.Notices()).Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnUnreachableCenterIsRetriedWithBackoffAndTheSameTokenAndNothingIsDeleted()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();
        link.Center.Script(Refresh, new FakeFault.HttpStatus(502));
        link.Center.Script(Refresh, new FakeFault.HttpStatus(503));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(45), () => link.Center.CallsOf(Refresh).Count == 3,
            "two retries");
        await Eventually.TrueAsync(() => link.StoredRecord()?.RefreshToken != issued.RefreshToken, "the third attempt rotates");
        Assert.True(link.Service.AccountLinked);
        Assert.False(link.Service.Status().CloudReachable == false);
    }

    [Fact]
    public async Task AProxys401IsNotACredentialVerdict()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        link.Center.Script(Refresh, new FakeFault.HttpStatus(401));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(45), () => link.Center.CallsOf(Refresh).Count == 2,
            "the retry after the 401");
        Assert.True(link.Service.AccountLinked);
        Assert.NotNull(link.StoredRecord());
    }

    [Fact]
    public async Task ARejectedCredentialIsKeptProbedHourlyAndRecovers()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        link.Center.Script(Refresh, new FakeFault.Refusal(Arc(ErrorCategory.Authentication, "unauthenticated")));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Service.Phase == CloudLinkPhase.SignedOut,
            "the rejection");
        Assert.Contains("center_rejected_credential", link.Service.Status().Warnings);
        Assert.NotNull(link.StoredRecord());
        Assert.Empty(link.Notices());

        // The probe waits about an hour (50..60 minutes), then presents the same token; the center accepts it again.
        var probeStart = link.Clock.GetTimestamp();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(70), () => link.Service.Phase == CloudLinkPhase.SignedIn,
            "the recovery");
        Assert.InRange(link.Clock.GetElapsedTime(probeStart), TimeSpan.FromMinutes(49), TimeSpan.FromMinutes(61));
        Assert.DoesNotContain("center_rejected_credential", link.Service.Status().Warnings);
    }

    [Fact]
    public async Task ARejectedCredentialIsDeletedNinetyDaysAfterItWasWritten()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        link.Center.Forget();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Service.Status().Warnings.Contains("center_rejected_credential"),
            "the rejection");
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromHours(6), TimeSpan.FromDays(92), () => link.StoredRecord() is null, "the deletion");
        Assert.Equal("center_rejected_credential", link.Service.LastError);
        Assert.InRange(link.Center.CallsOf(Refresh).Count, 30, 400);
    }

    [Fact]
    public async Task ARateLimitedRefreshWaitsForRetryAt()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        var start = link.Clock.GetTimestamp();

        // The first refresh comes at 34..40.5 minutes; the center refuses it until 47 minutes.
        var limited = Arc(ErrorCategory.Resource, "rate_limited");
        limited.Retry = new RetryAdvice { Mode = RetryMode.AfterTime, RetryAt = ProtoTime.ToInstant(link.Clock.GetUtcNow() + TimeSpan.FromMinutes(47)) };
        link.Center.Script(Refresh, new FakeFault.Refusal(limited));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(60), () => link.Center.CallsOf(Refresh).Count == 2, "the retry");
        Assert.InRange(link.Clock.GetElapsedTime(start), TimeSpan.FromMinutes(47), TimeSpan.FromMinutes(48));
        Assert.True(link.Service.AccountLinked);
    }

    [Fact]
    public async Task ConcurrentRefreshRequestsOfOneGenerationCallTheCenterOnce()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        var seen = link.Service.Generation;
        await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => link.Service.RefreshAsync(seen, CancellationToken.None)));
        Assert.Single(link.Center.CallsOf(Refresh));
        Assert.Equal(seen + 1, link.Service.Generation);
    }

    [Fact]
    public async Task TheExpiryWarningFollowsTheCentersValuesNotTheWallClock()
    {
        await using var link = await LinkFixture.CreateAsync();

        // The center keeps its own clock (the node's wall clock jumps below; the center's does not).
        var centerClock = new ManualClock(link.Clock.GetUtcNow());
        link.Center.Clock = centerClock;
        link.Center.FamilyLifetime = TimeSpan.FromHours(8);
        await link.StartAsync();
        await link.SignInAsync();
        Assert.DoesNotContain("credential_expires_soon", link.Service.Status().Warnings);

        // The wall clock jumping ahead changes nothing; the family's remaining time (from the center's values and monotonic time) does.
        link.Clock.SetWall(link.Clock.GetUtcNow() + TimeSpan.FromDays(300));
        Assert.DoesNotContain("credential_expires_soon", link.Service.Status().Warnings);
        var start = link.Clock.GetTimestamp();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(5), TimeSpan.FromHours(7), () => link.Service.Status().Warnings.Contains("credential_expires_soon"),
            "the warning at a quarter of the 8-hour family", centerClock.Advance);
        Assert.InRange(link.Clock.GetElapsedTime(start), TimeSpan.FromHours(5.9), TimeSpan.FromHours(6.1));
        Assert.True(link.Service.AccountLinked);
        Assert.NotNull(link.Service.Status().CredentialExpiresAt);
    }

    [Fact]
    public async Task AFailedWriteKeepsTheRotationInMemoryAndAWriteFailureUntilARestartSignsTheNodeOut()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();
        link.Secrets.FailWrites(1000);
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Center.CallsOf(Refresh).Count == 1, "a refresh");
        await Eventually.TrueAsync(() => link.Service.Status().Warnings.Contains("credential_storage_failed"), "credential_storage_failed");

        // The rotated token is used from memory: the next refresh presents it (the center accepts it), not the spent stored one.
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Center.CallsOf(Refresh).Count == 2, "a refresh");
        await Eventually.TrueAsync(() => link.Service.Generation >= 3, "the second rotation");
        Assert.True(link.Service.AccountLinked);
        Assert.Equal(issued.RefreshToken, link.StoredRecord()!.RefreshToken);

        // A crash before a successful write (the shutdown flush fails too): the restart presents the spent stored token, which the center
        // treats as a reuse (decision G-8: it fails closed).
        await link.StopAsync();
        link.Secrets.FailWrites(0);
        await link.StartAsync();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(5), () => link.Service.Phase == CloudLinkPhase.SignedOut, "signed out");
        Assert.Equal("credential_revoked", link.Service.LastError);
    }

    [Fact]
    public async Task AFailedWriteIsFlushedAtShutdown()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        link.Secrets.FailWrites(1);
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Center.CallsOf(Refresh).Count == 1, "a refresh");
        await Eventually.TrueAsync(() => link.Service.Status().Warnings.Contains("credential_storage_failed"), "credential_storage_failed");
        await link.StopAsync();
        var stored = link.StoredRecord();
        Assert.NotNull(stored);
        Assert.True(link.Center.IsLive(stored.RefreshToken));
    }

    [Fact]
    public async Task TheTestHookFixesTheCadence()
    {
        await using var link = await LinkFixture.CreateAsync();
        link.RefreshInterval = TimeSpan.FromSeconds(20);
        await link.StartAsync();
        await link.SignInAsync();
        var start = link.Clock.GetTimestamp();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(2), () => link.Center.CallsOf(Refresh).Count == 2, "two refreshes");
        Assert.InRange(link.Clock.GetElapsedTime(start), TimeSpan.FromSeconds(39), TimeSpan.FromSeconds(42));
    }

    private static ArcError Arc(ErrorCategory category, string code) => new()
    {
        Code = code,
        Category = category,
        MessageKey = "error." + category.ToString().ToLowerInvariant() + "." + code,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Effect = EffectCertainty.DidNotHappen,
    };
}
