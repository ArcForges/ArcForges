// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// The bound of the link's stop (review B N-9 of PR #72; review A C-N3): from <see cref="CloudLinkService.BeginStop"/> no refresh or report
/// starts; a refresh in flight that answers by the bound is stored, and the CTR4-NODE-05 flush runs after it; one still running at the bound
/// is cancelled and fails closed; the stop has ended by the bound plus <see cref="CloudLinkService.FlushReserve"/>. REAL CloudLink code and
/// secret store files; the center is MOCKED (FakeCenter, a slow center through <see cref="FakeFault.Hold"/>).
/// </summary>
public sealed class StopBoundTests
{
    private const string Refresh = "RefreshNodeSession";

    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(3);

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    [Fact]
    public void TheLinksStopEndsBeforeTheNodesForceExit()
    {
        // NodeHost begins the link's stop with its budget when the shutdown starts; the link ends by budget + FlushReserve, and the overrun
        // timer exits the process at budget + OverrunGrace.
        Assert.Equal(NodeHost.ShutdownBudget, CloudLinkService.StopBound);
        Assert.True(CloudLinkService.FlushReserve < NodeHost.OverrunGrace);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ARefreshThatAnswersJustInsideTheBoundIsStoredAndThenFlushed(bool channel)
    {
        // A slow center: the refresh (the link's scheduled one, review B N-9 (b), or the channel's PN-14 one) answers half a second before the
        // stop's bound. Its record write fails, so only the CTR4-NODE-05 flush at the end of the stop can store the rotated token.
        await using var link = await LinkFixture.CreateAsync();
        var release = new TaskCompletionSource();
        var issued = await InFlightAsync(link, channel, release);
        link.Secrets.FailWrites(1);

        var watch = Stopwatch.StartNew();
        link.Service.BeginStop(Bound);
        var stopping = link.StopAsync();
        await Task.Delay(Bound - TimeSpan.FromMilliseconds(500), Cancel);
        Assert.False(stopping.IsCompleted);
        release.SetResult();
        await stopping.WaitAsync(TimeSpan.FromSeconds(20), Cancel);
        Assert.True(watch.Elapsed < Bound + CloudLinkService.FlushReserve, "the stop ended at " + watch.Elapsed);

        Assert.Contains("cloud.credential_storage_failed", SignInFlowTests.ReadLog(link), StringComparison.Ordinal);
        var stored = link.StoredRecord()!;
        Assert.NotEqual(issued.RefreshToken, stored.RefreshToken);
        Assert.True(link.Center.IsLive(stored.RefreshToken));
    }

    [Fact]
    public async Task ARefreshStillRunningAtTheBoundIsCancelledAndFailsClosed()
    {
        // The center answers only after the bound: the stop cancels the call at the bound and ends within the flush's reserve. The center then
        // commits the rotation whose answer the node never got; the node restarts with the spent stored token, the center revokes the family
        // as a reuse, and the node is signed out (the documented fail-closed outcome).
        await using var link = await LinkFixture.CreateAsync();
        var release = new TaskCompletionSource();
        var issued = await InFlightAsync(link, channel: false, release);

        var watch = Stopwatch.StartNew();
        link.Service.BeginStop(Bound);
        await link.StopAsync().WaitAsync(TimeSpan.FromSeconds(20), Cancel);
        Assert.InRange(watch.Elapsed, Bound - TimeSpan.FromMilliseconds(100), Bound + CloudLinkService.FlushReserve);
        Assert.Equal(issued.RefreshToken, link.StoredRecord()!.RefreshToken);

        release.SetResult();
        await Eventually.TrueAsync(() => link.Center.IsSpent(issued.RefreshToken), "the center's late rotation");
        await link.StartAsync();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(5), () => link.Service.Phase == CloudLinkPhase.SignedOut,
            "signed out");
        Assert.Equal("credential_revoked", link.Service.LastError);
    }

    [Fact]
    public async Task NoRefreshStartsOnceTheStopBegan()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        link.Service.BeginStop(TimeSpan.FromMinutes(1));
        await Eventually.TrueAsync(() => link.Service.Idle, "the link's loop to wait for the stop");
        link.Clock.Advance(TimeSpan.FromHours(2));
        await Task.Delay(300, Cancel);
        Assert.Empty(link.Center.CallsOf(Refresh));

        // The due refresh does not turn the loop either: it waits for the stop.
        await Eventually.TrueAsync(() => link.Service.Idle, "the link's loop to wait with the refresh due");

        await link.Service.RefreshAsync(link.Service.Generation, Cancel);
        Assert.Empty(link.Center.CallsOf(Refresh));

        var watch = Stopwatch.StartNew();
        await link.StopAsync();
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2), "the idle stop took " + watch.Elapsed);
    }

    /// <summary>Signs in and leaves one refresh held at the center until <paramref name="release"/> completes.</summary>
    private static async Task<NodeCredentials> InFlightAsync(LinkFixture link, bool channel, TaskCompletionSource release)
    {
        link.Center.Script(Refresh, new FakeFault.Hold(release));
        NodeCredentials issued;
        if (channel)
        {
            // The channel's PN-14 refresh: the center's peer signs with a key the node does not have yet.
            link.Channel = true;
            link.Center.Channel.SigningKids.Add("cmd-rotated-0002");
            await link.StartAsync();
            issued = await link.SignInWithChannelAsync();
            await Eventually.TrueAsync(() => link.Center.CallsOf(Refresh).Count == 1, "the PN-14 refresh is at the center");
        }
        else
        {
            await link.StartAsync();
            issued = await link.SignInAsync();
            await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Center.CallsOf(Refresh).Count == 1,
                "the scheduled refresh is at the center");
        }

        return issued;
    }
}
