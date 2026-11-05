// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// The node channel against FakeCenter's channel peer (AF-CTR-05 part N1; G.2 rows N1-2..N1-6, N1-15, N1-16, N1-18 and the replay rule): REAL
/// CloudLink code, a REAL ClientWebSocket over loopback, REAL crypto (the file-backed node key), a REAL node store; the center is MOCKED.
/// </summary>
public sealed class ChannelTests
{
    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    internal static async Task<(LinkFixture Link, FakeChannelConnection Connection)> ConnectedAsync(Action<LinkFixture>? configure = null)
    {
        var link = await LinkFixture.CreateAsync();
        link.Channel = true;
        link.ChannelRandom = () => 0;
        configure?.Invoke(link);
        await link.StartAsync();
        await link.SignInWithChannelAsync();
        var connection = await link.Center.Channel.ProvedAsync();
        await Eventually.TrueAsync(() => link.Service.Status().Relay == RelayState.Connected, "the channel is connected");
        return (link, connection);
    }

    [Fact]
    public async Task ASignedInNodeConnectsProvesItsKeyAndIsConnected()
    {
        await using var link = await LinkFixture.CreateAsync();
        link.Channel = true;
        await link.StartAsync();
        var signedOut = link.Service.Status();
        Assert.Equal(RelayState.Disabled, signedOut.Relay);
        Assert.Equal(ChannelReasons.SignedOut, signedOut.RelayReason);
        Assert.False(signedOut.CloudLinkEnabled);
        Assert.Contains(CloudLinkService.ChannelFeature, link.Service.Features);

        await link.SignInWithChannelAsync();
        var connection = await link.Center.Channel.ProvedAsync();
        await Eventually.TrueAsync(() => link.Service.Status().Relay == RelayState.Connected, "connected");
        var status = link.Service.Status();
        Assert.Equal(ChannelReasons.Connected, status.RelayReason);
        Assert.True(status.CloudLinkEnabled);

        // The hello names this node and the credential's installation, carries the capability and the cohort, and its proof verified at the
        // peer with the peer's own verifier against the registered key.
        Assert.Equal(link.NodeId, connection.Hello!.NodeId.Value.ToByteArray());
        Assert.Equal(connection.Installation, connection.Hello.InstallationId.Value.ToByteArray());
        Assert.Equal([ChannelLoop.Capability], connection.Hello.Capabilities);
        Assert.Equal(ChannelContract.Cohort, connection.Hello.ContractVersion);
        Assert.True(connection.Proved);
    }

    [Fact]
    public async Task AVerifiedCallIsAnsweredWithASignedRefusalAndLoggedBeforeAnyEffect()
    {
        var (link, connection) = await ConnectedAsync();
        await using (link)
        {
            var (call, _) = link.Center.Channel.BuildCall(connection, new FakeCallSpec { Method = RoutedMethod.SubmitNodeTask, Payload = SubmitPayload() });
            await connection.SendCallAsync(call);
            var result = await connection.ResultOfAsync(call.CallId);

            await Eventually.TrueAsync(() => connection.VerifiedResults.Count == 1, "a result whose signature verified at the peer");
            Assert.Empty(connection.UnverifiedResults);
            var (header, _) = connection.VerifiedResults.Single();
            Assert.Equal(RoutedOutcome.RefusedByPolicy, header.Outcome);
            Assert.Equal(RoutedMethod.SubmitNodeTask, header.Method);
            Assert.Equal(link.NodeId, header.NodeId.Value.ToByteArray());
            Assert.Equal("permission_denied", header.Error.Code);
            Assert.Equal(RoutedRefusals.DispatchUnavailable, header.Error.Details.State.Reason);
            Assert.Equal("task.submit", header.Error.Details.State.State);
            Assert.True(ArcForges.Contracts.Relay.Shapes.ContractShapeValidation.IsValid(result));
            Assert.Empty(result.Payload);

            var row = Assert.Single(link.RoutedLog());
            Assert.Equal((2L, (string?)null, "AUTHORIZATION/permission_denied", true), row);
        }
    }

    [Fact]
    public async Task AReplayedCallIsRefusedAlsoAfterARestart()
    {
        var (link, connection) = await ConnectedAsync();
        await using (link)
        {
            var (call, _) = link.Center.Channel.BuildCall(connection, new FakeCallSpec());
            await connection.SendCallAsync(call);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Count == 1, "the first answer");
            await connection.SendCallAsync(call);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Count == 2, "the replay's answer");
            var replay = connection.VerifiedResults.Last().Header;
            Assert.Equal(RoutedOutcome.RefusedVerification, replay.Outcome);
            Assert.Equal(RoutedCallLog.Replayed, replay.Error.Details.State.Reason);

            // A restart of the node (the store closed and reopened from disk): the same call ID is still a replay.
            await link.StopAsync();
            await link.StartAsync();
            var again = await link.Center.Channel.ProvedAsync(2);
            await Eventually.TrueAsync(() => link.Service.Status().Relay == RelayState.Connected, "connected again");
            await again.SendCallAsync(call);
            await Eventually.TrueAsync(() => again.VerifiedResults.Count == 1, "the answer after the restart");
            var afterRestart = again.VerifiedResults.Single().Header;
            Assert.Equal(RoutedOutcome.RefusedVerification, afterRestart.Outcome);
            Assert.Equal(RoutedCallLog.Replayed, afterRestart.Error.Details.State.Reason);
            Assert.Equal([2L, 3L, 3L], link.RoutedLog().Select(row => row.Decision));
            Assert.All(link.RoutedLog().Skip(1), row => Assert.Equal((RoutedCallLog.Replayed, "AUTHENTICATION/signature_invalid", false), (row.Step, row.Code, row.CallId)));
        }
    }

    [Fact]
    public async Task AVerificationRefusalIsSignedLoggedAndHasNoEffect()
    {
        // N1-15 (acceptance bullet 6): a forged call (another target node) is answered REFUSED_VERIFICATION, signed, echoing nothing it
        // could not verify; it is logged by frame digest and step only; the dispatcher never sees it.
        var dispatcher = new RecordingDispatcher();
        var (link, connection) = await ConnectedAsync(fixture => fixture.Dispatcher = dispatcher);
        await using (link)
        {
            var (call, _) = link.Center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = RoutedMethod.CancelNodeTask,
                Payload = new TaskServiceCancelTaskRequest { Meta = new RequestMeta { CommandId = CommandIds.New() }, TaskId = CommandIds.New() }.ToByteArray(),
                TargetNodeId = RandomNumberGenerator.GetBytes(16),
            });
            await connection.SendCallAsync(call);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Count == 1, "the signed refusal");
            var header = connection.VerifiedResults.Single().Header;
            Assert.Equal(RoutedOutcome.RefusedVerification, header.Outcome);
            Assert.Equal(call.CallId, header.CallId);
            Assert.Null(header.CommandId);
            Assert.False(header.HasMethod);
            Assert.False(header.HasRequestSha256);
            Assert.Equal(("signature_invalid", ErrorCategory.Authentication, "routed_call", "target_mismatch"),
                (header.Error.Code, header.Error.Category, header.Error.Details.State.State, header.Error.Details.State.Reason));
            Assert.True(RoutedRefusals.Closed(header.Error));
            Assert.Equal(0, dispatcher.Calls);
            Assert.Equal([(3L, (string?)"target_mismatch", (string?)"AUTHENTICATION/signature_invalid", false)], link.RoutedLog());
            Assert.Equal(0L, link.Store!.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
        }
    }

    [Fact]
    public async Task HeartbeatsAreAnsweredAndASilentCenterIsLeftAfterTheDeadline()
    {
        // N1-5: the node answers each heartbeat with its seq; 60 s without a frame from the center closes 4408 and backs off.
        var (link, connection) = await ConnectedAsync();
        await using (link)
        {
            await connection.SendHeartbeatAsync(41, link.Clock.GetUtcNow());
            var answer = await connection.WaitForAsync(frame => frame.FrameCase == RelayFrame.FrameOneofCase.Heartbeat, "the heartbeat answer");
            Assert.Equal(41UL, answer.Heartbeat.Seq);

            link.Clock.Advance(TimeSpan.FromSeconds(59));
            await Task.Delay(200, Cancel);
            Assert.Equal(RelayState.Connected, link.Service.Status().Relay);
            await connection.SendHeartbeatAsync(42, link.Clock.GetUtcNow());
            await connection.WaitForAsync(frame => frame.FrameCase == RelayFrame.FrameOneofCase.Heartbeat && frame.Heartbeat.Seq == 42, "the second answer");
            link.Clock.Advance(TimeSpan.FromSeconds(59));
            await Task.Delay(200, Cancel);
            Assert.Equal(RelayState.Connected, link.Service.Status().Relay);
            link.Clock.Advance(TimeSpan.FromSeconds(2));
            await Eventually.TrueAsync(() => link.Service.Status() is { Relay: RelayState.Backoff, RelayReason: ChannelReasons.HeartbeatTimeout }, "the heartbeat deadline");
            await connection.Done.WaitAsync(TimeSpan.FromSeconds(10), Cancel);
        }
    }

    [Fact]
    public async Task TokenRefreshIsSentAfterEachRefresh()
    {
        // N1-6 (CTR5-NODE-04): every rotation of the node credential sends TokenRefresh with the new access token on the open channel.
        var (link, connection) = await ConnectedAsync(fixture => fixture.RefreshInterval = TimeSpan.FromSeconds(15));
        await using (link)
        {
            for (var refresh = 1; refresh <= 2; refresh++)
            {
                var expected = refresh;
                await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(2),
                    () => connection.TokenRefreshes.Count >= expected, "TokenRefresh " + expected);
                Assert.Equal(link.StoredRecord()!.AccessToken, connection.TokenRefreshes[^1]);
            }

            Assert.Equal(2, link.Center.CallsOf("RefreshNodeSession").Count);
            Assert.Equal(RelayState.Connected, link.Service.Status().Relay);
            Assert.False(connection.Closed);
        }
    }

    [Theory]
    [InlineData(4403, RelayState.Refused, ChannelReasons.Refused)]
    [InlineData(4503, RelayState.Refused, ChannelReasons.KillSwitch)]
    [InlineData(4408, RelayState.Backoff, ChannelReasons.HeartbeatTimeout)]
    [InlineData(4429, RelayState.Backoff, ChannelReasons.RateLimited)]
    [InlineData(4413, RelayState.Backoff, ChannelReasons.FrameTooLarge)]
    [InlineData(4500, RelayState.Backoff, ChannelReasons.CenterShuttingDown)]
    [InlineData(1000, RelayState.Backoff, ChannelReasons.CenterShuttingDown)]
    public async Task EachCloseCodeLeadsToItsState(int code, RelayState state, string reason)
    {
        // N1-3 (SM-RELAY): the closes of relay.proto RelayClose.
        var (link, connection) = await ConnectedAsync();
        await using (link)
        {
            await connection.CloseAsync(code, "closed_by_test", null);
            await Eventually.TrueAsync(() => link.Service.Status() is var status && status.Relay == state && status.RelayReason == reason, code + " -> " + state);
        }
    }

    [Fact]
    public async Task AnUnexpectedNormalCloseIsTreatedLikeAShutdownAndBacksOff()
    {
        // Routed to N1 by the E1a merge: the Worker's Durable Object proxy turns an abnormal close of the center side (1006) into 1000. A
        // center closes normally only at its shutdown, with 4500, so a bare 1000 from the center backs off as 4500 does and reconnects.
        var (link, connection) = await ConnectedAsync();
        await using (link)
        {
            await connection.CloseSocketAsync(1000);
            await Eventually.TrueAsync(() => link.Service.Status() is { Relay: RelayState.Backoff, RelayReason: ChannelReasons.CenterShuttingDown }, "backoff as 4500");
            Assert.Equal(1, link.Service.Channel!.Failures);
            await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(10),
                () => link.Center.Channel.Connections.Count(c => c.Proved) == 2, "the reconnect after the backoff");
        }
    }

    [Fact]
    public async Task ABackoffReconnectsAfterItsDelayAndARefusalWaitsAnHourOrARefresh()
    {
        var (link, connection) = await ConnectedAsync();
        await using (link)
        {
            // An abnormal close (no RelayClose) is treated like 4500; the first backoff is 1 s with a zero draw.
            connection.Abort();
            await Eventually.TrueAsync(() => link.Service.Status().Relay == RelayState.Backoff, "backoff");
            await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(10),
                () => link.Center.Channel.Connections.Count(c => c.Proved) == 2, "the reconnect");
            var second = await link.Center.Channel.ProvedAsync(2);
            await Eventually.TrueAsync(() => link.Service.Status().Relay == RelayState.Connected, "connected again");

            // REFUSED (4403) waits: not after a minute, but at once when the credential is refreshed.
            await second.CloseAsync(4403, "refused", null);
            await Eventually.TrueAsync(() => link.Service.Status().Relay == RelayState.Refused, "refused");
            link.Clock.Advance(TimeSpan.FromMinutes(1));
            await Task.Delay(300, Cancel);
            Assert.Equal(2, link.Center.Channel.Connections.Count);
            await link.Service.RefreshAsync(link.Service.Generation, Cancel);
            await link.Center.Channel.ProvedAsync(3);
            await Eventually.TrueAsync(() => link.Service.Status().Relay == RelayState.Connected, "connected after the refresh");
        }
    }

    [Fact]
    public async Task ARefusalBeforeTheUpgradeIsReadFromItsStatus()
    {
        // PN-3: a 403 before the upgrade is REFUSED; a 401 makes the node refresh its credential first.
        await using var link = await LinkFixture.CreateAsync();
        link.Channel = true;
        link.ChannelRandom = () => 0;
        link.Center.Channel.RefuseUpgrade = (403, "ENTITLEMENT/feature_not_entitled");
        await link.StartAsync();
        await link.SignInWithChannelAsync();
        await Eventually.TrueAsync(() => link.Service.Status() is { Relay: RelayState.Refused, RelayReason: ChannelReasons.Refused }, "refused before the upgrade");
        Assert.Empty(link.Center.Channel.Connections);

        link.Center.Channel.RefuseUpgrade = (401, "AUTHENTICATION/token_expired");
        await link.Service.RefreshAsync(link.Service.Generation, Cancel);
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(10),
            () => link.Center.CallsOf("RefreshNodeSession").Count >= 2, "the refresh after a 401");
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(10),
            () => link.Center.Channel.Connections.Any(connection => connection.Proved), "the reconnect after the backoff");
        await Eventually.TrueAsync(() => link.Service.Status().Relay == RelayState.Connected, "connected");
    }

    [Fact]
    public async Task AReplacedChannelRaisesANotification()
    {
        // N1-16 (SEC-09): a newer proved connection of this node replaced the channel (4409).
        var (link, connection) = await ConnectedAsync();
        await using (link)
        {
            await connection.CloseAsync(4409, "replaced", null);
            await Eventually.TrueAsync(() => link.Notices().Contains(CloudLinkService.Notices.ChannelReplaced), "the notification");
            await Eventually.TrueAsync(() => link.Service.Status() is { Relay: RelayState.Backoff, RelayReason: ChannelReasons.Replaced }, "BACKOFF, replaced");
        }
    }

    [Fact]
    public async Task TheChannelStopsWhenTheLinkEndsOrIsSwitchedOff()
    {
        // N1-18: SetCloudLink(false) closes the channel (DISABLED, cloud_link_disabled), true reconnects; a sign-out closes it (signed_out).
        var (link, connection) = await ConnectedAsync();
        await using (link)
        {
            Assert.True(await link.Service.SetCloudLinkAsync(false));
            await connection.Done.WaitAsync(TimeSpan.FromSeconds(10), Cancel);
            await Eventually.TrueAsync(() => link.Service.Status() is { Relay: RelayState.Disabled, RelayReason: ChannelReasons.LinkDisabled, CloudLinkEnabled: false },
                "switched off");
            Assert.True(link.Storage.ReadLink()!.ChannelDisabled);

            Assert.True(await link.Service.SetCloudLinkAsync(true));
            var second = await link.Center.Channel.ProvedAsync(2);
            await Eventually.TrueAsync(() => link.Service.Status() is { Relay: RelayState.Connected, CloudLinkEnabled: true }, "switched on");
            Assert.Null(link.Storage.ReadLink()!.ChannelDisabled);

            using (await link.Service.EnterForSignOutAsync(TimeSpan.FromSeconds(5), Cancel))
            {
                await link.Service.SignOutHeldAsync(revokeRemote: false);
            }

            await link.Service.PublishCurrentAsync();
            await second.Done.WaitAsync(TimeSpan.FromSeconds(10), Cancel);
            await Eventually.TrueAsync(() => link.Service.Status() is { Relay: RelayState.Disabled, RelayReason: ChannelReasons.SignedOut }, "signed out");
            Assert.False(await link.Service.SetCloudLinkAsync(true));
        }
    }

    [Fact]
    public async Task AnUnknownSigningKidMakesTheNodeRefreshOnceBeforeItAcceptsCalls()
    {
        // PN-14: ChannelAccepted names a kid the node does not hold: one RefreshNodeSession, then calls.
        var (link, connection) = await ConnectedAsync(fixture => fixture.Center.Channel.SigningKids.Add("cmd-rotated-0002"));
        await using (link)
        {
            await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMilliseconds(200), TimeSpan.FromSeconds(5),
                () => link.Center.CallsOf("RefreshNodeSession").Count == 1, "one refresh");
            var (call, _) = link.Center.Channel.BuildCall(connection, new FakeCallSpec { FrameKid = "cmd-rotated-0002", HeaderKid = "cmd-rotated-0002" });
            await connection.SendCallAsync(call);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Count == 1, "the refusal");
            Assert.Equal("unknown_key", connection.VerifiedResults.Single().Header.Error.Details.State.Reason);

            // At most once per connection: the unknown kid of the call does not refresh again.
            Assert.Single(link.Center.CallsOf("RefreshNodeSession"));
        }
    }

    [Fact]
    public async Task ARelayAssertionIsSignedWithTheNodeKeyOverACenterSentNonce()
    {
        // D0-B1, C-N2: one center-sent nonce per call, the assertion signed under the relay-origin domain string.
        var (link, connection) = await ConnectedAsync();
        await using (link)
        {
            var request = SHA256.HashData(SubmitPayload());
            var command = CommandIds.New();
            var session = CommandIds.New();
            var target = new Id { Value = ByteString.CopyFrom(link.NodeId) };
            var assertion = await link.Service.SignRelayAssertionAsync(Origin.Script, session, RoutedMethod.SubmitNodeTask, request, target, command, Cancel);
            Assert.NotNull(assertion);
            var nonce = connection.Received.Count(frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest);
            Assert.Equal(1, nonce);
            Assert.Equal(link.NodeId, assertion.RelayingNodeId.Value.ToByteArray());
            Assert.Equal(connection.Installation, assertion.RelayingInstallationId.Value.ToByteArray());
            Assert.True(ArcForges.Contracts.Relay.Shapes.ContractShapeValidation.IsValid(assertion));
            var input = RelaySignatures.AssertionInput(assertion, link.Center.Endpoint)!;
            Assert.True(FakeChannelPeer.Verify(link.NodePublicKey, input, assertion.Signature.ToByteArray()));
            Assert.True(ProtoTime.ToDateTimeOffset(assertion.ExpiresAt) - ProtoTime.ToDateTimeOffset(assertion.IssuedAt) <= TimeSpan.FromSeconds(120));

            // Without an answered nonce there is no assertion.
            link.Center.Channel.AnswerNonces = false;
            var refused = link.Service.SignRelayAssertionAsync(Origin.Human, session, RoutedMethod.GetNodeTask, request, target, null, Cancel);
            await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(20), () => refused.IsCompleted, "the nonce timeout");
            Assert.Null(await refused);
        }
    }

    [Fact]
    public void TheBackoffIsJitteredBetweenOneAndSixtySeconds()
    {
        // N1-4: 1 s doubling to 60 s, full jitter between 1 s and the ceiling.
        Assert.Equal(TimeSpan.FromSeconds(1), ChannelPolicy.Backoff(1, 0));
        Assert.Equal(TimeSpan.FromSeconds(2), ChannelPolicy.Backoff(1, 1));
        Assert.Equal(TimeSpan.FromSeconds(4), ChannelPolicy.Backoff(2, 1));
        Assert.Equal(TimeSpan.FromSeconds(32), ChannelPolicy.Backoff(5, 1));
        Assert.Equal(TimeSpan.FromSeconds(60), ChannelPolicy.Backoff(6, 1));
        Assert.Equal(TimeSpan.FromSeconds(60), ChannelPolicy.Backoff(50, 1));
        Assert.Equal(TimeSpan.FromSeconds(1), ChannelPolicy.Backoff(50, 0));
        var random = new Random(7);
        for (var failures = 1; failures <= 40; failures++)
        {
            var delay = ChannelPolicy.Backoff(failures, random.NextDouble());
            Assert.InRange(delay, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(60));
        }

        Assert.Equal(TimeSpan.FromMinutes(5), ChannelPolicy.Closed(4500, 900_000).Delay);
        Assert.True(ChannelPolicy.Closed(4401, null).RefreshFirst);
        Assert.Equal(ChannelReasons.CenterShuttingDown, ChannelPolicy.Closed(1006, null).Reason);
        Assert.Equal(ChannelReasons.CenterShuttingDown, ChannelPolicy.Closed(1011, null).Reason);
        Assert.Equal(ChannelReasons.All.Count, ChannelReasons.All.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void TheChannelUriIsTheCentersOwnOriginAndPath()
    {
        // N1-2: wss for an https center, ws only for the loopback centers CenterEndpoint accepts; the path base is kept.
        Assert.Equal("wss://arcforges.com/api/fleet/v1/node", CenterChannelClient.ChannelUri(CenterEndpoint.Parse("https://arcforges.com/api")).ToString());
        Assert.Equal("ws://127.0.0.1:8080/fleet/v1/node", CenterChannelClient.ChannelUri(CenterEndpoint.Parse("http://127.0.0.1:8080")).ToString());
    }

    [Fact]
    public async Task TheChannelConnectsOnlyToTheConfiguredCenter()
    {
        // N1-2: the channel's upgrade passes the same authority guard and connect log as the HTTP seam; nothing else is reached.
        var (link, _) = await ConnectedAsync(fixture => fixture.ConnectLog = Path.Combine(fixture.Root, "connect.log"));
        await using (link)
        {
            var authority = "127.0.0.1:" + link.Center.Endpoint.EffectivePort;
            var lines = File.ReadAllLines(link.ConnectLog!);
            Assert.NotEmpty(lines);
            Assert.All(lines, line => Assert.StartsWith(authority + " sent ", line, StringComparison.Ordinal));

            using var guard = new CenterHttpClient.AuthorityGuardHandler(link.Center.Endpoint, link.ConnectLog) { InnerHandler = new HttpClientHandler() };
            using var invoker = new HttpMessageInvoker(guard);
            using var other = new HttpRequestMessage(HttpMethod.Get, "ws://127.0.0.2:" + link.Center.Endpoint.EffectivePort + "/api/fleet/v1/node");
            await Assert.ThrowsAsync<HttpRequestException>(() => invoker.SendAsync(other, Cancel));
            Assert.StartsWith("127.0.0.2:" + link.Center.Endpoint.EffectivePort + " refused ", File.ReadAllLines(link.ConnectLog!)[^1], StringComparison.Ordinal);
        }
    }

    /// <summary>A dispatcher that counts the calls it sees (part N2's seam).</summary>
    private sealed class RecordingDispatcher : IRoutedDispatcher
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public Task<RoutedAnswer> DispatchAsync(VerifiedCall call, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            return new RefusingDispatcher(TimeProvider.System).DispatchAsync(call, cancellationToken);
        }
    }

    internal static byte[] SubmitPayload()
    {
        var request = new TaskServiceSubmitTaskRequest { Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() } };
        return request.ToByteArray();
    }
}
