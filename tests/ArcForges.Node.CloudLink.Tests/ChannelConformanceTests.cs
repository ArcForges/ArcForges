// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using Google.Protobuf;
using RelayShapes = ArcForges.Contracts.Relay.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N1-19: FakeCenter's channel peer and the node's channel against the 14 exchanges captured from the REAL center's hub (Cloud E1a #144 at
/// <c>c14156bf</c>, <c>center/internal/hub/testdata/exchanges/NodeChannel-*.json</c>, cohort 1.0.0-ci.437.1; vendored with a drift
/// check). The peer's own frame builders (the ones it sends) produce the captured center frames' bytes, and the REAL node client, served
/// each captured exchange (its frames and refusal header, and the JSON body of a refusal) in the captured order, answers the captured
/// challenge with a hello that proves against its registered key and records the state the center meant (its status publications).
/// </summary>
public sealed class ChannelConformanceTests
{
    private const string SourceCommit = "5c4c60744f2a269a4546d5e65a0870cb97feca21";

    /// <summary>What each captured exchange must leave the node in (SM-RELAY; relay.proto RelayClose; PN-3).</summary>
    private static readonly Dictionary<string, (RelayState State, string Reason)> Expected = new(StringComparer.Ordinal)
    {
        ["accepted"] = (RelayState.Disabled, ChannelReasons.LinkDisabled),
        ["hello-deadline"] = (RelayState.Backoff, ChannelReasons.HeartbeatTimeout),
        ["hello-malformed"] = (RelayState.Refused, ChannelReasons.Refused),
        ["hello-mismatch"] = (RelayState.Refused, ChannelReasons.Refused),
        ["hello-signature"] = (RelayState.Refused, ChannelReasons.Refused),
        ["lapsed"] = (RelayState.Refused, ChannelReasons.Refused),
        ["refused-account-session"] = (RelayState.Refused, ChannelReasons.Refused),
        ["refused-credential-revoked"] = (RelayState.Backoff, ChannelReasons.CredentialExpired),
        ["refused-no-credential"] = (RelayState.Backoff, ChannelReasons.CredentialExpired),
        ["refused-token-expired"] = (RelayState.Backoff, ChannelReasons.CredentialExpired),
        ["replaced"] = (RelayState.Backoff, ChannelReasons.Replaced),
        ["revoked"] = (RelayState.Backoff, ChannelReasons.CredentialExpired),
        ["shutting-down"] = (RelayState.Backoff, ChannelReasons.CenterShuttingDown),
        ["token-expired"] = (RelayState.Backoff, ChannelReasons.CredentialExpired),
    };

    /// <summary>
    /// The exchanges of Cloud E1b (#145) whose center frames answer the node (a call, a relay nonce): their IDs and signatures are
    /// normalized placeholders, so they are compared frame by frame and field by field, not replayed to the real client.
    /// </summary>
    private static readonly string[] Answered = ["call-executed", "call-refused", "call-unverifiable", "relay-nonce"];

    public static TheoryData<string> Cases() => [.. Expected.Keys.Order(StringComparer.Ordinal)];

    public static TheoryData<string> AllCases() => [.. Expected.Keys.Concat(Answered).Order(StringComparer.Ordinal)];

    [Fact]
    public void TheVendoredChannelCapturesAreTheManifestsBytesOfTheCohortThisRepositoryUses()
    {
        var root = FakeCenterConformanceTests.VendoredManifest("channel-exchanges", 18, SourceCommit);
        Assert.Equal(ChannelContract.Cohort, root.GetProperty("contractsCohort").GetString());
        var cases = root.GetProperty("files").EnumerateArray().Select(file => file.GetProperty("file").GetString()!).ToList();
        Assert.Equal(Expected.Keys.Concat(Answered).Select(name => "NodeChannel-" + name + ".json").Order(StringComparer.Ordinal), cases);
        foreach (var name in Expected.Keys.Concat(Answered))
        {
            var capture = Load(name);
            Assert.Equal(ChannelContract.Cohort, capture.GetProperty("contractsCohort").GetString());
            Assert.Equal(2, capture.GetProperty("schemaVersion").GetInt32());
            Assert.Equal("NodeChannel", capture.GetProperty("method").GetString());
        }
    }

    [Theory]
    [MemberData(nameof(AllCases))]
    public void EveryCapturedCenterFrameIsValidAndThePeerSendsTheSameShapes(string name)
    {
        var capture = Load(name);
        var reply = capture.GetProperty("reply");
        if (reply.GetProperty("httpStatus").GetInt32() != 101)
        {
            // A refusal before the upgrade: 401 or 403 with the closed reason in the header (PN-3), as the peer answers.
            Assert.InRange(reply.GetProperty("httpStatus").GetInt32(), 401, 403);
            Assert.NotEqual(402, reply.GetProperty("httpStatus").GetInt32());
            Assert.Matches("^[A-Z]+/[a-z_]+$", capture.GetProperty("headers").GetProperty("reply arcforges-refusal").GetString()!);
            return;
        }

        var frames = Frames(reply).Select(bytes => (Bytes: bytes, Frame: RelayFrame.Parser.ParseFrom(bytes))).ToList();
        Assert.All(frames, frame => Assert.Equal(1U, frame.Frame.FrameVersion));
        // frame_seq only increases: the center's sequence may have gaps (abandoned frames, a refused enqueue, RelayClose; Cloud
        // center-fleet.md), and the node never checks contiguity.
        Assert.All(frames.Zip(frames.Skip(1)), pair => Assert.True(pair.Second.Frame.FrameSeq > pair.First.Frame.FrameSeq));

        // The center's first frame is the challenge, in the shape the peer sends.
        var challenge = frames[0].Frame;
        Assert.Equal(RelayFrame.FrameOneofCase.Challenge, challenge.FrameCase);
        Assert.True(RelayShapes.IsValid(challenge.Challenge));
        var peerChallenge = FakeChannelPeer.ChallengeFrame(challenge.Challenge.Nonce.ToByteArray(), challenge.Challenge.ConnectionId,
            ArcForges.Client.ProtoTime.ToDateTimeOffset(challenge.Challenge.HelloDeadline)!.Value);
        peerChallenge.FrameVersion = 1;
        peerChallenge.FrameSeq = 1;
        Assert.Equal(frames[0].Bytes, peerChallenge.ToByteArray());

        foreach (var (bytes, frame) in frames.Skip(1))
        {
            switch (frame.FrameCase)
            {
                case RelayFrame.FrameOneofCase.Accepted:
                    // The peer's acceptance carries the center's limits (the 1 MiB pin included) and the same fields.
                    Assert.True(RelayShapes.IsValid(frame.Accepted));
                    // The capture's hub runs with test-tuned heartbeats (60 s and 180 s); the frame pin, the in-flight and the nonce bounds
                    // are the defaults the peer uses too.
                    var peer = FakeChannelPeer.DefaultLimits;
                    var center = frame.Accepted.Limits;
                    Assert.Equal((peer.MaxFrameBytes, peer.MaxInFlightCalls, peer.MaxRelayNonces), (center.MaxFrameBytes, center.MaxInFlightCalls, center.MaxRelayNonces));
                    Assert.True(center.HasHeartbeatIntervalMs && center.HasHeartbeatDeadlineMs && peer.HasHeartbeatIntervalMs && peer.HasHeartbeatDeadlineMs);
                    // The peer's own acceptance with the hub's values is the hub's frame byte for byte (no node_name, as the hub sends).
                    var peerAccepted = FakeChannelPeer.AcceptedFrame(frame.Accepted.ConnectionId, center, frame.Accepted.SigningKids, null);
                    peerAccepted.FrameVersion = 1;
                    peerAccepted.FrameSeq = frame.FrameSeq;
                    Assert.Equal(bytes, peerAccepted.ToByteArray());
                    Assert.True(RelayShapes.IsValid(FakeChannelPeer.AcceptedFrame(frame.Accepted.ConnectionId, peer, frame.Accepted.SigningKids, null).Accepted));
                    Assert.Equal(challenge.Challenge.ConnectionId, frame.Accepted.ConnectionId);
                    break;
                case RelayFrame.FrameOneofCase.Close:
                    // The peer's close frame of the same code, reason and hint is the center's, byte for byte.
                    var close = FakeChannelPeer.CloseFrame(frame.Close.Code, frame.Close.Reason, frame.Close.HasReconnectAfterMs ? frame.Close.ReconnectAfterMs : null);
                    close.FrameVersion = 1;
                    close.FrameSeq = frame.FrameSeq;
                    Assert.Equal(bytes, close.ToByteArray());
                    Assert.Equal(reply.GetProperty("trailers").GetString(), "websocket-close: " + frame.Close.Code);
                    break;
                case RelayFrame.FrameOneofCase.Call:
                    // A routed call (E1b): the frame's shape, and the peer's framing of the same call is the hub's bytes.
                    Assert.True(RelayShapes.IsValid(frame.Call));
                    Assert.Equal(bytes, new RelayFrame { FrameVersion = 1, FrameSeq = frame.FrameSeq, Call = frame.Call }.ToByteArray());
                    Assert.True(RelayShapes.IsValid(CallHeader.Parser.ParseFrom(frame.Call.Header.Header)));
                    break;
                case RelayFrame.FrameOneofCase.RelayNonce:
                    Assert.True(RelayShapes.IsValid(frame.RelayNonce));
                    var nonce = FakeChannelPeer.NonceFrame(frame.RelayNonce.RequestId, frame.RelayNonce.Nonce.ToByteArray(),
                        ArcForges.Client.ProtoTime.ToDateTimeOffset(frame.RelayNonce.ExpiresAt)!.Value);
                    nonce.FrameVersion = 1;
                    nonce.FrameSeq = frame.FrameSeq;
                    Assert.Equal(bytes, nonce.ToByteArray());
                    break;
                default:
                    Assert.Fail("an unexpected center frame " + frame.FrameCase + " in " + name);
                    break;
            }
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task TheRealClientReadsEveryCapturedExchangeAsTheCenterMeantIt(string name)
    {
        var capture = Load(name);
        var reply = capture.GetProperty("reply");
        var status = reply.GetProperty("httpStatus").GetInt32();
        var close = status == 101 ? int.Parse(reply.GetProperty("trailers").GetString()!["websocket-close: ".Length..], System.Globalization.CultureInfo.InvariantCulture) : 0;
        var refusal = capture.GetProperty("headers").TryGetProperty("reply arcforges-refusal", out var header) ? header.GetString() : null;
        await using var link = await LinkFixture.CreateAsync();
        link.Channel = true;
        link.ChannelRandom = () => 0;

        // The "accepted" capture's close is the hub's echo of the node's own close: it is held until the node closes (here, SetCloudLink),
        // after the node's TokenRefresh for the refresh its unknown signing kid made (PN-14), as in the capture.
        link.Center.Channel.Replay = new FakeChannelReplay(status, refusal, Frames(reply), close, HoldAfter: name == "accepted" ? 1 : 0);
        await link.StartAsync();
        await link.SignInWithChannelAsync();
        if (name == "accepted")
        {
            await Eventually.TrueAsync(() => Reached(link, RelayState.Connected, ChannelReasons.Connected), "CONNECTED on the captured acceptance");
            Assert.True(await link.Service.SetCloudLinkAsync(false));
        }

        var (state, reason) = Expected[name];
        await Eventually.TrueAsync(() => Reached(link, state, reason), name + " -> " + state + " " + reason);
        if (status == 101)
        {
            // The node's hello to the captured challenge proves, by the center's own check, against the key the sign-in registered.
            var challenge = RelayFrame.Parser.ParseFrom(Frames(reply)[0]).Challenge;
            var hello = RelayFrame.Parser.ParseFrom(link.Center.Channel.ReplayReceived.First());
            Assert.Equal(RelayFrame.FrameOneofCase.NodeHello, hello.FrameCase);
            var installation = hello.NodeHello.InstallationId.Value.ToByteArray();
            Assert.Null(FakeChannelPeer.HelloFailure(hello.NodeHello, link.NodePublicKey, challenge.Nonce.ToByteArray(), challenge.ConnectionId,
                link.Center.Endpoint.Url, link.NodeId, installation));
        }

        if (name == "accepted")
        {
            // The node's own close, as the capture's node sent it: RelayClose 1000 node_closed.
            await Eventually.TrueAsync(() => link.Center.Channel.ReplayReceived.Count == 3, "the node's TokenRefresh and close at the replaying hub");
            var sent = link.Center.Channel.ReplayReceived.Skip(1).Select(bytes => RelayFrame.Parser.ParseFrom(bytes)).ToList();
            var captured = Frames(capture.GetProperty("request")).Skip(1).Select(bytes => RelayFrame.Parser.ParseFrom(bytes)).ToList();
            Assert.Equal(captured.Select(frame => frame.FrameCase), sent.Select(frame => frame.FrameCase));
            Assert.Equal(captured[^1].Close, sent[^1].Close);
        }

        if (name == "replaced")
        {
            await Eventually.TrueAsync(() => link.Notices().Contains(CloudLinkService.Notices.ChannelReplaced), "the replacement notice");
        }

        if (reason == ChannelReasons.CredentialExpired)
        {
            await Eventually.TrueAsync(() => link.Center.CallsOf("RefreshNodeSession").Count >= 1, "a refresh first (4401 or a 401)");
        }

        // The state lasts: no new upgrade while the node's clock stands still (BACKOFF waits at least 1 s of it); REFUSED waits past the
        // backoff's 60 s cap (30 minutes here: before the credential's own refresh, which also ends a REFUSED wait, at two thirds of 60).
        await Task.Delay(300, TestContext.Current.CancellationToken);
        Assert.Equal(1, link.Center.Channel.Upgrades);
        if (state == RelayState.Refused)
        {
            link.Clock.Advance(TimeSpan.FromMinutes(30));
            await Task.Delay(300, TestContext.Current.CancellationToken);
            Assert.Equal(1, link.Center.Channel.Upgrades);
        }
    }

    [Theory]
    [InlineData("call-executed")]
    [InlineData("call-refused")]
    [InlineData("relay-nonce")]
    public void TheNodesFramesHaveTheShapesTheHubAccepted(string name)
    {
        // The node side of the E1b captures (the center's nodetest peer): the ArcForges node's result for the captured call carries the
        // same ResultHeader fields, and its relay nonce request is the captured frame byte for byte.
        var capture = Load(name);
        var sent = Frames(capture.GetProperty("request")).Select(bytes => (Bytes: bytes, Frame: RelayFrame.Parser.ParseFrom(bytes))).ToList();
        var received = Frames(capture.GetProperty("reply")).Select(bytes => RelayFrame.Parser.ParseFrom(bytes)).ToList();
        if (name == "relay-nonce")
        {
            var request = sent.Single(frame => frame.Frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest);
            var built = new RelayFrame { FrameVersion = 1, FrameSeq = request.Frame.FrameSeq, RelayNonceRequest = new RelayNonceRequest { RequestId = request.Frame.RelayNonceRequest.RequestId } };
            Assert.Equal(request.Bytes, built.ToByteArray());
            Assert.Equal(request.Frame.RelayNonceRequest.RequestId, received.Single(frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonce).RelayNonce.RequestId);
            return;
        }

        var call = CallHeader.Parser.ParseFrom(received.Single(frame => frame.FrameCase == RelayFrame.FrameOneofCase.Call).Call.Header.Header);
        var captured = sent.Single(frame => frame.Frame.FrameCase == RelayFrame.FrameOneofCase.CallResult).Frame.CallResult;
        var capturedHeader = ResultHeader.Parser.ParseFrom(captured.Header.Header);
        Assert.True(RelayShapes.IsValid(capturedHeader));
        var root = Directory.CreateTempSubdirectory("arcforges-conformance-").FullName;
        try
        {
            using var key = NodeKeyStores.ForTestDataRoot(root).Create(capturedHeader.NodeId.Value.ToByteArray(), "https://center.example.test", TimeProvider.System);
            var signer = new ResultSigner(key, capturedHeader.NodeId.Value.ToByteArray(), TimeProvider.System);
            var ours = capturedHeader.Outcome == RoutedOutcome.Executed
                ? signer.Executed(call, captured.Payload)
                : signer.Refused(call, capturedHeader.Outcome, RoutedRefusals.Policy(RoutedRefusals.Operation(call.Method), RoutedRefusals.DispatchUnavailable, signer.NewCorrelation()));
            var oursHeader = ResultHeader.Parser.ParseFrom(ours.Header.Header);
            Assert.Equal(Present(capturedHeader), Present(oursHeader));
            Assert.Equal(Present(captured.Header), Present(ours.Header));
            Assert.Equal((capturedHeader.CallId, capturedHeader.Method, capturedHeader.RequestSha256), (oursHeader.CallId, oursHeader.Method, oursHeader.RequestSha256));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>The fields a message carries (presence, by field number).</summary>
    private static List<int> Present(IMessage message) =>
        [.. message.Descriptor.Fields.InFieldNumberOrder().Where(field => field.HasPresence ? field.Accessor.HasValue(message) : field.Accessor.GetValue(message) is not null)
            .Select(field => field.FieldNumber)];

    /// <summary>Whether the link published <paramref name="state"/> with <paramref name="reason"/> (the transitions, not only the last one).</summary>
    private static bool Reached(LinkFixture link, RelayState state, string reason)
    {
        lock (link.Publications)
        {
            return link.Publications.Any(publication => publication.Status.Relay == state && publication.Status.RelayReason == reason);
        }
    }

    private static List<byte[]> Frames(JsonElement wire) => [.. wire.GetProperty("frames").EnumerateArray().Select(frame => Convert.FromHexString(frame.GetString()!))];

    private static JsonElement Load(string name)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "channel-exchanges", "NodeChannel-" + name + ".json")));
        return document.RootElement.Clone();
    }
}
