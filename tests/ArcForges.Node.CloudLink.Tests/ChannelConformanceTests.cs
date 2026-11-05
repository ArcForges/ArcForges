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
/// check). The peer's frames have the captured center frames' shapes and bytes, and the REAL node client, served each captured exchange
/// byte for byte, ends in the state the center meant.
/// </summary>
public sealed class ChannelConformanceTests
{
    private const string SourceCommit = "c14156bf97aadce9165fd7762aaf482d68d23bd9";

    /// <summary>What each captured exchange must leave the node in (SM-RELAY; relay.proto RelayClose; PN-3).</summary>
    private static readonly Dictionary<string, (RelayState State, string Reason)> Expected = new(StringComparer.Ordinal)
    {
        ["accepted"] = (RelayState.Backoff, ChannelReasons.CenterShuttingDown),
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

    public static TheoryData<string> Cases() => [.. Expected.Keys.Order(StringComparer.Ordinal)];

    [Fact]
    public void TheVendoredChannelCapturesAreTheManifestsBytesOfTheCohortThisRepositoryUses()
    {
        var root = FakeCenterConformanceTests.VendoredManifest("channel-exchanges", 14, SourceCommit);
        Assert.Equal(ChannelContract.Cohort, root.GetProperty("contractsCohort").GetString());
        var cases = root.GetProperty("files").EnumerateArray().Select(file => file.GetProperty("file").GetString()!).ToList();
        Assert.Equal(Expected.Keys.Select(name => "NodeChannel-" + name + ".json").Order(StringComparer.Ordinal), cases);
        foreach (var name in Expected.Keys)
        {
            var capture = Load(name);
            Assert.Equal(ChannelContract.Cohort, capture.GetProperty("contractsCohort").GetString());
            Assert.Equal(2, capture.GetProperty("schemaVersion").GetInt32());
            Assert.Equal("NodeChannel", capture.GetProperty("method").GetString());
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
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
        Assert.Equal(Enumerable.Range(1, frames.Count).Select(seq => (ulong)seq), frames.Select(frame => frame.Frame.FrameSeq));

        // The center's first frame is the challenge, in the shape the peer sends.
        var challenge = frames[0].Frame;
        Assert.Equal(RelayFrame.FrameOneofCase.Challenge, challenge.FrameCase);
        Assert.True(RelayShapes.IsValid(challenge.Challenge));
        var peerChallenge = new RelayFrame
        {
            FrameVersion = 1,
            FrameSeq = 1,
            Challenge = new ChannelChallenge { Nonce = challenge.Challenge.Nonce, ConnectionId = challenge.Challenge.ConnectionId, HelloDeadline = challenge.Challenge.HelloDeadline },
        };
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
                    Assert.True(RelayShapes.IsValid(new ChannelAccepted { ConnectionId = frame.Accepted.ConnectionId, Limits = peer, SigningKids = { frame.Accepted.SigningKids } }));
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
        link.Center.Channel.Replay = new FakeChannelReplay(status, refusal, status == 101 ? Frames(reply) : [], close);
        await link.StartAsync();
        await link.SignInWithChannelAsync();
        var (state, reason) = Expected[name];
        await Eventually.TrueAsync(() => link.Service.Status() is var now && now.Relay == state && now.RelayReason == reason,
            name + " -> " + state + " " + reason + " (now " + link.Service.Status().Relay + " " + link.Service.Status().RelayReason + ")");
        if (status == 101)
        {
            // The node answered the captured challenge with its hello (its proof over that nonce and connection ID).
            var hello = RelayFrame.Parser.ParseFrom(link.Center.Channel.ReplayReceived.First());
            Assert.Equal(RelayFrame.FrameOneofCase.NodeHello, hello.FrameCase);
            Assert.Equal(64, hello.NodeHello.HelloSignature.Length);
        }

        if (name == "replaced")
        {
            await Eventually.TrueAsync(() => link.Notices().Contains(CloudLinkService.Notices.ChannelReplaced), "the replacement notice");
        }

        if (reason == ChannelReasons.CredentialExpired)
        {
            await Eventually.TrueAsync(() => link.Center.CallsOf("RefreshNodeSession").Count >= 1, "a refresh first (4401 or a 401)");
        }
    }

    private static List<byte[]> Frames(JsonElement wire) => [.. wire.GetProperty("frames").EnumerateArray().Select(frame => Convert.FromHexString(frame.GetString()!))];

    private static JsonElement Load(string name)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "channel-exchanges", "NodeChannel-" + name + ".json")));
        return document.RootElement.Clone();
    }
}
