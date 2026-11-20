// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink.Tests;

public sealed class V2ChannelProtocolTests
{
    private static readonly CenterEndpoint Center = CenterEndpoint.Parse("https://center.example.test/managed");

    [Fact]
    public void TheProofSignsTheExactEnrollmentFenceOwnerAndQualificationVector()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-v2-channel-");
        try
        {
            var node = Repeated(0x11, 16);
            var installation = Repeated(0x22, 16);
            var owner = Repeated(0x33, 16);
            var challengeBytes = Challenge();
            Assert.True(V2ChannelProtocol.TryChallenge(new(V2ChannelKind.Challenge, challengeBytes), out var challenge));
            var ticket = new ChannelTicket(Center, "fixture-token", 1, node, installation)
            {
                UseV2 = true,
                AccountId = challenge.AccountId.ToArray(),
            };
            var snapshot = new V2ChannelSnapshot(owner, "204", 2, ["linux-bubblewrap-sdk-v1"]);
            using var key = NodeKeyStores.ForTestDataRoot(root.FullName).Create(node, Center.Origin, TimeProvider.System);
            var hello = V2ChannelProtocol.Hello(ticket, snapshot, challenge, key);
            Assert.NotNull(hello);

            byte[] expected = [.. node, .. installation, .. owner, 3, (byte)'2', (byte)'0', (byte)'4', 2, 2,
                .. LengthPrefixed("cohort-ci.481.1"), .. LengthPrefixed("linux-bubblewrap-sdk-v1")];
            Assert.Equal(expected, hello[..^64]);
            byte[] audience = SHA256.HashData(Encoding.UTF8.GetBytes(Center.Url));
            byte[] signed = [.. "ArcForges relay-hello v2\n"u8, .. challengeBytes, .. audience, .. expected];
            Assert.True(RelaySignatures.Verify(key.PublicKey, signed, hello.AsSpan(^64)));
            byte[] legacy = [.. "ArcForges relay-hello v1\n"u8, .. challengeBytes, .. audience, .. expected];
            Assert.False(RelaySignatures.Verify(key.PublicKey, legacy, hello.AsSpan(^64)));

            var malformed = snapshot with { Capabilities = ["linux-bubblewrap-sdk-v1", "linux-bubblewrap-sdk-v1"] };
            Assert.Null(V2ChannelProtocol.Hello(ticket, malformed, challenge, key));
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public void AcceptanceIsExactAndThePrivateRouteDoesNotSelectTheLegacyCodec()
    {
        var challengeBytes = Challenge();
        var framedChallenge = V2ChannelProtocol.Encode(V2ChannelKind.Challenge, 1, challengeBytes);
        Assert.Equal(new byte[] { 2, 1, 0, 0, 0, 0, 0, 0, 0, 1 }, framedChallenge[..10]);
        Assert.False(V2ChannelProtocol.TryDecode(framedChallenge, 2, out _));
        Assert.True(V2ChannelProtocol.TryDecode(framedChallenge, 1, out var frame));
        Assert.True(V2ChannelProtocol.TryChallenge(frame, out var challenge));
        Assert.Equal("wss://center.example.test/managed/fleet/v2/node", CenterChannelClient.ChannelUri(Center, useV2: true).AbsoluteUri);
        Assert.Equal("wss://center.example.test/managed/fleet/v1/node", CenterChannelClient.ChannelUri(Center).AbsoluteUri);

        var acceptance = new byte[68];
        challengeBytes.AsSpan(32, 48).CopyTo(acceptance);
        BinaryPrimitives.WriteUInt64BigEndian(acceptance.AsSpan(48), 7);
        BinaryPrimitives.WriteUInt32BigEndian(acceptance.AsSpan(56), 1_048_576);
        BinaryPrimitives.WriteUInt32BigEndian(acceptance.AsSpan(60), 20_000);
        BinaryPrimitives.WriteUInt32BigEndian(acceptance.AsSpan(64), 60_000);
        Assert.True(V2ChannelProtocol.TryAccept(new(V2ChannelKind.Accepted, acceptance), challenge, out var limits));
        Assert.Equal(60_000U, limits.HeartbeatDeadlineMilliseconds);

        BinaryPrimitives.WriteUInt64BigEndian(acceptance.AsSpan(48), 8);
        Assert.False(V2ChannelProtocol.TryAccept(new(V2ChannelKind.Accepted, acceptance), challenge, out _));
        framedChallenge[0] = 1;
        Assert.False(V2ChannelProtocol.TryDecode(framedChallenge, 1, out _));
    }

    private static byte[] Challenge()
    {
        byte[] payload = [.. Repeated(0x44, 32), .. Repeated(0x55, 16), .. Repeated(0x66, 16),
            .. Repeated(0x77, 16), .. Repeated(0x88, 16), .. new byte[16]];
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(96), 7);
        BinaryPrimitives.WriteInt64BigEndian(payload.AsSpan(104), 1_750_000_000_000L);
        return payload;
    }

    private static byte[] Repeated(byte value, int count) => [.. Enumerable.Repeat(value, count)];

    private static byte[] LengthPrefixed(string value) => [(byte)value.Length, .. Encoding.ASCII.GetBytes(value)];
}
