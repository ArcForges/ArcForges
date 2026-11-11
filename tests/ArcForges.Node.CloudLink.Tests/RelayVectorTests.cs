// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// The node signs and verifies byte for byte against the Contracts golden vectors of the node channel (AF-CTR-05 C2,
/// <c>fixtures/internal/af-ctr-05-relay-vectors.json</c> at e67a6b0, vendored with a drift check; G.2 rows N1-13 and N1-14; PB-3): the
/// node's signing inputs equal the vectors', every vector signature verifies with the node's verifier, and a high-S signature, a signature
/// over the bare bytes and a signature under another kind's domain string are refused.
/// </summary>
public sealed class RelayVectorTests
{
    private static readonly JsonElement Root = Load();

    private static readonly string[] Kinds = ["call", "result", "hello", "origin"];

    private static CenterEndpoint Audience => CenterEndpoint.Parse(Root.GetProperty("audience").GetString()!);

    [Fact]
    public void TheVendoredVectorsAreTheContractsFileOfTheCohortThisRepositoryUses()
    {
        var manifest = FakeCenterConformanceTests.VendoredManifest("relay-vectors", 1, "e67a6b089a7270ab771a97c27aeba92c5d3b0469");
        // The published 450.1 producer (de3dba76266e89654be9b4d29d097d525a281c6a) carries this
        // exact historical fixture (SHA-256 8b6f1fb333a6aad96c32467b77148894ed0fce04d54fc9603c7b8c620fdec899).
        // Its existing relay field numbers are unchanged; the remaining tests exercise every golden
        // signature and frame with the 450.1 codecs. Do not relabel the historical 437.1 provenance.
        Assert.Equal("1.0.0-ci.437.1", manifest.GetProperty("contractsCohort").GetString());
        Assert.Equal("1.0.0-ci.450.1", ChannelContract.Cohort);
        Assert.Equal("af-ctr-05-relay-vectors.v1", Root.GetProperty("schemaVersion").GetString());
        var version = typeof(RelayFrame).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .Cast<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion;
        Assert.StartsWith(ChannelContract.Cohort, version, StringComparison.Ordinal);
    }

    [Fact]
    public void TheDomainStringsAreTheContracts()
    {
        var domains = Root.GetProperty("domains");
        Assert.Equal(RelaySignatures.CallDomain, domains.GetProperty("call").GetString());
        Assert.Equal(RelaySignatures.ResultDomain, domains.GetProperty("result").GetString());
        Assert.Equal(RelaySignatures.HelloDomain, domains.GetProperty("hello").GetString());
        Assert.Equal(RelaySignatures.OriginDomain, domains.GetProperty("origin").GetString());
        Assert.Equal([24, 26, 25, 26], Kinds.Select(kind => Root.GetProperty("domainLengths").GetProperty(kind).GetInt32()));
        Assert.Equal(Root.GetProperty("audienceSha256").GetString(), Convert.ToHexStringLower(RelaySignatures.Audience(Audience)));
    }

    [Fact]
    public void TheHelloProofIsBuiltByteForByteAndTheVectorSignatureVerifies()
    {
        var hello = Root.GetProperty("hello");
        var challenge = RelayFrame.Parser.ParseFrom(Hex(hello, "challengeFrame")).Challenge;
        var helloFrame = RelayFrame.Parser.ParseFrom(Hex(hello, "helloFrame")).NodeHello;
        Assert.Equal(Hex(hello, "nonce"), challenge.Nonce.ToByteArray());
        var input = RelaySignatures.HelloInput(challenge.Nonce.Span, challenge.ConnectionId, Audience, Id("node"), Id("installation"));
        Assert.Equal(Hex(hello, "signingInput"), input);
        Assert.Equal(RelaySignatures.HelloInputLength, input!.Length);
        Assert.Equal(Hex(hello, "signature"), helloFrame.HelloSignature.ToByteArray());
        Assert.True(RelaySignatures.Verify(Key("node"), input, Hex(hello, "signature")));
        Assert.False(RelaySignatures.Verify(Key("node"), input, Hex(hello, "highSSignature")), "a high-S hello proof is refused");
        Assert.False(RelaySignatures.Verify(Key("node"), input.AsSpan(RelaySignatures.HelloDomain.Length), Hex(hello, "signature")), "the bare bytes");
        Assert.False(RelaySignatures.Verify(Key("otherInstallation"), input, Hex(hello, "signature")), "another installation's key");

        // Exact lengths before any signing input (relay.proto, "Verifier pre-conditions"): nothing is padded or truncated.
        Assert.Null(RelaySignatures.HelloInput(challenge.Nonce.Span[..31], challenge.ConnectionId, Audience, Id("node"), Id("installation")));
        Assert.Null(RelaySignatures.HelloInput(challenge.Nonce.Span, new Id { Value = ByteString.CopyFrom(new byte[15]) }, Audience, Id("node"), Id("installation")));
        Assert.Null(RelaySignatures.HelloInput(challenge.Nonce.Span, challenge.ConnectionId, Audience, new byte[16], Id("installation")));
        Assert.Null(RelaySignatures.HelloInput(challenge.Nonce.Span, null, Audience, Id("node"), Id("installation")));
    }

    [Fact]
    public void TheVectorCallVerifiesWithTheNodesVerifierAndItsSigningInputIsTheContracts()
    {
        var vector = Root.GetProperty("routedCall");
        var frame = RelayFrame.Parser.ParseFrom(Hex(vector, "frame"));
        Assert.Equal(RelayFrame.FrameOneofCase.Call, frame.FrameCase);
        var call = frame.Call;
        Assert.Equal(Hex(vector, "signingInput"), RelaySignatures.CallInput(call.Header.Header.Span));
        Assert.True(RelaySignatures.Verify(Key("center"), Hex(vector, "signingInput"), Hex(vector, "signature")));
        Assert.False(RelaySignatures.Verify(Key("center"), Hex(vector, "signingInput"), Hex(vector, "highSSignature")), "a high-S call signature");
        Assert.False(RelaySignatures.Verify(Key("center"), Hex(vector, "callHeader"), Hex(vector, "signature")), "a signature over the bare header");
        Assert.False(RelaySignatures.Verify(Key("otherCenter"), Hex(vector, "signingInput"), Hex(vector, "signature")), "another center's key");

        var (header, refusal) = VectorVerifier().Check(call, VectorBinding());
        Assert.Null(refusal);
        Assert.Equal(Hex(vector, "payloadSha256"), header!.RequestSha256.ToByteArray());
        Assert.Equal(RoutedMethod.SubmitNodeTask, header.Method);
    }

    [Fact]
    public void TheVectorResultIsVerifiableAndTheNodeBuildsItsSigningInputTheSameWay()
    {
        var vector = Root.GetProperty("routedResult");
        var result = RelayFrame.Parser.ParseFrom(Hex(vector, "frame")).CallResult;
        Assert.Equal(Hex(vector, "resultHeader"), result.Header.Header.ToByteArray());
        Assert.Equal(Hex(vector, "signingInput"), RelaySignatures.ResultInput(result.Header.Header.Span));
        Assert.True(RelaySignatures.Verify(Key("node"), Hex(vector, "signingInput"), Hex(vector, "signature")));
        Assert.False(RelaySignatures.Verify(Key("node"), Hex(vector, "resultHeader"), Hex(vector, "signature")), "a result over the bare header (PB-3)");
        Assert.False(RelaySignatures.Verify(Key("node"), Hex(vector, "signingInput"), Hex(vector, "highSSignature")), "a high-S result");

        // A signature of one kind is never valid as another: the call domain over the same bytes does not verify.
        Assert.False(RelaySignatures.Verify(Key("node"), RelaySignatures.CallInput(Hex(vector, "resultHeader")), Hex(vector, "signature")));
    }

    [Theory]
    [InlineData("submit-own-node-human")]
    [InlineData("list-nodes-script")]
    [InlineData("get-node-human")]
    public void TheRelayAssertionSigningInputIsTheContractsAndTheVectorSignatureVerifies(string id)
    {
        var vector = Root.GetProperty("relayAssertions").EnumerateArray().Single(entry => entry.GetProperty("id").GetString() == id);
        var assertion = RelayAssertion.Parser.ParseFrom(Hex(vector, "assertion"));
        var input = RelaySignatures.AssertionInput(assertion, Audience);
        Assert.Equal(Hex(vector, "signingInput"), input);
        Assert.Equal(RelaySignatures.OriginInputLength, input!.Length);
        Assert.True(RelaySignatures.Verify(Key("node"), input, assertion.Signature.Span));
        Assert.False(RelaySignatures.Verify(Key("node"), input, Hex(vector, "highSSignature")));
        Assert.False(RelaySignatures.Verify(Key("node"), input.AsSpan(RelaySignatures.OriginDomain.Length), assertion.Signature.Span));

        // The layout's pre-conditions: a 31-byte nonce, a 121 s lifetime, an origin of 0 and an all-zero ID are refused before any input.
        Assert.Null(RelaySignatures.AssertionInput(Change(assertion, a => a.RelayNonce = ByteString.CopyFrom(new byte[31])), Audience));
        Assert.Null(RelaySignatures.AssertionInput(Change(assertion, a => a.ExpiresAt = new Instant { UnixSeconds = a.IssuedAt.UnixSeconds + 121, Nanos = a.IssuedAt.Nanos }), Audience));
        Assert.Null(RelaySignatures.AssertionInput(Change(assertion, a => a.LocalOrigin = ArcForges.Contracts.Node.V1.Origin.Unspecified), Audience));
        Assert.Null(RelaySignatures.AssertionInput(Change(assertion, a => a.RelayingNodeId = new Id { Value = ByteString.CopyFrom(new byte[16]) }), Audience));
    }

    [Fact]
    public void WorkspaceRelayAssertionsBindTheCommandIdOnlyForMutations()
    {
        var vector = Root.GetProperty("relayAssertions").EnumerateArray().Single(entry => entry.GetProperty("id").GetString() == "submit-own-node-human");
        var original = RelayAssertion.Parser.ParseFrom(Hex(vector, "assertion"));
        foreach (var method in new[] { RoutedMethod.ReadNodeFile, RoutedMethod.RegisterNodeWorkspace, RoutedMethod.UnregisterNodeWorkspace,
            RoutedMethod.ListNodeWorkspaces, RoutedMethod.GetNodeWorkspace })
        {
            var mutation = method is RoutedMethod.RegisterNodeWorkspace or RoutedMethod.UnregisterNodeWorkspace;
            var valid = Change(original, assertion =>
            {
                assertion.Method = method;
                assertion.CommandId = mutation ? original.CommandId.Clone() : null;
            });
            Assert.NotNull(RelaySignatures.AssertionInput(valid, Audience));
            valid.CommandId = mutation ? null : original.CommandId.Clone();
            Assert.Null(RelaySignatures.AssertionInput(valid, Audience));
        }

        Assert.Null(RelaySignatures.AssertionInput(Change(original, assertion => assertion.Method = RoutedMethod.WriteNodeFile), Audience));
    }

    [Fact]
    public void TheRelayCloseNonceAndChallengeFramesOfThePeerAreTheVectorsBytes()
    {
        // N1-19 (until the E1a captures are vendored): FakeCenter's channel peer encodes the frames as the contract's vectors do.
        var close = Root.GetProperty("relayClose");
        var frame = FakeChannelPeer.CloseFrame(4500, "center_shutting_down", 15000);
        frame.FrameVersion = 1;
        frame.FrameSeq = RelayFrame.Parser.ParseFrom(Hex(close, "frame")).FrameSeq;
        Assert.Equal(Hex(close, "frame"), frame.ToByteArray());
        Assert.Equal(new ChannelEnd(ArcForges.Contracts.Node.V1.RelayState.Backoff, ChannelReasons.CenterShuttingDown, Delay: TimeSpan.FromMilliseconds(15000)),
            ChannelPolicy.Closed(4500, 15000));

        var nonce = Root.GetProperty("relayNonce");
        var nonceFrame = RelayFrame.Parser.ParseFrom(Hex(nonce, "frame"));
        Assert.True(ArcForges.Contracts.Relay.Shapes.ContractShapeValidation.IsValid(nonceFrame.RelayNonce));
        Assert.Equal(Hex(nonce, "nonce"), nonceFrame.RelayNonce.Nonce.ToByteArray());
        var request = RelayFrame.Parser.ParseFrom(Hex(nonce, "requestFrame"));
        Assert.Equal(request.RelayNonceRequest.RequestId, nonceFrame.RelayNonce.RequestId);
        var built = new RelayFrame { FrameVersion = 1, FrameSeq = request.FrameSeq, RelayNonceRequest = new RelayNonceRequest { RequestId = request.RelayNonceRequest.RequestId } };
        Assert.Equal(Hex(nonce, "requestFrame"), built.ToByteArray());
    }

    internal static CallVerifier VectorVerifier()
    {
        var issued = Root.GetProperty("routedCall").GetProperty("issuedAt");
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(issued[0].GetInt64()) + TimeSpan.FromSeconds(1));
        return new CallVerifier(new RoutedCallLog(new NoStore(), clock), clock);
    }

    internal static CallBinding VectorBinding(string centerKey = "center") => new()
    {
        Center = Audience,
        NodeId = Id("node"),
        AccountId = Id("account"),
        InstallationId = Convert.ToHexStringLower(Id("installation")),
        Keys = new CloudKeySetFile
        {
            CenterUrl = Audience.Url,
            InstallationId = Convert.ToHexStringLower(Id("installation")),
            CommandKeys =
            [
                new CloudKeyEntry
                {
                    Kid = Root.GetProperty("keys").GetProperty("center").GetProperty("kid").GetString(),
                    Algorithm = "ES256",
                    Key = Convert.ToBase64String(Key(centerKey)),
                    NotBeforeMs = (Root.GetProperty("routedCall").GetProperty("issuedAt")[0].GetInt64() - 86_400) * 1000,
                    NotAfterMs = (Root.GetProperty("routedCall").GetProperty("issuedAt")[0].GetInt64() + 86_400) * 1000,
                },
            ],
        },
    };

    internal static JsonElement Vectors => Root;

    internal static byte[] Key(string name) => Convert.FromHexString(Root.GetProperty("keys").GetProperty(name).GetProperty("spki").GetString()!);

    internal static byte[] Id(string name) => Convert.FromHexString(Root.GetProperty("ids").GetProperty(name).GetString()!);

    internal static byte[] Hex(JsonElement element, string name) => Convert.FromHexString(element.GetProperty(name).GetString()!);

    private static T Change<T>(T message, Action<T> change)
        where T : IMessage<T>
    {
        var copy = message.Clone();
        change(copy);
        return copy;
    }

    private static JsonElement Load()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "relay-vectors", "af-ctr-05-relay-vectors.json")));
        return document.RootElement.Clone();
    }

    /// <summary>A store that refuses every write (the checks before the replay check write nothing).</summary>
    private sealed class NoStore : IRoutedCallStore
    {
        public Task<long> WriteAsync(Func<ArcForges.Node.Store.StoreTransaction, long> write) => throw new InvalidOperationException("No write in this test.");
    }
}
