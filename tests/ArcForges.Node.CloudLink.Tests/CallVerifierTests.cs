// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// The verification before policy (AF-CTR-05 CTR5-NODE-05; Design 11 T-11; G.2 rows N1-7..N1-13): REAL ES256 over the exact received bytes,
/// each step refusing before the next, in the binding order. The calls are signed here with a test command key (a center's signer is not the
/// node's code).
/// </summary>
public sealed class CallVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 6, 12, 0, 0, TimeSpan.Zero);
    private static readonly CenterEndpoint Center = CenterEndpoint.Parse("https://center.example.test/api");
    private static readonly byte[] Node = RandomNumberGenerator.GetBytes(16);
    private static readonly byte[] Account = RandomNumberGenerator.GetBytes(16);
    private static readonly byte[] Installation = RandomNumberGenerator.GetBytes(16);
    private static readonly ECDsa CommandKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private static readonly ECDsa OtherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private const string Kid = "cmd-test-0001";

    [Fact]
    public void AWellFormedCallPassesEveryCheck() => Assert.Null(Check(Build()).Refusal);

    [Fact]
    public void SignedWorkspaceCallsRequireCommandIdsExactlyForMutations()
    {
        foreach (var method in new[] { RoutedMethod.RegisterNodeWorkspace, RoutedMethod.UnregisterNodeWorkspace,
            RoutedMethod.ListNodeWorkspaces, RoutedMethod.GetNodeWorkspace })
        {
            var mutation = method is RoutedMethod.RegisterNodeWorkspace or RoutedMethod.UnregisterNodeWorkspace;
            var valid = Build(lifetime: TimeSpan.FromSeconds(35), change: header =>
            {
                header.Method = method;
                header.CommandId = mutation ? CommandIds.New() : null;
            });
            Assert.Null(Check(valid).Refusal);
            var bad = Build(lifetime: TimeSpan.FromSeconds(35), change: header =>
            {
                header.Method = method;
                header.CommandId = mutation ? null : CommandIds.New();
            });
            Assert.NotNull(Check(bad).Refusal);
        }

        // File reads and directory pages admit no command ID; later file mutations are still refused.
        foreach (var method in new[] { RoutedMethod.ReadNodeFile, RoutedMethod.SearchNodeFiles, RoutedMethod.ListNodeDirectory, RoutedMethod.GetNodeFileOperation })
        {
            Assert.Null(Check(Build(lifetime: TimeSpan.FromSeconds(35), change: header => header.Method = method)).Refusal);
            Assert.NotNull(Check(Build(lifetime: TimeSpan.FromSeconds(35), change: header =>
            {
                header.Method = method;
                header.CommandId = CommandIds.New();
            })).Refusal);
        }
        Assert.NotNull(Check(Build(lifetime: TimeSpan.FromSeconds(35), change: header => header.Method = RoutedMethod.WriteNodeFile)).Refusal);
    }

    [Fact]
    public void FileAndWorkspaceSignedLifetimesRespectTheirSeparateDeadlineAndExpiryBounds()
    {
        foreach (var method in new[] { RoutedMethod.ReadNodeFile, RoutedMethod.SearchNodeFiles, RoutedMethod.ListNodeDirectory, RoutedMethod.GetNodeFileOperation, RoutedMethod.GetNodeWorkspace })
        {
            Assert.Null(Check(Build(lifetime: TimeSpan.FromSeconds(35), change: header => header.Method = method)).Refusal);
            Assert.Equal("lifetime", Step(Build(lifetime: TimeSpan.FromSeconds(36), change: header => header.Method = method)));
            Assert.Equal("lifetime", Step(Build(lifetime: TimeSpan.FromSeconds(40), change: header =>
            {
                header.Method = method;
                header.Deadline = Add(header.IssuedAt, 16);
            })));
        }
    }

    [Fact]
    public void ACallSignedByAnUnknownKeyIsRefusedBeforeParsing()
    {
        // N1-7 and the "verify before parse" mutant: a header that is not even a protobuf, signed by an unknown key or not at all, fails at
        // the key or the signature, never at the header's shape (it is never decoded).
        var garbage = new byte[] { 0xFF, 0xFF, 0xFF, 0x0F };
        Assert.Equal("unknown_key", Step(Build(raw: garbage, frameKid: "cmd-unknown-01")));
        Assert.Equal("signature", Step(Build(raw: garbage, key: OtherKey)));
        Assert.Equal("header_shape", Step(Build(raw: garbage)));
        Assert.Equal("unknown_key", Step(Build(frameKid: "cmd-unknown-01")));
        Assert.Equal("signature", Step(Build(key: OtherKey)));
    }

    [Fact]
    public void AFlippedHeaderByteIsRefused() => Assert.Equal("signature", Step(Build(alterHeader: bytes => Flip(bytes, bytes.Length / 2))));

    [Fact]
    public void AFlippedPayloadByteIsRefused() => Assert.Equal("request_digest", Step(Build(alterPayload: bytes => Flip(bytes, 0))));

    [Fact]
    public void ASignatureThatIsHighSDerOrOfAnotherKindIsRefused()
    {
        Assert.Equal("signature", Step(Build(alterSignature: FakeChannelPeer.HighS)));
        Assert.Equal("signature", Step(Build(domain: RelaySignatures.ResultDomain)));
        Assert.Equal("signature", Step(Build(domain: RelaySignatures.HelloDomain)));
        Assert.Equal("signature", Step(Build(domain: string.Empty)));
        Assert.Equal("frame_shape", Step(Build(alterSignature: signature => [.. signature, 0])));
        Assert.Equal("frame_shape", Step(Build(alterSignature: signature => CommandKey.SignData(signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))));
        // The contract's shape rule already requires "ES256" (SignedHeader.algorithm), so another algorithm fails the frame's shape; the
        // node's own algorithm step stays behind it.
        Assert.Equal("frame_shape", Step(Build(algorithm: "ES384")));
    }

    [Fact]
    public void ACallForAnotherNodeIsRefused() => Assert.Equal("target_mismatch", Step(Build(change: header => header.TargetNodeId = Id(RandomNumberGenerator.GetBytes(16)))));

    [Fact]
    public void ACallForAnotherAccountIsRefused()
    {
        var other = Id(RandomNumberGenerator.GetBytes(16));
        Assert.Equal("account_mismatch", Step(Build(change: header =>
        {
            header.AccountId = other;
            header.Caller.AccountId = other;
        })));
    }

    [Fact]
    public void TheHeaderMustNameTheSignedKidTheCenterAndTheFramesCall()
    {
        Assert.Equal("kid_mismatch", Step(Build(change: header => header.Kid = "cmd-other-001")));
        Assert.Equal("center_mismatch", Step(Build(change: header => header.CenterUrlSha256 = ByteString.CopyFrom(SHA256.HashData(Encoding.UTF8.GetBytes("https://other.example.test/api"))))));
        Assert.Equal("call_id_mismatch", Step(Build(change: header => header.CallId = CommandIds.New())));
        Assert.Equal("request_digest", Step(Build(change: header => header.RequestSize += 1)));
        Assert.Equal("method", Step(Build(change: header => header.Method = RoutedMethod.ListNodes)));
        Assert.Equal("method", Step(Build(change: header => header.CommandId = CommandIds.New())));
        Assert.Equal("lifetime", Step(Build(change: header => header.Deadline = Add(header.ExpiresAt, 1))));
    }

    [Fact]
    public void AKeyFromAnotherCenterIsNotTrusted()
    {
        // N1-12: the key set of a previous center (or of another installation) is no key set for this one, although the kid and key match.
        var call = Build();
        Assert.Equal("unknown_key", Step(call, Binding() with { Keys = Keys(center: "https://previous.example.test/api") }));
        Assert.Equal("unknown_key", Step(call, Binding() with { Keys = Keys(installation: Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16))) }));
        Assert.Equal("unknown_key", Step(call, Binding() with { Keys = null }));
        Assert.Null(Check(call, Binding()).Refusal);
    }

    [Theory]
    [InlineData(0, 60, null)]
    [InlineData(120, 60, null)]
    [InlineData(121, 60, "not_yet_valid")]
    [InlineData(-179, 60, null)]
    [InlineData(-180, 60, "expired")]
    [InlineData(-300, 300, null)]
    [InlineData(0, 300, null)]
    [InlineData(0, 301, "lifetime")]
    public void TheWindowsAllow120SecondsOfSkewAndAtMost300SecondsOfLifetime(int issuedOffset, int lifetime, string? step)
    {
        // N1-10: issued_at <= now + 120 s; expires_at + 120 s > now; expires_at - issued_at <= 300 s (the contract's validator).
        Assert.Equal(step, Step(Build(issued: TimeSpan.FromSeconds(issuedOffset), lifetime: TimeSpan.FromSeconds(lifetime))));
    }

    [Fact]
    public void AKeyOutsideItsValidityPlusTheSkewIsNotValid()
    {
        var call = Build();
        var expired = Keys(entry: Entry(notAfter: Now - TimeSpan.FromSeconds(121)));
        var future = Keys(entry: Entry(notBefore: Now + TimeSpan.FromSeconds(121)));
        var edge = Keys(entry: Entry(notBefore: Now + TimeSpan.FromSeconds(120), notAfter: Now - TimeSpan.FromSeconds(120)));
        Assert.Equal("unknown_key", Step(call, Binding() with { Keys = expired }));
        Assert.Equal("unknown_key", Step(call, Binding() with { Keys = future }));
        Assert.Null(Check(call, Binding() with { Keys = edge }).Refusal);
        Assert.Equal("unknown_key", Step(call, Binding() with { Keys = Keys(entry: Entry(algorithm: "ES384")) }));

        // Review A N-6: the algorithm is required, and a key without its validity dates is not valid.
        Assert.Equal("unknown_key", Step(call, Binding() with { Keys = Keys(entry: Entry(algorithm: null)) }));
        var undated = Entry();
        undated.NotAfterMs = 0;
        Assert.Equal("unknown_key", Step(call, Binding() with { Keys = Keys(entry: undated) }));
        var unstarted = Entry();
        unstarted.NotBeforeMs = 0;
        Assert.Equal("unknown_key", Step(call, Binding() with { Keys = Keys(entry: unstarted) }));
    }

    /// <summary>
    /// Review A B-1: CTR5-NODE-05's order after the signature, pinned pair by pair: a call with the faults of two adjacent steps is refused
    /// by the earlier one (for example an expired call with a wrong digest gets STATE/expired).
    /// </summary>
    [Theory]
    [InlineData("kid", "center", "kid_mismatch")]
    [InlineData("center", "target", "center_mismatch")]
    [InlineData("target", "account", "target_mismatch")]
    [InlineData("account", "not_yet_valid", "account_mismatch")]
    [InlineData("account", "expired", "account_mismatch")]
    [InlineData("expired", "lifetime", "expired")]
    [InlineData("not_yet_valid", "lifetime", "not_yet_valid")]
    [InlineData("expired", "request_digest", "expired")]
    [InlineData("lifetime", "request_digest", "lifetime")]
    [InlineData("request_digest", "method", "request_digest")]
    [InlineData("method", "call_id", "method")]
    public void OfTwoFaultsTheEarlierStepOfTheBindingOrderWins(string first, string second, string step)
    {
        var call = Build(change: header =>
        {
            Fault(header, first);
            Fault(header, second);
        }, alterPayload: first == "request_digest" || second == "request_digest" ? bytes => Flip(bytes, 0) : null);
        Assert.Equal(step, Step(call));
        Assert.Equal(step == "expired" ? RoutedRefusals.Expired : RoutedRefusals.SignatureInvalid, Check(call).Refusal!.Code);
    }

    private static void Fault(CallHeader header, string step)
    {
        switch (step)
        {
            case "kid":
                header.Kid = "cmd-other-001";
                break;
            case "center":
                header.CenterUrlSha256 = ByteString.CopyFrom(SHA256.HashData(Encoding.UTF8.GetBytes("https://other.example.test/api")));
                break;
            case "target":
                header.TargetNodeId = Id(RandomNumberGenerator.GetBytes(16));
                break;
            case "account":
                header.AccountId = Id(RandomNumberGenerator.GetBytes(16));
                header.Caller.AccountId = header.AccountId;
                break;
            case "not_yet_valid":
                header.IssuedAt = Add(header.IssuedAt, 200);
                header.ExpiresAt = Add(header.ExpiresAt, 200);
                header.Deadline = Add(header.Deadline, 200);
                break;
            case "expired":
                header.IssuedAt = Add(header.IssuedAt, -400);
                header.ExpiresAt = Add(header.ExpiresAt, -400);
                header.Deadline = Add(header.Deadline, -400);
                break;
            case "lifetime":
                header.Deadline = Add(header.ExpiresAt, 1);
                break;
            case "request_digest":
                break;
            case "method":
                header.Method = RoutedMethod.ListNodes;
                break;
            case "call_id":
                header.CallId = CommandIds.New();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(step));
        }
    }

    private static Instant Add(Instant instant, int seconds) => new() { UnixSeconds = instant.UnixSeconds + seconds, Nanos = instant.Nanos };

    /// <summary>
    /// AF-CTR-05 N2b decisions Q12: a caller of kind AGENT_GRANT (reserved for AF-CTR-07) or of no kind never passes verification; the
    /// contract's shape of CenterCaller admits ACCOUNT_SESSION and NODE_RELAY only.
    /// </summary>
    [Fact]
    public void AnAgentGrantCallerIsRefusedAtVerification()
    {
        Assert.Equal("header_shape", Step(Build(header => header.Caller.Kind = CenterCallerKind.AgentGrant)));
        Assert.Equal("header_shape", Step(Build(header => header.Caller.ClearKind())));
        Assert.Null(Step(Build()));
    }

    [Fact]
    public void EveryStepIsInTheClosedVocabularyAndFitsTheLogColumn()
    {
        Assert.Equal(CallVerifier.Steps.Count, CallVerifier.Steps.Distinct(StringComparer.Ordinal).Count());
        Assert.All(CallVerifier.Steps, step => Assert.Matches("^[a-z_]{1,40}$", step));
    }

    internal static ChannelCall Build(Action<CallHeader>? change = null, byte[]? raw = null, ECDsa? key = null, string domain = RelaySignatures.CallDomain,
        string? frameKid = null, string algorithm = "ES256", TimeSpan? issued = null, TimeSpan? lifetime = null, Func<byte[], byte[]>? alterHeader = null,
        Func<byte[], byte[]>? alterPayload = null, Func<byte[], byte[]>? alterSignature = null)
    {
        var payload = new TaskServiceGetTaskRequest { TaskId = CommandIds.New() }.ToByteArray();
        var callId = CommandIds.New();
        var at = Now + (issued ?? TimeSpan.Zero);
        var header = new CallHeader
        {
            CallId = callId,
            Kid = Kid,
            CenterUrlSha256 = ByteString.CopyFrom(SHA256.HashData(Encoding.UTF8.GetBytes(Center.Url))),
            AccountId = Id(Account),
            TargetNodeId = Id(Node),
            Caller = new CenterCaller { Kind = CenterCallerKind.AccountSession, AccountId = Id(Account), UserId = CommandIds.New(), SessionId = CommandIds.New() },
            Method = RoutedMethod.GetNodeTask,
            RequestSha256 = ByteString.CopyFrom(SHA256.HashData(payload)),
            RequestSize = (uint)payload.Length,
            IssuedAt = ProtoTime.ToInstant(at),
            ExpiresAt = ProtoTime.ToInstant(at + (lifetime ?? TimeSpan.FromSeconds(60))),
            Deadline = ProtoTime.ToInstant(at + TimeSpan.FromSeconds(5)),
        };
        change?.Invoke(header);
        var bytes = raw ?? header.ToByteArray();
        var signature = FakeChannelPeer.Sign(key ?? CommandKey, [.. Encoding.ASCII.GetBytes(domain), .. bytes]);
        return new ChannelCall
        {
            CallId = callId,
            Header = new SignedHeader
            {
                Header = ByteString.CopyFrom(alterHeader?.Invoke(bytes) ?? bytes),
                Signature = ByteString.CopyFrom(alterSignature?.Invoke(signature) ?? signature),
                Kid = frameKid ?? Kid,
                Algorithm = algorithm,
            },
            Payload = ByteString.CopyFrom(alterPayload?.Invoke(payload) ?? payload),
        };
    }

    internal static CallBinding Binding() => new()
    {
        Center = Center,
        NodeId = Node,
        AccountId = Account,
        InstallationId = Convert.ToHexStringLower(Installation),
        Keys = Keys(),
    };

    private static CloudKeySetFile Keys(string? center = null, string? installation = null, CloudKeyEntry? entry = null) => new()
    {
        CenterUrl = center ?? Center.Url,
        InstallationId = installation ?? Convert.ToHexStringLower(Installation),
        CommandKeys = [entry ?? Entry()],
    };

    private static CloudKeyEntry Entry(DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, string? algorithm = "ES256") => new()
    {
        Kid = Kid,
        Algorithm = algorithm,
        Key = Convert.ToBase64String(CommandKey.ExportSubjectPublicKeyInfo()),
        NotBeforeMs = (notBefore ?? Now - TimeSpan.FromDays(1)).ToUnixTimeMilliseconds(),
        NotAfterMs = (notAfter ?? Now + TimeSpan.FromDays(1)).ToUnixTimeMilliseconds(),
    };

    private static (CallHeader? Header, CallRefusal? Refusal) Check(ChannelCall call, CallBinding? binding = null)
    {
        var clock = new ManualClock(Now);
        return new CallVerifier(new RoutedCallLog(new ThrowingStore(), clock), clock).Check(call, binding ?? Binding());
    }

    private static string? Step(ChannelCall call, CallBinding? binding = null) => Check(call, binding).Refusal?.Step;

    private static Id Id(byte[] value) => new() { Value = ByteString.CopyFrom(value) };

    private static byte[] Flip(byte[] bytes, int index)
    {
        var copy = (byte[])bytes.Clone();
        copy[index] ^= 0x01;
        return copy;
    }

    private sealed class ThrowingStore : IRoutedCallStore
    {
        public Task<long> WriteAsync(Func<ArcForges.Node.Store.StoreTransaction, long> write,
            ArcForges.Node.Store.CommitDurability durability = ArcForges.Node.Store.CommitDurability.Normal) => throw new InvalidOperationException("No write in this test.");
    }
}
