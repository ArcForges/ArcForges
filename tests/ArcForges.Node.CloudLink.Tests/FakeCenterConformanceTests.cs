// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N1-10: FakeCenter (MOCKED center) proven against REAL captures (CTR4-TST-03; delivery-5; N1 decisions R-6, G-5). The 53 exchanges the
/// Cloud integration test <c>TestFleetExchangeCapture</c> captured from the real Go center behind its ingress on real PostgreSQL (cohort
/// <c>1.0.0-ci.424.1</c>; Cloud 41c8a72, #136) are vendored byte for byte with a manifest. They pin message shapes and the center's refusals;
/// their proofs, tokens and IDs are normalized placeholders, so they pin no cryptography. The captures are the Go center's ingress, not the
/// hosted Worker: Worker replies stay contract-modelled.
/// </summary>
public sealed class FakeCenterConformanceTests
{
    private static readonly string Fixtures = Path.Combine(AppContext.BaseDirectory, "Fixtures");

    /// <summary>
    /// The reviewed table of outcomes FakeCenter emits that no capture pins yet (contract-modelled, with their source); the Cloud vectors PR
    /// adds captures for them (N1 decision G-5).
    /// </summary>
    private static readonly Dictionary<(string Method, string Outcome), string> ContractModelled = new()
    {
        [("RefreshNodeSession", "VALIDATION/invalid_argument")] = "center-fleet.md: an empty token or one over 8,192 bytes",
        [("ReportNodeInfo", "transport:auth.unauthenticated")] = "Design errors.md, the ingress table",
        [("ReportNodeInfo", "AUTHENTICATION/unauthenticated")] = "c0-decisions E-14; center-fleet.md: no live node row (captured for SignOutNode)",
        [("SignOutNode", "transport:auth.unauthenticated")] = "Design errors.md, the ingress table",
        [("SignOutNode", "transport:auth.token_expired")] = "Design errors.md, the ingress table",
        [("SignOutNode", "CONFLICT/command_id_reused")] = "fleet.proto SignOutNode idempotency: command_id",
    };

    public static TheoryData<string> Captures() =>
        [.. Directory.EnumerateFiles(Path.Combine(Fixtures, "center-exchanges"), "*.json").Select(path => Path.GetFileNameWithoutExtension(path)!).Order(StringComparer.Ordinal)];

    [Fact]
    public void TheVendoredCapturesAreTheManifestsBytesOfTheCohortThisRepositoryUses()
    {
        var root = VendoredManifest("center-exchanges", 53);

        // A cohort bump without a re-vendor fails: the captures name the cohort of the generated types this repository builds with.
        var cohort = root.GetProperty("contractsCohort").GetString()!;
        var version = typeof(NodeEnrollmentService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        Assert.StartsWith(cohort, version, StringComparison.Ordinal);
        foreach (var file in root.GetProperty("files").EnumerateArray())
        {
            Assert.Equal(cohort, Capture.Load(file.GetProperty("file").GetString()![..^5]).Cohort);
        }
    }

    /// <summary>
    /// Checks a vendored directory against its manifest (the Cloud source commit of Cloud #136, each file's SHA-256, the listing digest) and
    /// returns the manifest; a drifted, missing or extra file fails.
    /// </summary>
    internal static JsonElement VendoredManifest(string directory, int count)
    {
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Fixtures, directory + ".SOURCE.json")));
        var root = manifest.RootElement.Clone();
        Assert.Equal("41c8a72dbbd63efdb6967f71c23610ae2f73fae1", root.GetProperty("sourceCommit").GetString());
        var files = root.GetProperty("files").EnumerateArray().ToList();
        Assert.Equal(count, files.Count);
        var listing = new StringBuilder();
        var onDisk = Directory.EnumerateFiles(Path.Combine(Fixtures, directory), "*.json").Select(Path.GetFileName).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(files.Select(file => file.GetProperty("file").GetString()), onDisk);
        foreach (var file in files)
        {
            var name = file.GetProperty("file").GetString()!;
            var sha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(Fixtures, directory, name))));
            Assert.Equal(file.GetProperty("sha256").GetString(), sha);
            listing.Append(name).Append(' ').Append(sha).Append('\n');
        }

        Assert.Equal(root.GetProperty("listingSha256").GetString(), Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(listing.ToString()))));
        return root;
    }

    [Theory]
    [MemberData(nameof(Captures))]
    public async Task TheRealClientReadsEveryCapturedReplyAsTheCenterMeantIt(string name)
    {
        var capture = Capture.Load(name);
        await using var center = await FakeCenter.StartAsync();
        using var http = new CenterHttpClient(center.Endpoint);
        var client = new CenterClient(http, TimeProvider.System);
        center.Script(capture.Method, new FakeFault.Raw(capture.ReplyBody()));
        var outcome = capture.Method switch
        {
            "BeginNodeSignIn" => Outcome(await client.BeginNodeSignInAsync(new NodeEnrollmentServiceBeginNodeSignInRequest(), CancellationToken.None)),
            "CompleteNodeSignIn" => Outcome(await client.CompleteNodeSignInAsync(new NodeEnrollmentServiceCompleteNodeSignInRequest(), CancellationToken.None)),
            "StartDeviceAuthorization" => Outcome(await client.StartDeviceAuthorizationAsync(new NodeEnrollmentServiceStartDeviceAuthorizationRequest(), CancellationToken.None)),
            "PollDeviceAuthorization" => Outcome(await client.PollDeviceAuthorizationAsync(new NodeEnrollmentServicePollDeviceAuthorizationRequest(), CancellationToken.None)),
            "RefreshNodeSession" => Outcome(await client.RefreshAsync("afr1.x", CancellationToken.None)),
            "ReportNodeInfo" => Outcome(await client.ReportNodeInfoAsync("afa1.x", new EnrollingNodeInfo(), CommandIds.New(), CancellationToken.None)),
            "SignOutNode" => Outcome(await client.SignOutNodeAsync("afa1.x", CommandIds.New(), CancellationToken.None)),
            _ => throw new InvalidOperationException(capture.Method),
        };
        Assert.Equal(capture.Outcome, outcome);
    }

    [Theory]
    [InlineData("RefreshNodeSession-ok")]
    [InlineData("RefreshNodeSession-spent-token")]
    [InlineData("RefreshNodeSession-unknown-token")]
    [InlineData("RefreshNodeSession-account-token")]
    [InlineData("ReportNodeInfo-ok")]
    [InlineData("ReportNodeInfo-command-id-reused")]
    [InlineData("ReportNodeInfo-node-id-mismatch")]
    [InlineData("SignOutNode-ok")]
    [InlineData("SignOutNode-retry-after-revocation")]
    [InlineData("RefreshNodeSession-token-expired")]
    [InlineData("RefreshNodeSession-rate-limited")]
    [InlineData("RefreshNodeSession-device-revoked")]
    [InlineData("ReportNodeInfo-token-expired")]
    [InlineData("ReportNodeInfo-credential-revoked")]
    [InlineData("ReportNodeInfo-restricted-account")]
    [InlineData("SignOutNode-node-not-live")]
    public async Task TheRealClientBuildsTheCapturedRequests(string name)
    {
        var capture = Capture.Load(name);
        await using var center = await FakeCenter.StartAsync();
        using var http = new CenterHttpClient(center.Endpoint);
        var client = new CenterClient(http, TimeProvider.System);
        var payload = capture.RequestPayload();
        var bearer = capture.Authorization?["Bearer ".Length..];
        switch (capture.Method)
        {
            case "RefreshNodeSession":
                await client.RefreshAsync(NodeEnrollmentServiceRefreshNodeSessionRequest.Parser.ParseFrom(payload).RefreshToken, CancellationToken.None);
                break;
            case "ReportNodeInfo":
                var report = NodeEnrollmentServiceReportNodeInfoRequest.Parser.ParseFrom(payload);
                await client.ReportNodeInfoAsync(bearer!, report.Node, report.Meta.CommandId, CancellationToken.None);
                break;
            default:
                await client.SignOutNodeAsync(bearer!, NodeEnrollmentServiceSignOutNodeRequest.Parser.ParseFrom(payload).Meta.CommandId, CancellationToken.None);
                break;
        }

        var sent = Assert.Single(center.Calls);
        Assert.Equal(capture.Authorization, sent.Authorization);
        Assert.Contains(sent.ContentType, (string[])["application/grpc-web", "application/grpc-web+proto"]);

        // The node's own correlation ID is the only difference (the captures carry the test's request values; correlation excluded).
        Assert.Equal(capture.RequestFrame(), WithoutCorrelation(capture.Method, sent.Body));
    }

    [Theory]
    [InlineData("RefreshNodeSession-ok")]
    [InlineData("RefreshNodeSession-spent-token")]
    [InlineData("RefreshNodeSession-unknown-token")]
    [InlineData("RefreshNodeSession-account-token")]
    [InlineData("ReportNodeInfo-ok")]
    [InlineData("ReportNodeInfo-command-id-reused")]
    [InlineData("ReportNodeInfo-node-id-mismatch")]
    [InlineData("SignOutNode-ok")]
    [InlineData("SignOutNode-retry-after-revocation")]
    [InlineData("RefreshNodeSession-token-expired")]
    [InlineData("RefreshNodeSession-rate-limited")]
    [InlineData("RefreshNodeSession-device-revoked")]
    [InlineData("ReportNodeInfo-token-expired")]
    [InlineData("ReportNodeInfo-credential-revoked")]
    [InlineData("ReportNodeInfo-restricted-account")]
    [InlineData("SignOutNode-node-not-live")]
    public async Task FakeCenterAnswersTheCapturedRequestsWithTheCapturedBytes(string name)
    {
        var capture = Capture.Load(name);
        await using var center = await FakeCenter.StartAsync();

        // The capture's clock (its instants are offsets from the harness clock at the call) and its placeholder values.
        center.Clock = new ManualClock(DateTimeOffset.UnixEpoch);
        var payload = capture.RequestPayload();
        var reply = capture.ReplyMessage();
        var bearer = capture.Authorization?["Bearer ".Length..];
        switch (name)
        {
            case "RefreshNodeSession-ok":
                center.Seed(new byte[16], "afa1.seeded", NodeEnrollmentServiceRefreshNodeSessionRequest.Parser.ParseFrom(payload).RefreshToken);
                var value = ((NodeEnrollmentServiceRefreshNodeSessionResponse)reply).Value;
                center.NextTokens.Enqueue(value.AccessToken);
                center.NextTokens.Enqueue(value.RefreshToken);
                break;
            case "RefreshNodeSession-spent-token":
                var spent = NodeEnrollmentServiceRefreshNodeSessionRequest.Parser.ParseFrom(payload).RefreshToken;
                center.Seed(new byte[16], "afa1.seeded", spent);
                center.MarkSpent(spent);
                break;
            case "RefreshNodeSession-account-token":
                center.AccountTokens.Add(NodeEnrollmentServiceRefreshNodeSessionRequest.Parser.ParseFrom(payload).RefreshToken);
                break;
            case "ReportNodeInfo-ok":
            case "ReportNodeInfo-command-id-reused":
                var report = NodeEnrollmentServiceReportNodeInfoRequest.Parser.ParseFrom(payload);
                center.Seed(report.Node.NodeId.Value.Span, bearer!, "afr1.seeded");
                if (name.EndsWith("reused", StringComparison.Ordinal))
                {
                    // The capture's first report under this command ID named the node "buildbox".
                    var first = report.Clone();
                    first.Node.Name = "buildbox";
                    center.NextCorrelations.Enqueue(new byte[16]);
                    center.Reply(capture.Method, capture.Authorization, FakeCenter.DataFrame(first));
                }

                break;
            case "ReportNodeInfo-node-id-mismatch":
                center.Seed(RandomNumberGenerator.GetBytes(16), bearer!, "afr1.seeded");
                break;
            case "SignOutNode-ok":
                center.Seed(new byte[16], bearer!, "afr1.seeded");
                break;
            case "SignOutNode-retry-after-revocation":
            case "ReportNodeInfo-credential-revoked":
                center.Seed(new byte[16], bearer!, "afr1.seeded", revoked: true);
                break;
            case "RefreshNodeSession-token-expired":
                center.Seed(new byte[16], "afa1.seeded", NodeEnrollmentServiceRefreshNodeSessionRequest.Parser.ParseFrom(payload).RefreshToken, familyExpired: true);
                break;
            case "RefreshNodeSession-rate-limited":
                center.RefreshSessionLimit = 2;
                center.Seed(new byte[16], "afa1.seeded", NodeEnrollmentServiceRefreshNodeSessionRequest.Parser.ParseFrom(payload).RefreshToken, refreshesUsed: 2);
                break;
            case "RefreshNodeSession-device-revoked":
                center.Seed(new byte[16], "afa1.seeded", NodeEnrollmentServiceRefreshNodeSessionRequest.Parser.ParseFrom(payload).RefreshToken, revoked: true);
                break;
            case "ReportNodeInfo-token-expired":
                center.Seed(new byte[16], bearer!, "afr1.seeded", accessExpired: true);
                break;
            case "ReportNodeInfo-restricted-account":
                center.Seed(NodeEnrollmentServiceReportNodeInfoRequest.Parser.ParseFrom(payload).Node.NodeId.Value.Span, bearer!, "afr1.seeded", restricted: true);
                break;
            case "SignOutNode-node-not-live":
                center.Seed(new byte[16], bearer!, "afr1.seeded", nodeLive: false);
                break;
            default:
                break;
        }

        if (capture.ReplyCorrelation() is { } correlation)
        {
            center.NextCorrelations.Enqueue(correlation);
        }

        var (body, status) = center.Reply(capture.Method, capture.Authorization, capture.RequestFrame());
        Assert.Equal(capture.HttpStatus, status);
        Assert.Equal(Convert.ToHexString(capture.ReplyBody()), Convert.ToHexString(body));
    }

    [Fact]
    public void EveryOutcomeFakeCenterEmitsIsCapturedOrAReviewedContractModelledRow()
    {
        var captured = Directory.EnumerateFiles(Path.Combine(Fixtures, "center-exchanges"), "*.json").Select(path => Capture.Load(Path.GetFileNameWithoutExtension(path)))
            .Select(capture => (capture.Method, capture.Outcome)).ToHashSet();
        foreach (var outcome in FakeCenter.Outcomes)
        {
            Assert.True(captured.Contains(outcome) || ContractModelled.ContainsKey(outcome), $"{outcome.Method} {outcome.Outcome} is neither captured nor a reviewed row");
            Assert.False(captured.Contains(outcome) && ContractModelled.ContainsKey(outcome), $"{outcome.Method} {outcome.Outcome} is captured now: drop its row");
        }

        // Every captured outcome of the methods FakeCenter serves is one FakeCenter emits.
        foreach (var outcome in captured.Where(item => item.Method is "RefreshNodeSession" or "ReportNodeInfo" or "SignOutNode"))
        {
            Assert.Contains(outcome, FakeCenter.Outcomes);
        }

        Assert.All(ContractModelled.Keys, key => Assert.Contains(key, FakeCenter.Outcomes));
    }

    private static string Outcome<T>(CenterReply<T> reply)
        where T : class => reply.Outcome switch
        {
            CenterOutcome.Value => "ok",
            CenterOutcome.Transport => "transport:" + reply.TransportCode,
            CenterOutcome.Refused when reply.Error!.Code == "already_exists" => reply.Code + ":" + reply.Error.Details?.State?.State,
            CenterOutcome.Refused => reply.Code!,
            _ => reply.Outcome + " " + reply.Detail,
        };

    private static byte[] WithoutCorrelation(string method, byte[] body)
    {
        IMessage message = method switch
        {
            "RefreshNodeSession" => NodeEnrollmentServiceRefreshNodeSessionRequest.Parser.ParseFrom(FakeCenter.Payload(body)),
            "ReportNodeInfo" => NodeEnrollmentServiceReportNodeInfoRequest.Parser.ParseFrom(FakeCenter.Payload(body)),
            _ => NodeEnrollmentServiceSignOutNodeRequest.Parser.ParseFrom(FakeCenter.Payload(body)),
        };
        var meta = (RequestMeta)message.Descriptor.FindFieldByName("meta").Accessor.GetValue(message);
        meta.CorrelationId = null;
        return FakeCenter.DataFrame(message);
    }

    /// <summary>One vendored capture file.</summary>
    private sealed class Capture
    {
        private JsonElement _root;

        public required string Method { get; init; }

        public required string Outcome { get; init; }

        public required string Cohort { get; init; }

        public string? Authorization { get; init; }

        public int HttpStatus => _root.GetProperty("reply").GetProperty("httpStatus").GetInt32();

        public static Capture Load(string name)
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Fixtures, "center-exchanges", name + ".json")));
            var root = document.RootElement.Clone();
            return new Capture
            {
                _root = root,
                Method = root.GetProperty("method").GetString()!,
                Outcome = root.GetProperty("outcome").GetString()!,
                Cohort = root.GetProperty("contractsCohort").GetString()!,
                Authorization = root.GetProperty("headers").TryGetProperty("authorization", out var authorization) ? authorization.GetString() : null,
            };
        }

        public byte[] RequestFrame() => Convert.FromHexString(_root.GetProperty("request").GetProperty("frames")[0].GetString()!);

        public byte[] RequestPayload() => FakeCenter.Payload(RequestFrame());

        public byte[] ReplyBody()
        {
            var reply = _root.GetProperty("reply");
            var frames = reply.GetProperty("frames").EnumerateArray().SelectMany(frame => Convert.FromHexString(frame.GetString()!)).ToList();
            var trailers = Encoding.ASCII.GetBytes(reply.GetProperty("trailers").GetString()!);
            var trailer = new byte[5 + trailers.Length];
            trailer[0] = 0x80;
            BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(1), (uint)trailers.Length);
            trailers.CopyTo(trailer, 5);
            return [.. frames, .. trailer];
        }

        public IMessage ReplyMessage()
        {
            var frames = _root.GetProperty("reply").GetProperty("frames");
            if (frames.GetArrayLength() == 0)
            {
                return new Empty();
            }

            var payload = FakeCenter.Payload(Convert.FromHexString(frames[0].GetString()!));
            return Method switch
            {
                "RefreshNodeSession" => NodeEnrollmentServiceRefreshNodeSessionResponse.Parser.ParseFrom(payload),
                "ReportNodeInfo" => NodeEnrollmentServiceReportNodeInfoResponse.Parser.ParseFrom(payload),
                _ => NodeEnrollmentServiceSignOutNodeResponse.Parser.ParseFrom(payload),
            };
        }

        public byte[]? ReplyCorrelation()
        {
            var reply = ReplyMessage();
            if (reply is Empty)
            {
                return null;
            }

            var meta = reply.Descriptor.FindFieldByName("meta") is { } field ? field.Accessor.GetValue(reply) as ResponseMeta : null;
            return meta?.CorrelationId?.Value.ToByteArray();
        }
    }

    /// <summary>The empty reply of a trailers-only refusal.</summary>
    private sealed class Empty : IMessage
    {
        public Google.Protobuf.Reflection.MessageDescriptor Descriptor => throw new NotSupportedException();

        public int CalculateSize() => 0;

        public void MergeFrom(CodedInputStream input)
        {
        }

        public void WriteTo(CodedOutputStream output)
        {
        }
    }
}
