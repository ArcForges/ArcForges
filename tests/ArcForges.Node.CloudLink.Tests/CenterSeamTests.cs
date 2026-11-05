// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Core;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N1-7 (REAL files: the key sets), N1-8 (the one HTTP seam, REAL loopback sockets) and N1-15 (the refusal mapping) against FakeCenter
/// (MOCKED center).
/// </summary>
public sealed class CenterSeamTests
{
    [Fact]
    public async Task TestRequestsCarryThePathBaseOnceAndTheContractDeadline()
    {
        await using var center = await FakeCenter.StartAsync("/api/v2");
        using var http = new CenterHttpClient(center.Endpoint);
        var client = new CenterClient(http, TimeProvider.System);
        await client.RefreshAsync("afr1.unknown", CancellationToken.None);
        await client.RefreshAsync("afr1.unknown", CancellationToken.None);
        Assert.All(center.Calls, call =>
        {
            Assert.Equal("/api/v2/arcforges.fleet.v1.NodeEnrollmentService/RefreshNodeSession", call.Path);
            Assert.Equal("application/grpc-web", call.ContentType);
            Assert.NotNull(call.GrpcTimeout);
            Assert.InRange(ParseTimeoutSeconds(call.GrpcTimeout!), 8, 10);
        });

        await using var bare = await FakeCenter.StartAsync(string.Empty);
        using var bareHttp = new CenterHttpClient(bare.Endpoint);
        await new CenterClient(bareHttp, TimeProvider.System).RefreshAsync("afr1.unknown", CancellationToken.None);
        Assert.Equal("/arcforges.fleet.v1.NodeEnrollmentService/RefreshNodeSession", Assert.Single(bare.Calls).Path);
    }

    [Fact]
    public async Task TheAccessTokenGoesOnlyToTheCredentialedMethodsAndTheRefreshTokenOnlyInTheRefreshBody()
    {
        await using var center = await FakeCenter.StartAsync();
        using var http = new CenterHttpClient(center.Endpoint);
        var client = new CenterClient(http, TimeProvider.System);
        var node = new byte[16];
        var issued = center.Issue(node);
        await client.ReportNodeInfoAsync(issued.AccessToken, new EnrollingNodeInfo { NodeId = new Id { Value = ByteString.CopyFrom(node) }, Name = "n" },
            CommandIds.New(), CancellationToken.None);
        await client.RefreshAsync(issued.RefreshToken, CancellationToken.None);
        await client.StartDeviceAuthorizationAsync(new NodeEnrollmentServiceStartDeviceAuthorizationRequest(), CancellationToken.None);
        await client.SignOutNodeAsync("afa1.other", CommandIds.New(), CancellationToken.None);
        var calls = center.Calls;
        Assert.Equal("Bearer " + issued.AccessToken, calls.Single(call => call.Method == "ReportNodeInfo").Authorization);
        Assert.Equal("Bearer afa1.other", calls.Single(call => call.Method == "SignOutNode").Authorization);
        Assert.Null(calls.Single(call => call.Method == "RefreshNodeSession").Authorization);
        Assert.Null(calls.Single(call => call.Method == "StartDeviceAuthorization").Authorization);
        Assert.Contains(issued.RefreshToken, Encoding.ASCII.GetString(calls.Single(call => call.Method == "RefreshNodeSession").Body), StringComparison.Ordinal);
        Assert.All(calls.Where(call => call.Method != "RefreshNodeSession"),
            call => Assert.DoesNotContain(issued.RefreshToken, Encoding.ASCII.GetString(call.Body), StringComparison.Ordinal));
    }

    [Fact]
    public async Task TestNoRequestLeavesTheConfiguredCenterAndNoRedirectIsFollowed()
    {
        await using var center = await FakeCenter.StartAsync();
        var log = Path.Combine(Path.GetTempPath(), "arcforges-connect-" + Guid.NewGuid().ToString("N") + ".log");
        try
        {
            using var http = new CenterHttpClient(center.Endpoint, log);

            // The guard refuses a request URI of another authority (a rewritten URI). It does not see redirects: the socket handler would
            // follow them below it, so the transport follows none (AllowAutoRedirect false), which the redirect case below proves.
            var guard = new CenterHttpClient.AuthorityGuardHandler(center.Endpoint, log) { InnerHandler = new SocketsHttpHandler() };
            using var invoker = new HttpMessageInvoker(guard);
            foreach (var foreign in new[] { "http://127.0.0.2:" + center.Endpoint.Port + "/api/x", "https://127.0.0.1:" + center.Endpoint.Port + "/api/x",
                "http://127.0.0.1:" + (center.Endpoint.Port + 1) + "/api/x", "http://localhost:" + center.Endpoint.Port + "/api/x" })
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, foreign);
                var refused = await Assert.ThrowsAsync<HttpRequestException>(() => invoker.SendAsync(request, CancellationToken.None));
                Assert.Contains("only to its configured center", refused.Message, StringComparison.Ordinal);
            }

            await new CenterClient(http, TimeProvider.System).RefreshAsync("afr1.unknown", CancellationToken.None);
            var lines = File.ReadAllLines(log);
            Assert.Equal(5, lines.Length);
            Assert.All(lines.Take(4), line => Assert.EndsWith(" refused", line, StringComparison.Ordinal));
            Assert.Equal("127.0.0.1:" + center.Endpoint.Port + " sent", lines[4]);
            Assert.All(lines, line => Assert.Matches("^[^ /]+:[0-9]+ (sent|refused)$", line));
            Assert.Single(center.Calls);

            // A 307 and a 308 with a Location on another server are not followed: that server receives nothing (it would answer a value).
            await using var elsewhere = await FakeCenter.StartAsync();
            foreach (var status in new[] { 307, 308 })
            {
                center.Script("RefreshNodeSession", new FakeFault.Redirect(status, elsewhere.Endpoint.Url + "/arcforges.fleet.v1.NodeEnrollmentService/RefreshNodeSession"));
                var reply = await new CenterClient(http, TimeProvider.System).RefreshAsync("afr1.unknown", CancellationToken.None);
                Assert.NotEqual(CenterOutcome.Value, reply.Outcome);
            }

            Assert.Empty(elsewhere.Calls);
        }
        finally
        {
            File.Delete(log);
        }
    }

    [Fact]
    public async Task ADeadlinePassedIsUnreachableWithAnUnknownEffect()
    {
        await using var center = await FakeCenter.StartAsync();
        using var http = new CenterHttpClient(center.Endpoint);
        var release = new TaskCompletionSource();
        center.Script("RefreshNodeSession", new FakeFault.Hold(release));
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var reply = await new CenterClient(http, clock).RefreshAsync("afr1.unknown", cancel.Token);
        release.SetResult();
        Assert.Equal(CenterOutcome.Unreachable, reply.Outcome);
        Assert.True(reply.MaybeApplied);
    }

    [Theory]
    [InlineData(16, "auth.unauthenticated", "Transport")]
    [InlineData(16, "auth.token_expired", "Transport")]
    [InlineData(16, "auth.credential_revoked", "Transport")]
    [InlineData(12, "unimplemented", "ProtocolMismatch")]
    [InlineData(7, "perm.resource_denied", "ProtocolMismatch")]
    [InlineData(3, "validation.invalid_request", "ProtocolMismatch")]
    [InlineData(8, "validation.invalid_request", "ProtocolMismatch")]
    [InlineData(9, "state.stale_generation", "Unreachable")]
    [InlineData(14, "dependency.unavailable", "Unreachable")]
    [InlineData(16, "auth.something_new", "Unreachable")]
    public async Task EveryIngressRefusalIsClassifiedFromItsPercentDecodedCode(int status, string code, string outcome)
    {
        var expected = Enum.Parse<CenterOutcome>(outcome);
        await using var center = await FakeCenter.StartAsync();
        using var http = new CenterHttpClient(center.Endpoint);
        center.Script("ReportNodeInfo", new FakeFault.Transport(status, code));
        var reply = await new CenterClient(http, TimeProvider.System).ReportNodeInfoAsync("afa1.x", new EnrollingNodeInfo(), CommandIds.New(), CancellationToken.None);
        Assert.Equal(expected, reply.Outcome);
        if (expected == CenterOutcome.Transport)
        {
            Assert.Equal(code, reply.TransportCode);
        }

        Assert.False(reply.MaybeApplied && expected != CenterOutcome.Unreachable);
    }

    [Theory]
    [InlineData("auth%2Etoken_expired", "auth.token_expired")]
    [InlineData("auth%2Ecredential%5Frevoked", "auth.credential_revoked")]
    [InlineData("auth.unauthenticated", "auth.unauthenticated")]
    public async Task TheIngressCodeIsReadPercentDecoded(string onTheWire, string code)
    {
        await using var center = await FakeCenter.StartAsync();
        using var http = new CenterHttpClient(center.Endpoint);

        // The ingress percent-encodes grpc-message (Design errors.md): a trailer with encoded characters, exactly as written here, reaches
        // the real client, which decodes it before the node classifies it.
        var trailer = FakeCenter.RawTrailerFrame("grpc-status: 16\r\ngrpc-message: " + onTheWire + "\r\n");
        Assert.Contains(onTheWire, Encoding.ASCII.GetString(trailer), StringComparison.Ordinal);
        center.Script("SignOutNode", new FakeFault.Raw(trailer));
        var reply = await new CenterClient(http, TimeProvider.System).SignOutNodeAsync("afa1.x", CommandIds.New(), CancellationToken.None);
        Assert.Equal(CenterOutcome.Transport, reply.Outcome);
        Assert.Equal(code, reply.TransportCode);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(429)]
    [InlineData(502)]
    [InlineData(504)]
    public async Task HttpErrorsFromSomethingInBetweenAreUnreachable(int status)
    {
        await using var center = await FakeCenter.StartAsync();
        using var http = new CenterHttpClient(center.Endpoint);
        center.Script("RefreshNodeSession", new FakeFault.HttpStatus(status));
        var reply = await new CenterClient(http, TimeProvider.System).RefreshAsync("afr1.x", CancellationToken.None);
        Assert.Equal(CenterOutcome.Unreachable, reply.Outcome);
        Assert.Null(reply.TransportCode);
    }

    [Theory]
    [InlineData(404)]
    [InlineData(415)]
    public async Task AWrongPathOrMediaTypeIsAProtocolMismatch(int status)
    {
        await using var center = await FakeCenter.StartAsync();
        using var http = new CenterHttpClient(center.Endpoint);
        center.Script("RefreshNodeSession", new FakeFault.HttpStatus(status));
        var reply = await new CenterClient(http, TimeProvider.System).RefreshAsync("afr1.x", CancellationToken.None);
        Assert.Equal(CenterOutcome.ProtocolMismatch, reply.Outcome);
    }

    [Fact]
    public async Task AWorkerReplyWithoutResponseMetaIsReadAsItsArcError()
    {
        await using var center = await FakeCenter.StartAsync();
        using var http = new CenterHttpClient(center.Endpoint);
        var error = new ArcError
        {
            Code = "not_activated",
            Category = ErrorCategory.State,
            MessageKey = "error.state.not_activated",
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Effect = EffectCertainty.DidNotHappen,
            Details = new ErrorDetails { State = new StateFailure { Reason = "fleet" } },
        };
        center.Script("RefreshNodeSession", new FakeFault.WorkerRefusal(error));
        var reply = await new CenterClient(http, TimeProvider.System).RefreshAsync("afr1.x", CancellationToken.None);
        Assert.Equal(CenterOutcome.Refused, reply.Outcome);
        Assert.Equal("STATE/not_activated", reply.Code);
    }

    [Fact]
    public async Task ANotSentRequestIsUnreachableWithNoEffect()
    {
        // Nothing listens on this port: a connection error before anything was sent.
        var port = FreePort();
        using var http = new CenterHttpClient(CenterEndpoint.Parse("http://127.0.0.1:" + port));
        var reply = await new CenterClient(http, TimeProvider.System).RefreshAsync("afr1.x", CancellationToken.None);
        Assert.Equal(CenterOutcome.Unreachable, reply.Outcome);
        Assert.False(reply.MaybeApplied);
    }

    [Fact]
    public async Task TheKeySetsAreAdoptedReplacedAsReceivedAndPrunedByExpiryOnly()
    {
        await using var link = await LinkFixture.CreateAsync();
        var now = link.Clock.GetUtcNow();
        link.Center.CommandKeys.Add(Key("k1", now - TimeSpan.FromDays(30), now + TimeSpan.FromDays(100)));
        link.Center.CommandKeys.Add(Key("k2", now + TimeSpan.FromDays(10), now + TimeSpan.FromDays(400)));
        link.Center.CommandKeys.Add(Key("old", now - TimeSpan.FromDays(400), now - TimeSpan.FromDays(8)));
        await link.StartAsync();
        await link.SignInAsync();
        var adopted = link.Storage.ReadKeys()!;
        Assert.Equal(["k1", "k2"], adopted.CommandKeys.Select(key => key.Kid));
        Assert.Equal(link.Center.Endpoint.Url, adopted.CenterUrl);

        // An emergency rotation: the next set shares no key with the held one, and it replaces it as received (no continuity gate).
        link.Center.CommandKeys.Clear();
        link.Center.CommandKeys.Add(Key("k9", now, now + TimeSpan.FromDays(200)));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Center.CallsOf("RefreshNodeSession").Count == 1, "a refresh");
        await Eventually.TrueAsync(() => link.Storage.ReadKeys()!.CommandKeys.Select(key => key.Kid).SequenceEqual(["k9"]), "the replaced set");
        Assert.DoesNotContain("center_keys_discontinuity", link.Service.Status().Warnings);
    }

    [Fact]
    public async Task TestKeySetsAreBoundToTheCenterAndTheCredential()
    {
        await using var link = await LinkFixture.CreateAsync();
        link.Center.CommandKeys.Add(Key("k1", link.Clock.GetUtcNow(), link.Clock.GetUtcNow() + TimeSpan.FromDays(100)));
        await link.StartAsync();
        await link.SignInAsync();
        await link.StopAsync();

        // A key-set file of another installation (or another center) is not this credential's: deleted at start.
        var keys = link.Storage.ReadKeys()!;
        keys.InstallationId = "00";
        link.Storage.WriteKeys(keys);
        await link.StartAsync();
        Assert.True(link.Service.AccountLinked);
        Assert.Null(link.Storage.ReadKeys());
    }

    [Fact]
    public async Task TestSignOutAndRevocationDeleteTheKeyCache()
    {
        await using var link = await LinkFixture.CreateAsync();
        link.Center.CommandKeys.Add(Key("k1", link.Clock.GetUtcNow(), link.Clock.GetUtcNow() + TimeSpan.FromDays(100)));
        await link.StartAsync();
        await link.SignInAsync();
        using (await link.Service.EnterAsync(CancellationToken.None))
        {
            Assert.Equal(SignOutResult.LocalOnly, await link.Service.SignOutHeldAsync(revokeRemote: false));
        }

        Assert.False(File.Exists(link.Storage.KeysPath));
    }

    [Fact]
    public async Task TestCenterSwitchAcceptsTheFirstSetOfTheNewCenter()
    {
        await using var link = await LinkFixture.CreateAsync();
        link.Center.CommandKeys.Add(Key("first", link.Clock.GetUtcNow(), link.Clock.GetUtcNow() + TimeSpan.FromDays(100)));
        await link.StartAsync();
        await link.SignInAsync();
        using (await link.Service.EnterAsync(CancellationToken.None))
        {
            await link.Service.SignOutHeldAsync(revokeRemote: true);
        }

        await using var second = await FakeCenter.StartAsync("/second");
        second.Clock = link.Clock;
        second.CommandKeys.Add(Key("second", link.Clock.GetUtcNow(), link.Clock.GetUtcNow() + TimeSpan.FromDays(100)));
        link.ConfiguredCenter = second.Endpoint;
        await link.Service.CenterChangedAsync();
        await link.Service.AdoptAsync(second.Issue(link.NodeId), second.Endpoint);
        Assert.Equal(["second"], link.Storage.ReadKeys()!.CommandKeys.Select(key => key.Kid));
        Assert.Equal(second.Endpoint.Url, link.Storage.ReadKeys()!.CenterUrl);
        Assert.DoesNotContain(link.Service.Status().Warnings, warning => warning.Contains("discontinuity", StringComparison.Ordinal));
    }

    [Fact]
    public void PruningDropsOnlyKeysExpiredMoreThanSevenDaysAgo()
    {
        var now = new DateTimeOffset(2026, 11, 4, 0, 0, 0, TimeSpan.Zero);
        var kept = CloudLinkService.Prune(
        [
            Key("a", now - TimeSpan.FromDays(10), now - TimeSpan.FromDays(7) + TimeSpan.FromSeconds(1)),
            Key("b", now - TimeSpan.FromDays(10), now - TimeSpan.FromDays(7) - TimeSpan.FromSeconds(1)),
            Key("c", now + TimeSpan.FromDays(1), now + TimeSpan.FromDays(2)),
        ], now);
        Assert.Equal(["a", "c"], kept.Select(key => key.Kid));
    }

    internal static PublicKey Key(string kid, DateTimeOffset notBefore, DateTimeOffset notAfter) => new()
    {
        Kid = kid,
        Algorithm = "ES256",
        Key = ByteString.CopyFrom(new byte[91]),
        NotBefore = ProtoTime.ToInstant(notBefore),
        NotAfter = ProtoTime.ToInstant(notAfter),
    };

    private static int ParseTimeoutSeconds(string header) =>
        header[^1] switch
        {
            'S' => int.Parse(header[..^1], System.Globalization.CultureInfo.InvariantCulture),
            'm' => int.Parse(header[..^1], System.Globalization.CultureInfo.InvariantCulture) / 1000,
            'u' => (int)(long.Parse(header[..^1], System.Globalization.CultureInfo.InvariantCulture) / 1_000_000),
            _ => -1,
        };

    private static int FreePort()
    {
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
