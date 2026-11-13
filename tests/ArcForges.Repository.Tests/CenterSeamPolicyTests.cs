// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;

namespace ArcForges.Repository.Tests;

/// <summary>
/// AF-CTR-04 part N1 (rows N1-1, N1-8 and N1-19): the node reaches its center through one HTTP seam only, names the official endpoint in one
/// source file, does no center or secret-store I/O as sync-over-async in the account handler, keeps the center fake in its test project, and
/// has no path that imports a credential into a node.
/// </summary>
public sealed partial class CenterSeamPolicyTests
{
    private const string Seam = "src/ArcForges.Node.CloudLink/CenterHttpClient.cs";

    /// <summary>The second reviewed seam (AF-CTR-05 N1, CTR5-NODE-01): the node channel's WebSocket, through the same authority guard.</summary>
    private const string ChannelSeam = "src/ArcForges.Node.CloudLink/CenterChannelClient.cs";
    private const string Official = "src/ArcForges.Node.Core/CenterEndpoint.cs";
    private const string FakeCenterDirectory = "tests/ArcForges.Node.CloudLink.Tests/";

    /// <summary>The explicitly reviewed local endpoint, readiness and private worker Unix-domain socket sites.</summary>
    private static readonly HashSet<string> UnixSocketSites = new(StringComparer.Ordinal)
    {
        "src/ArcForges.Client/NodeConnector.cs",
        "src/ArcForges.Node.Core/Platform/Readiness.cs",
        "src/ArcForges.Node.Core/Platform/LinuxFileEffectController.cs",
        "src/ArcForges.Node.Core/Platform/LinuxFileEffectWorker.cs",
        "src/ArcForges.Node.Core/Platform/LinuxWorkerBootstrapSelfTest.cs",
    };

    [Fact]
    public void TheOfficialEndpointAppearsInOneSourceFile()
    {
        var naming = Files("src").Where(path => File.ReadAllText(Path.Combine(RepositoryFiles.Root, path)).Contains("arcforges.com/api", StringComparison.Ordinal)).ToList();
        Assert.Equal([Official], naming);
        Assert.Contains("public const string OfficialDefault = \"https://arcforges.com/api\";", File.ReadAllText(Path.Combine(RepositoryFiles.Root, Official)),
            StringComparison.Ordinal);
    }

    [Fact]
    public void OnlyTheTwoCenterSeamsCreateNetworkClients()
    {
        var offenders = new List<string>();
        foreach (var path in Files("src").Where(path => path.EndsWith(".cs", StringComparison.Ordinal) && path != Seam && path != ChannelSeam))
        {
            var text = File.ReadAllText(Path.Combine(RepositoryFiles.Root, path));
            if (OutboundHttp().IsMatch(text))
            {
                offenders.Add(path);
            }

            foreach (Match socket in SocketConstruction().Matches(text))
            {
                if (!IsAllowedLocalSocket(path, socket.Value))
                {
                    offenders.Add(path + " (" + socket.Value + ")");
                }
            }
        }

        Assert.True(offenders.Count == 0, "Only " + Seam + " and " + ChannelSeam
            + " create an HttpClient, an outbound handler, a GrpcChannel, a WebSocket client or a network socket: " + string.Join(", ", offenders));
        var seam = File.ReadAllText(Path.Combine(RepositoryFiles.Root, Seam));
        Assert.Matches(OutboundHttp(), seam);
        Assert.Contains("AllowAutoRedirect = false", seam, StringComparison.Ordinal);
        Assert.Contains("new GrpcWebHandler(GrpcWebMode.GrpcWeb, pathBase)", seam, StringComparison.Ordinal);
        Assert.Contains("Timeout = Timeout.InfiniteTimeSpan", seam, StringComparison.Ordinal);
        Assert.DoesNotContain("ServerCertificateCustomValidationCallback", seam, StringComparison.Ordinal);
        Assert.All(UnixSocketSites, path => Assert.Matches(SocketConstruction(), File.ReadAllText(Path.Combine(RepositoryFiles.Root, path))));

        // The channel seam (N1-1): one ClientWebSocket over HttpMessageInvoker(AuthorityGuardHandler(SocketsHttpHandler)), the HTTP seam's own
        // guard and connect log, no redirect, no cookies, no compression, HTTP/1.1 only, the platform's certificate validation.
        var channel = File.ReadAllText(Path.Combine(RepositoryFiles.Root, ChannelSeam));
        Assert.Equal(1, Regex.Count(channel, @"\bnew\s+ClientWebSocket\b"));
        Assert.Equal(1, Regex.Count(channel, @"\bnew\s+SocketsHttpHandler\b"));
        Assert.Contains("new CenterHttpClient.AuthorityGuardHandler(center, connectLog) { InnerHandler = transport }", channel, StringComparison.Ordinal);
        Assert.Contains("new HttpMessageInvoker(guard, disposeHandler: true)", channel, StringComparison.Ordinal);
        Assert.Contains("ConnectAsync(ChannelUri(center), invoker,", channel, StringComparison.Ordinal);
        Assert.Contains("AllowAutoRedirect = false", channel, StringComparison.Ordinal);
        Assert.Contains("UseCookies = false", channel, StringComparison.Ordinal);
        Assert.Contains("DangerousDeflateOptions = null", channel, StringComparison.Ordinal);
        Assert.Contains("HttpVersionPolicy = HttpVersionPolicy.RequestVersionExact", channel, StringComparison.Ordinal);
        foreach (var forbidden in (string[])["ServerCertificateCustomValidationCallback", "RemoteCertificateValidationCallback", "SslOptions", "Credentials", "ClientCertificates"])
        {
            Assert.DoesNotContain(forbidden, channel, StringComparison.Ordinal);
        }
    }

    private static bool IsAllowedLocalSocket(string path, string construction) =>
        UnixSocketSites.Contains(path) && LocalUnixSocket().IsMatch(construction);

    [Theory]
    [InlineData("src/ArcForges.Node.Core/Platform/LinuxFileEffectController.cs", "new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified)", true)]
    [InlineData("src/ArcForges.Node.Core/Platform/Readiness.cs", "new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified)", true)]
    [InlineData("src/ArcForges.Node.Core/Platform/LinuxFileEffectWorker.cs", "new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Unspecified)", false)]
    [InlineData("src/ArcForges.Node.Core/Platform/LinuxFileEffectWorker.cs", "new Socket(AddressFamily.InterNetwork, /* AddressFamily.Unix */ SocketType.Stream, ProtocolType.Unspecified)", false)]
    [InlineData("src/other.cs", "new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified)", false)]
    public void OnlyReviewedUnixSocketConstructionsAreLocal(string path, string construction, bool allowed) =>
        Assert.Equal(allowed, IsAllowedLocalSocket(path, construction));

    [Fact]
    public void TheFileEffectSocketsUseAuthenticatedLocalPeers()
    {
        var controller = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.Core/Platform/LinuxFileEffectController.cs"));
        var worker = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.Core/Platform/LinuxFileEffectWorker.cs"));
        var selfTest = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.Core/Platform/LinuxWorkerBootstrapSelfTest.cs"));
        foreach (var source in new[] { controller, worker, selfTest })
        {
            Assert.DoesNotContain("IPEndPoint", source, StringComparison.Ordinal);
            Assert.DoesNotContain("DnsEndPoint", source, StringComparison.Ordinal);
            Assert.All(SocketConstruction().Matches(source).Cast<Match>(),
                socket => Assert.Matches(LocalUnixSocket(), socket.Value));
        }
        Assert.Contains("new UnixDomainSocketEndPoint(", controller, StringComparison.Ordinal);
        Assert.Contains("LinuxOwnedPidfd.OpenPending(", controller, StringComparison.Ordinal);
        Assert.Contains("AuthenticateAndSeal(", controller, StringComparison.Ordinal);
        Assert.Contains("new UnixDomainSocketEndPoint(", worker, StringComparison.Ordinal);
        Assert.Contains("LinuxPeerCredentialReader.Read(socket)", worker, StringComparison.Ordinal);
        Assert.Contains("peer.ProcessId != parent", worker, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("using var socket = new ClientWebSocket();")]
    [InlineData("var invoker = new HttpMessageInvoker(handler);")]
    public void TheSeamCheckCatchesAWebSocketClient(string source) => Assert.Matches(OutboundHttp(), source);

    [Fact]
    public void TheNodeNeverUsesTextModeGrpcWeb() =>
        Assert.DoesNotContain(Files("src"), path => File.ReadAllText(Path.Combine(RepositoryFiles.Root, path)).Contains("GrpcWebText", StringComparison.Ordinal));

    [Theory]
    [InlineData("var http = new HttpClient(handler);")]
    [InlineData("using var transport = new SocketsHttpHandler { };")]
    [InlineData("internal sealed class Tap(HttpMessageHandler inner) : DelegatingHandler(inner)")]
    [InlineData("var channel = GrpcChannel.ForAddress(address);")]
    [InlineData("var request = WebRequest.Create(uri);")]
    [InlineData("using var client = new TcpClient(host, port);")]
    public void TheSeamCheckCatchesEveryOutboundType(string source) => Assert.Matches(OutboundHttp(), source);

    [Fact]
    public void TheAccountHandlerDoesNoSyncOverAsync()
    {
        var handler = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.Api/AccountServiceHandler.cs"));
        Assert.DoesNotContain(".GetAwaiter().GetResult()", handler, StringComparison.Ordinal);
        Assert.DoesNotContain(".Result", handler, StringComparison.Ordinal);
        Assert.DoesNotContain(".Wait()", handler, StringComparison.Ordinal);
    }

    [Fact]
    public void FakeCenterLivesOnlyInItsTestProject()
    {
        var defining = Files("tests").Where(path => path.EndsWith(".cs", StringComparison.Ordinal)
            && Regex.IsMatch(File.ReadAllText(Path.Combine(RepositoryFiles.Root, path)), @"\bclass\s+FakeCenter\b")).ToList();
        Assert.Equal([FakeCenterDirectory + "FakeCenter/FakeCenter.cs"], defining);
        var using_ = Files("src", "tools", "tests").Where(path => path.EndsWith(".cs", StringComparison.Ordinal) && !path.StartsWith(FakeCenterDirectory, StringComparison.Ordinal)
            && path != "tests/ArcForges.Repository.Tests/CenterSeamPolicyTests.cs" && path != "tests/ArcForges.ClosedLoop.Tests/CloudLinkHostTests.cs"
            && path != "tests/ArcForges.ClosedLoop.Tests/CloudSignInHostTests.cs" && path != "tests/ArcForges.ClosedLoop.Tests/CloudSignInTests.cs"
            && path != "tests/ArcForges.ClosedLoop.Tests/SignInSecretsTests.cs"
            && path != "tests/ArcForges.ClosedLoop.Tests/CloudChannelTests.cs"
            && path != "tests/ArcForges.ClosedLoop.Tests/LinuxFileMutationHostTests.cs"
            && path != "tests/ArcForges.ClosedLoop.Tests/LinuxWorkerInterruptionHostTests.cs"
            && path != "tests/ArcForges.ClosedLoop.Tests/WindowsFileMutationHostTests.cs"
            // AF-CTR-06: exact real-Host consumers of the same isolated peer; no production or new project use.
            && path != "tests/ArcForges.ClosedLoop.Tests/AttemptRemovalPlanHostTests.cs"
            && path != "tests/ArcForges.ClosedLoop.Tests/OptionalAvailableFleetHostTests.cs"
            && path != "tests/ArcForges.ClosedLoop.Tests/PlanRemovalHostTests.cs"
            && path != "tests/ArcForges.ClosedLoop.Tests/PlanRemovalInputAuditHostTests.cs"
            && path != "tests/ArcForges.ClosedLoop.Tests/FileCreationOwnershipHostTests.cs"
            && path != "tests/ArcForges.ClosedLoop.Tests/FileStageProducerHostTests.cs"
            && Regex.IsMatch(File.ReadAllText(Path.Combine(RepositoryFiles.Root, path)), @"\bFakeCenter\b")).ToList();
        Assert.Empty(using_);

        // Its one other consumer compiles the same file in (N1-21; a real node process against FakeCenter).
        var linked = RepositoryFiles.Projects("src", "tools", "tests").Where(project =>
            File.ReadAllText(Path.Combine(RepositoryFiles.Root, project)).Contains("FakeCenter", StringComparison.Ordinal)).ToList();
        Assert.Equal(["tests/ArcForges.ClosedLoop.Tests/ArcForges.ClosedLoop.Tests.csproj", "tests/ArcForges.Node.CloudLink.Tests/ArcForges.Node.CloudLink.Tests.csproj"],
            linked.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void NoProductionPathImportsACredential()
    {
        // A credential reaches a node only from a center's sign-in reply: the sign-in flows of part N2 adopt it through AdoptSignInAsync with
        // the credentials a CompleteNodeSignIn or PollDeviceAuthorization reply delivered; no test hook, flag or RPC writes one, and nothing in
        // src/ calls the test seam AdoptAsync.
        var callers = Files("src").Where(path => path.EndsWith(".cs", StringComparison.Ordinal)
            && Regex.IsMatch(File.ReadAllText(Path.Combine(RepositoryFiles.Root, path)), @"\.AdoptAsync\(")).ToList();
        Assert.Empty(callers);

        // Nothing else in src/ builds, names or writes a credential record or its link file: the link is the only writer, and its only new
        // record is the one AdoptAsync builds from NodeCredentials (a rotation clones the record it holds).
        var writers = Files("src").Where(path => path.EndsWith(".cs", StringComparison.Ordinal)
            && CredentialWriting().IsMatch(File.ReadAllText(Path.Combine(RepositoryFiles.Root, path)))).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(["src/ArcForges.Node.CloudLink/CloudLinkService.cs"], writers);
        var service = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.CloudLink/CloudLinkService.cs"));
        Assert.Single(Regex.Matches(service, @"\bnew\s+CloudCredentialRecord\b"));
        Assert.Single(Regex.Matches(service, @"\bnew\s+CloudLinkFile\b"));
        var adopt = service[service.IndexOf("private void AdoptCore(NodeCredentials credentials, CenterEndpoint center)", StringComparison.Ordinal)..];
        adopt = adopt[..adopt.IndexOf("\n    }\n", StringComparison.Ordinal)];
        Assert.Contains("new CloudCredentialRecord", adopt, StringComparison.Ordinal);
        Assert.Contains("new CloudLinkFile", adopt, StringComparison.Ordinal);
        Assert.Equal(4, Regex.Count(service, @"\bNodeCredentials\b(?!\.)"));
        var signIn = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.CloudLink/SignInOrchestrator.cs"));
        Assert.Single(Regex.Matches(signIn, @"\.AdoptSignInAsync\("));
        Assert.Contains("await DeliveredAsync(run, value.Credentials)", signIn, StringComparison.Ordinal);
        Assert.Contains("await DeliveredAsync(run, credentials)", signIn, StringComparison.Ordinal);
        Assert.Contains("DeviceAuthorizationState.Approved when value.Credentials is { } credentials", signIn, StringComparison.Ordinal);
        var hooks = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.CloudLink/CloudLinkTestHooks.cs"));
        Assert.Equal(["ARCFORGES_TEST_CENTER_URL", "ARCFORGES_TEST_CONNECT_LOG", "ARCFORGES_TEST_CLOUDLINK_REFRESH_SECONDS", "ARCFORGES_TEST_BROWSER_FILE"],
            Regex.Matches(hooks, "\"(ARCFORGES_TEST_[A-Z_]+)\"").Select(match => match.Groups[1].Value));
        Assert.Equal(4, Regex.Count(hooks, @"\(bool testMode, string\? value\) =>\s+testMode &&"));
    }

    [Fact]
    public void OnlyBrowserOpenerStartsAnOsHandler()
    {
        // AF-CTR-04 N2 (CTR4-NODE-17 e, SEC-24): no source of src/ outside BrowserOpener.cs names xdg-open or sets UseShellExecute = true.
        const string Opener = "src/ArcForges.Node.CloudLink/BrowserOpener.cs";
        var naming = Files("src").Where(path => path.EndsWith(".cs", StringComparison.Ordinal)
            && Regex.IsMatch(File.ReadAllText(Path.Combine(RepositoryFiles.Root, path)), @"xdg-open|UseShellExecute\s*=\s*true")).ToList();
        Assert.Equal([Opener], naming);
        var opener = File.ReadAllText(Path.Combine(RepositoryFiles.Root, Opener));
        Assert.Contains("ArgumentList.Add(url.Value)", opener, StringComparison.Ordinal);
        Assert.DoesNotContain("\"cmd", opener, StringComparison.Ordinal);
        Assert.Contains("public Task<bool> OpenAsync(DerivedUrl url", opener.Replace("async ", string.Empty, StringComparison.Ordinal), StringComparison.Ordinal);
    }

    [Fact]
    public void OnlyTheLoopbackReceiverListensAndOnlyOnLoopback()
    {
        // AF-CTR-04 N2 (node-15 item 6): the one listener of src/ besides the local endpoint is the sign-in's loopback receiver.
        const string Receiver = "src/ArcForges.Node.CloudLink/LoopbackReceiver.cs";
        var listening = Files("src").Where(path => path.EndsWith(".cs", StringComparison.Ordinal)
            && Regex.IsMatch(File.ReadAllText(Path.Combine(RepositoryFiles.Root, path)), @"\bnew\s+TcpListener\b")).ToList();
        Assert.Equal([Receiver], listening);
        var receiver = File.ReadAllText(Path.Combine(RepositoryFiles.Root, Receiver));
        Assert.Contains("new[] { IPAddress.Loopback, IPAddress.IPv6Loopback }", receiver, StringComparison.Ordinal);
        Assert.DoesNotContain("IPAddress.Any", receiver, StringComparison.Ordinal);

        // N2 review FX-8: exactly one listener construction, over the loop variable of the loopback-only foreach, port 0.
        Assert.Equal(1, Regex.Count(receiver, @"\bnew\s+TcpListener\b"));
        var loop = receiver.IndexOf("foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })", StringComparison.Ordinal);
        var construction = receiver.IndexOf("new TcpListener(address, 0)", StringComparison.Ordinal);
        Assert.True(loop >= 0 && construction > loop, "the listener is constructed outside the loopback foreach");
        Assert.True(receiver.IndexOf("return null;", loop, StringComparison.Ordinal) > construction, "the listener is constructed outside the loopback foreach");
        Assert.DoesNotMatch(@"\baddress\s*=(?!=)", receiver[loop..construction]);
        Assert.Contains("CryptographicOperations.FixedTimeEquals(presented, expected)", receiver, StringComparison.Ordinal);
        Assert.DoesNotContain("Access-Control", receiver, StringComparison.Ordinal);
    }

    [Fact]
    public void ThePrivateFilesReadIntoOneExactSizeArray()
    {
        // PR #71 review B-2: the node key's PKCS#8 bytes are read through PrivateFiles; no copy may outlive the one array its caller zeroes.
        var source = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.CloudLink/NodeKeyStore.cs"));
        var start = source.IndexOf("internal static class PrivateFiles", StringComparison.Ordinal);
        Assert.True(start >= 0);
        var privateFiles = source[start..];
        foreach (var forbidden in (string[])["MemoryStream", "CopyTo", "ArrayPool", "ReadAllBytes", "StreamReader", "BufferedStream"])
        {
            Assert.DoesNotContain(forbidden, privateFiles, StringComparison.Ordinal);
        }

        Assert.Contains("bufferSize: 0", privateFiles, StringComparison.Ordinal);
        Assert.Contains("CryptographicOperations.ZeroMemory(bytes)", privateFiles, StringComparison.Ordinal);

        // PR #71 review N-9: every stream of the region is unbuffered, no other file API reads there, and the node key's own reader
        // (FileNodeKeyBackend.Open, before the region) reads through PrivateFiles.ReadOrNull and zeroes what it got.
        foreach (Match stream in Regex.Matches(privateFiles, @"new\s+FileStream\((?<arguments>[^;]*)\);"))
        {
            Assert.Matches(@"bufferSize: 0|BufferSize = 0|\boptions\b", stream.Groups["arguments"].Value);
        }

        Assert.Contains("var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, BufferSize = 0 };",
            privateFiles, StringComparison.Ordinal);
        foreach (var forbidden in (string[])["File.Open", "OpenRead", "ReadAll", "File.OpenText"])
        {
            Assert.DoesNotContain(forbidden, privateFiles, StringComparison.Ordinal);
        }

        var open = source[source.IndexOf("public INodeKey? Open(string name)", StringComparison.Ordinal)..];
        open = open[..open.IndexOf("\n    }\n", StringComparison.Ordinal)];
        Assert.Contains("PrivateFiles.ReadOrNull(PathOf(name))", open, StringComparison.Ordinal);
        Assert.Contains("CryptographicOperations.ZeroMemory(bytes)", open, StringComparison.Ordinal);
        foreach (var forbidden in (string[])["FileStream", "File.", "MemoryStream", "StreamReader"])
        {
            Assert.DoesNotContain(forbidden, open, StringComparison.Ordinal);
        }

        // PR #71 review N-8: a read that throws zeroes the partly filled array.
        var exact = privateFiles[privateFiles.IndexOf("private static byte[] ReadExact(string path)", StringComparison.Ordinal)..];
        Assert.Matches(@"catch\s*\{\s*//[^\n]*\n\s*CryptographicOperations\.ZeroMemory\(bytes\);\s*throw;", exact);
    }

    [Fact]
    public void EveryRelayReasonIsListedOnce()
    {
        // Review B N-5: AccountStatus.relay_reason is a closed vocabulary: every constant of ChannelReasons is in ChannelReasons.All once,
        // and nothing else sets relay_reason (the status takes it from the channel only).
        var source = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.CloudLink/ChannelState.cs"));
        var block = source[source.IndexOf("internal static class ChannelReasons", StringComparison.Ordinal)..];
        block = block[..block.IndexOf("\n}\n", StringComparison.Ordinal)];
        var constants = Regex.Matches(block, @"public const string (\w+) = ""[a-z_]+"";").Select(match => match.Groups[1].Value).ToList();
        var all = block[block.IndexOf("All { get; } =", StringComparison.Ordinal)..];
        var listed = Regex.Matches(all, @"\b([A-Z]\w+)\b").Select(match => match.Groups[1].Value).Where(constants.Contains).ToList();
        Assert.NotEmpty(constants);
        Assert.Equal(constants.Order(StringComparer.Ordinal), listed.Order(StringComparer.Ordinal));
        var setters = Files("src").Where(path => path.EndsWith(".cs", StringComparison.Ordinal)
            && Regex.IsMatch(File.ReadAllText(Path.Combine(RepositoryFiles.Root, path)), @"RelayReason\s*=")).ToList();
        Assert.Equal(["src/ArcForges.Node.CloudLink/CloudLinkService.cs"], setters);
        Assert.Contains("RelayReason = channel.Reason,", File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.CloudLink/CloudLinkService.cs")),
            StringComparison.Ordinal);
    }

    [Fact]
    public void TheNodeBoundsTheCloudLinksStopFromTheShutdownsStart()
    {
        // Review B N-9 of PR #72: NodeHost.ShutdownAsync begins the cloud link's stop with its budget before anything else of the shutdown
        // (before the local server stops), so the link has ended by budget + CloudLinkService.FlushReserve, before the force exit.
        var host = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.Api/NodeHost.cs"));
        var shutdown = host[host.IndexOf("private static async Task<int> ShutdownAsync(", StringComparison.Ordinal)..];
        var begin = shutdown.IndexOf("cloud.BeginStop(ShutdownBudget);", StringComparison.Ordinal);
        Assert.True(begin >= 0, "ShutdownAsync begins the cloud link's stop");
        foreach (var later in new[] { "using var overrun = new Timer(", "server.StopAsync(", "cloud.DisposeAsync()" })
        {
            var at = shutdown.IndexOf(later, StringComparison.Ordinal);
            Assert.True(at > begin, later + " comes after the cloud link's stop begins");
        }
    }

    [Fact]
    public void TheChannelContractCohortIsThePinnedOne()
    {
        // The hello's contract_version names the cohort the node is built with: ChannelContract.Cohort equals Directory.Packages.props.
        var packages = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "Directory.Packages.props"));
        var service = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.CloudLink/CloudLinkService.cs"));
        var cohort = Regex.Match(service, "public const string Cohort = \"(?<v>[^\"]+)\";").Groups["v"].Value;
        foreach (var id in (string[])["ArcForges.Contracts.Relay", "ArcForges.Contracts.Fleet", "ArcForges.Contracts.Foundation", "ArcForges.Contracts.Node"])
        {
            Assert.Contains("<PackageVersion Include=\"" + id + "\" Version=\"" + cohort + "\" />", packages, StringComparison.Ordinal);
        }
    }

    private static IEnumerable<string> Files(params string[] roots) => roots.SelectMany(root =>
        Directory.EnumerateFiles(Path.Combine(RepositoryFiles.Root, root), "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(RepositoryFiles.Root, path).Replace('\\', '/'))
            .Where(path => !path.Split('/').Any(part => part is "bin" or "obj" or "Fixtures")));

    [GeneratedRegex(@"\bnew\s+(?:HttpClient|SocketsHttpHandler|HttpClientHandler|TcpClient|HttpMessageInvoker|ClientWebSocket)\b|:\s*(?:DelegatingHandler|HttpMessageHandler)\b|\bGrpcChannel\.ForAddress\b|\bWebRequest\.Create\b|\bHttpWebRequest\b")]
    private static partial Regex OutboundHttp();

    [GeneratedRegex(@"\bnew\s+Socket\([^)]*\)")]
    private static partial Regex SocketConstruction();

    [GeneratedRegex(@"^new\s+Socket\(\s*AddressFamily\.Unix\s*,")]
    private static partial Regex LocalUnixSocket();

    // A credential record or link file built, a credential target named, or a record or link written (outside the store class itself).
    [GeneratedRegex(@"\bnew\s+(?:CloudCredentialStore|CloudCredentialRecord|CloudLinkFile)\b|\bCloudCredentialStore\.Target\(|\.Write(?:Record|Link)\(")]
    private static partial Regex CredentialWriting();
}
