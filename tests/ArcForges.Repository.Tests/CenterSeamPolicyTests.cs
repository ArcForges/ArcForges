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
    private const string Official = "src/ArcForges.Node.Core/CenterEndpoint.cs";
    private const string FakeCenterDirectory = "tests/ArcForges.Node.CloudLink.Tests/";

    /// <summary>The Unix-domain socket sites of the local endpoint (outbound to the node, never to a network).</summary>
    private static readonly HashSet<string> UnixSocketSites = new(StringComparer.Ordinal)
    {
        "src/ArcForges.Client/NodeConnector.cs",
        "src/ArcForges.Node.Core/Platform/Readiness.cs",
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
    public void OnlyTheCenterHttpClientCreatesHttpClients()
    {
        var offenders = new List<string>();
        foreach (var path in Files("src").Where(path => path.EndsWith(".cs", StringComparison.Ordinal) && path != Seam))
        {
            var text = File.ReadAllText(Path.Combine(RepositoryFiles.Root, path));
            if (OutboundHttp().IsMatch(text))
            {
                offenders.Add(path);
            }

            foreach (Match socket in SocketConstruction().Matches(text))
            {
                if (!UnixSocketSites.Contains(path) || !socket.Value.Contains("AddressFamily.Unix", StringComparison.Ordinal))
                {
                    offenders.Add(path + " (" + socket.Value + ")");
                }
            }
        }

        Assert.True(offenders.Count == 0, "Only " + Seam + " creates an HttpClient, an outbound handler, a GrpcChannel or a network socket: "
            + string.Join(", ", offenders));
        var seam = File.ReadAllText(Path.Combine(RepositoryFiles.Root, Seam));
        Assert.Matches(OutboundHttp(), seam);
        Assert.Contains("AllowAutoRedirect = false", seam, StringComparison.Ordinal);
        Assert.Contains("new GrpcWebHandler(GrpcWebMode.GrpcWeb, pathBase)", seam, StringComparison.Ordinal);
        Assert.Contains("Timeout = Timeout.InfiniteTimeSpan", seam, StringComparison.Ordinal);
        Assert.DoesNotContain("ServerCertificateCustomValidationCallback", seam, StringComparison.Ordinal);
        Assert.All(UnixSocketSites, path => Assert.Matches(SocketConstruction(), File.ReadAllText(Path.Combine(RepositoryFiles.Root, path))));
    }

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
        // A credential reaches a node only from a center's sign-in reply (AdoptAsync, called by the sign-in flows of part N2): no test hook,
        // flag or RPC writes one. In part N1 nothing in src/ calls it.
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
        var adopt = service[service.IndexOf("public async Task AdoptAsync(NodeCredentials credentials, CenterEndpoint center)", StringComparison.Ordinal)..];
        adopt = adopt[..adopt.IndexOf("\n    }\n", StringComparison.Ordinal)];
        Assert.Contains("new CloudCredentialRecord", adopt, StringComparison.Ordinal);
        Assert.Contains("new CloudLinkFile", adopt, StringComparison.Ordinal);
        Assert.Single(Regex.Matches(service, @"\bNodeCredentials\b(?!\.)"));
        var hooks = File.ReadAllText(Path.Combine(RepositoryFiles.Root, "src/ArcForges.Node.CloudLink/CloudLinkTestHooks.cs"));
        Assert.Equal(["ARCFORGES_TEST_CENTER_URL", "ARCFORGES_TEST_CONNECT_LOG", "ARCFORGES_TEST_CLOUDLINK_REFRESH_SECONDS"],
            Regex.Matches(hooks, "\"(ARCFORGES_TEST_[A-Z_]+)\"").Select(match => match.Groups[1].Value));
        Assert.Equal(3, Regex.Count(hooks, @"\(bool testMode, string\? value\) =>\s+testMode &&"));
    }

    private static IEnumerable<string> Files(params string[] roots) => roots.SelectMany(root =>
        Directory.EnumerateFiles(Path.Combine(RepositoryFiles.Root, root), "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(RepositoryFiles.Root, path).Replace('\\', '/'))
            .Where(path => !path.Split('/').Any(part => part is "bin" or "obj" or "Fixtures")));

    [GeneratedRegex(@"\bnew\s+(?:HttpClient|SocketsHttpHandler|HttpClientHandler|TcpClient|HttpMessageInvoker)\b|:\s*(?:DelegatingHandler|HttpMessageHandler)\b|\bGrpcChannel\.ForAddress\b|\bWebRequest\.Create\b|\bHttpWebRequest\b")]
    private static partial Regex OutboundHttp();

    [GeneratedRegex(@"\bnew\s+Socket\([^)]*\)")]
    private static partial Regex SocketConstruction();

    // A credential record or link file built, a credential target named, or a record or link written (outside the store class itself).
    [GeneratedRegex(@"\bnew\s+(?:CloudCredentialStore|CloudCredentialRecord|CloudLinkFile)\b|\bCloudCredentialStore\.Target\(|\.Write(?:Record|Link)\(")]
    private static partial Regex CredentialWriting();
}
