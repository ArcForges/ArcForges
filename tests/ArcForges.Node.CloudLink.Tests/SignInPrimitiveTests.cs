// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Node.Core;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N2-2 (PKCE and state), N2-9 (center-supplied URLs are never trusted: CTR4-NODE-17, SEC-24, the plan review's protocol-2 corrected fix
/// rows), N2-10 (the browser opener's start info and the test-mode hook). Unit tests; the opener's real launch is not run by any test.
/// </summary>
public sealed class SignInPrimitiveTests
{
    private static readonly CenterEndpoint Center = CenterEndpoint.Parse("https://center.example.test/api");
    private static readonly byte[] Flow = Convert.FromHexString("f10e2d3c4b5a69788796a5b4c3d2e10f");

    [Fact]
    public void PkceIsS256OfAVerifierOfTheRightShape()
    {
        // RFC 7636 appendix B.
        Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", FakeCenter.S256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        var verifiers = Enumerable.Range(0, 50).Select(_ => Pkce.NewVerifier()).ToList();
        Assert.All(verifiers, verifier => Assert.Matches("^[A-Za-z0-9_-]{64}$", verifier));
        Assert.Equal(50, verifiers.Distinct(StringComparer.Ordinal).Count());
        Assert.All(verifiers, verifier => Assert.True(Pkce.IsBase64Url43(Pkce.Challenge(verifier))));
        var state = Pkce.NewState();
        Assert.Matches("^[A-Za-z0-9_-]{43}$", state);
        Assert.NotEqual(state, Pkce.NewState());
    }

    [Fact]
    public void TheDerivedUrlsAreTheCentersVectors()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "center-vectors", "url-vectors.json")));
        var root = document.RootElement;
        var flow = ByteString.CopyFrom(Convert.FromHexString(root.GetProperty("flowId").GetString()!));
        var userCode = root.GetProperty("userCode").GetString()!;
        var checkedCount = 0;
        foreach (var vector in root.GetProperty("baseUrls").EnumerateArray().Where(vector => vector.TryGetProperty("derived", out _)))
        {
            if (!CenterEndpoint.TryParse(vector.GetProperty("input").GetString(), out var center, out _))
            {
                continue;
            }

            var derived = vector.GetProperty("derived");
            if (derived.GetProperty("longestLength").GetInt32() > SignInUrls.MaxLength)
            {
                // A base URL over the fleet bound: its derived URLs exceed the contract's 512 characters, so the node never uses them.
                Assert.Null(SignInUrls.Authorize(center, flow, derived.GetProperty("authorizeUrl").GetString(), out _));
                continue;
            }

            Assert.Equal(derived.GetProperty("authorizeUrl").GetString(), SignInUrls.Authorize(center, flow, derived.GetProperty("authorizeUrl").GetString(), out _)!.Value);
            var device = SignInUrls.Device(center, new DeviceAuthorization
            {
                DeviceCode = new string('d', 43),
                UserCode = userCode,
                VerificationUri = derived.GetProperty("verificationUri").GetString(),
                VerificationUriComplete = derived.GetProperty("verificationUriComplete").GetString(),
            }, out var failure);
            Assert.True(device is not null, failure);
            checkedCount++;
        }

        Assert.True(checkedCount >= 3, checkedCount + " vectors");
    }

    [Theory]
    [InlineData("file:///C:/Windows/System32/calc.exe")]
    [InlineData("ms-msdt:/id PCWDiagnostic")]
    [InlineData("search-ms:query=x")]
    [InlineData("javascript:alert(1)")]
    [InlineData("\\\\host\\share\\x.exe")]
    [InlineData("file://host/share/x")]
    [InlineData("https://user@center.example.test/api/connect#flow=f10e2d3c-4b5a-6978-8796-a5b4c3d2e10f")]
    [InlineData("https://evil.example/api/connect#flow=f10e2d3c-4b5a-6978-8796-a5b4c3d2e10f")]
    [InlineData("https://center.example.test:8443/api/connect#flow=f10e2d3c-4b5a-6978-8796-a5b4c3d2e10f")]
    [InlineData("https://center.example.test/other/connect#flow=f10e2d3c-4b5a-6978-8796-a5b4c3d2e10f")]
    [InlineData("https://center.example.test/api/connect?x=1#flow=f10e2d3c-4b5a-6978-8796-a5b4c3d2e10f")]
    [InlineData("https://center.example.test/api/connect#code=f10e2d3c-4b5a-6978-8796-a5b4c3d2e10f")]
    [InlineData("https://center.example.test/api/connect#flow=F10E2D3C-4B5A-6978-8796-A5B4C3D2E10F")]
    [InlineData("https://center.example.test/api/connect#flow=f10e2d3c-4b5a-6978-8796-a5b4c3d2e10f\n")]
    [InlineData(" https://center.example.test/api/connect#flow=f10e2d3c-4b5a-6978-8796-a5b4c3d2e10f")]
    [InlineData("--https://center.example.test/api/connect#flow=f10e2d3c-4b5a-6978-8796-a5b4c3d2e10f")]
    [InlineData("")]
    public void AForeignAuthorizeUrlFailsTheFlow(string reply)
    {
        Assert.Null(SignInUrls.Authorize(Center, ByteString.CopyFrom(Flow), reply, out var failure));
        Assert.Equal("authorize_url: center_url_mismatch", failure);
        Assert.NotNull(SignInUrls.Authorize(Center, ByteString.CopyFrom(Flow), Center.ConnectUrl(Flow), out _));
        Assert.Equal("flow_id: length", SignInUrls.Authorize(Center, ByteString.CopyFrom(Flow[..15]), Center.ConnectUrl(Flow), out var length) is null ? length : null);
    }

    [Theory]
    [InlineData("verification_uri", "https://evil.example/api/activate", null, "BCDFGHJK")]
    [InlineData("verification_uri_complete", null, "https://center.example.test/api/activate#code=BCDF-GHJL", "BCDFGHJK")]
    [InlineData("verification_uri_complete", null, "https://evil.example/api/activate#code=BCDF-GHJK", "BCDFGHJK")]
    [InlineData("user_code", null, null, "BCDF\u001b[2J")]
    [InlineData("user_code", null, null, "BCDFGHJA")]
    [InlineData("user_code", null, null, "bcdfghjk")]
    [InlineData("user_code", null, null, "BCDF-GHJK")]
    [InlineData("device_code", null, null, "BCDFGHJK")]
    public void AForeignDeviceReplyFailsTheFlow(string field, string? verification, string? complete, string userCode)
    {
        var authorization = new DeviceAuthorization
        {
            DeviceCode = field == "device_code" ? "short" : new string('d', 43),
            UserCode = userCode,
            VerificationUri = verification ?? Center.ActivateUrl,
            VerificationUriComplete = complete ?? (SignInUrls.IsUserCode(userCode) ? Center.ActivateCompleteUrl(userCode) : Center.ActivateUrl + "#code=x"),
        };
        Assert.Null(SignInUrls.Device(Center, authorization, out var failure));
        Assert.StartsWith(field + ": ", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void TheOpenerStartsOnlyTheDerivedUrlWithoutAShell()
    {
        var url = SignInUrls.Authorize(Center, ByteString.CopyFrom(Flow), Center.ConnectUrl(Flow), out _)!;
        var linux = BrowserOpener.StartInfo(url, windows: false);
        Assert.Equal("xdg-open", linux.FileName);
        Assert.False(linux.UseShellExecute);
        Assert.Equal([url.Value], linux.ArgumentList);
        Assert.Empty(linux.Arguments);
        var windows = BrowserOpener.StartInfo(url, windows: true);
        Assert.Equal(url.Value, windows.FileName);
        Assert.True(windows.UseShellExecute);
        Assert.Empty(windows.ArgumentList);
    }

    [Fact]
    public async Task UnderTestModeTheOpenerWritesTheHookFileAndStartsNothing()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-opener-").FullName;
        try
        {
            var url = SignInUrls.Authorize(Center, ByteString.CopyFrom(Flow), Center.ConnectUrl(Flow), out _)!;
            var file = Path.Combine(root, "browser.txt");
            Assert.True(await new BrowserOpener(testMode: true, file).OpenAsync(url, TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken));
            Assert.Equal(url.Value + "\n", await File.ReadAllTextAsync(file, TestContext.Current.CancellationToken));
            Assert.False(await new BrowserOpener(testMode: true, browserFile: null).OpenAsync(url, TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken));
            Assert.Equal(file, CloudLinkTestHooks.Browser(true, file));
            Assert.Null(CloudLinkTestHooks.Browser(false, file));
            Assert.Null(CloudLinkTestHooks.Browser(true, "browser.txt"));
            Assert.Null(CloudLinkTestHooks.Browser(true, " "));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
