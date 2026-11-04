// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N1-1 (unit): the center URL (CTR4-NODE-01 as amended; SEC-11/19). The node's narrower rules (its http host set, the 512 bound, the fleet
/// base warning) are pinned here; the rules it shares with the center's <c>ParsePublicBaseURL</c> are pinned by the vendored Cloud vector file
/// (<c>CenterUrlVectorTests</c>, N1 decision R-2).
/// </summary>
public sealed class CenterEndpointTests
{
    [Theory]
    [InlineData("https://arcforges.com/api", "https", "arcforges.com", null, "/api", "https://arcforges.com")]
    [InlineData("https://center.example.test", "https", "center.example.test", null, "", "https://center.example.test")]
    [InlineData("https://center.example.test:8443/a/b-c_d.e~f", "https", "center.example.test", 8443, "/a/b-c_d.e~f", "https://center.example.test:8443")]
    [InlineData("http://localhost:18080", "http", "localhost", 18080, "", "http://localhost:18080")]
    [InlineData("http://127.0.0.1:1/api", "http", "127.0.0.1", 1, "/api", "http://127.0.0.1:1")]
    [InlineData("http://[::1]:8443", "http", "[::1]", 8443, "", "http://[::1]:8443")]
    [InlineData("https://xn--bcher-kva.example", "https", "xn--bcher-kva.example", null, "", "https://xn--bcher-kva.example")]
    public void TheCenterUrlIsAcceptedOnlyAsWritten(string url, string scheme, string host, int? port, string path, string origin)
    {
        Assert.True(CenterEndpoint.TryParse(url, out var endpoint, out var reason), reason);
        Assert.Equal(url, endpoint.Url);
        Assert.Equal(scheme, endpoint.Scheme);
        Assert.Equal(host, endpoint.Host);
        Assert.Equal(port, endpoint.Port);
        Assert.Equal(path, endpoint.PathBase);
        Assert.Equal(origin, endpoint.Origin);
    }

    [Theory]
    [InlineData("", "required")]
    [InlineData("http://example.org", "https")]
    [InlineData("http://127.0.0.2:8080", "https")]
    [InlineData("http://localhost.example:8080", "https")]
    [InlineData("ftp://arcforges.com", "https")]
    [InlineData("HTTPS://arcforges.com", "https")]
    [InlineData("https://ArcForges.com", "lower-case")]
    [InlineData("https://arcforges.com.", "lower-case")]
    [InlineData("https://user@arcforges.com", "user information")]
    [InlineData("https://arcforges.com/api?x=1", "query")]
    [InlineData("https://arcforges.com/api#frag", "fragment")]
    [InlineData("https://arcforges.com/a%20b", "percent")]
    [InlineData("https://arcforges.com\\api", "backslash")]
    [InlineData("https://arcforges.com/api/", "trailing slash")]
    [InlineData("https://arcforges.com/", "trailing slash")]
    [InlineData("https://arcforges.com//api", "empty or dot")]
    [InlineData("https://arcforges.com/./api", "empty or dot")]
    [InlineData("https://arcforges.com/a/../b", "empty or dot")]
    [InlineData("https://arcforges.com/a!b", "outside letters")]
    [InlineData("https://arcforges.com:443/api", "default")]
    [InlineData("http://localhost:80", "default")]
    [InlineData("https://arcforges.com:0", "port")]
    [InlineData("https://arcforges.com:65536", "port")]
    [InlineData("https://arcforges.com:080", "port")]
    [InlineData("https://arcforges.com:", "port")]
    [InlineData("https://bücher.example", "non-ASCII")]
    [InlineData("https://arc forges.com", "space")]
    [InlineData("https://[::1", "IPv6")]
    [InlineData("https://[FE80::1]", "IPv6")]
    public void ANonCanonicalCenterUrlIsRefusedWithItsRule(string url, string rule)
    {
        Assert.False(CenterEndpoint.TryParse(url, out _, out var reason));
        Assert.Contains(rule, reason, StringComparison.Ordinal);
    }

    [Fact]
    public void TheSettingIsBoundedBy512CharactersAndWarnsAboveTheFleetBase()
    {
        var at462 = "https://c.example/" + new string('a', 462 - "https://c.example/".Length);
        var at463 = at462 + "b";
        var at512 = "https://c.example/" + new string('a', 512 - "https://c.example/".Length);
        Assert.True(CenterEndpoint.TryParse(at462, out var fits, out _));
        Assert.False(fits.ExceedsFleetBase);
        Assert.True(CenterEndpoint.TryParse(at463, out var over, out _));
        Assert.True(over.ExceedsFleetBase);
        Assert.True(CenterEndpoint.TryParse(at512, out _, out _));
        Assert.False(CenterEndpoint.TryParse(at512 + "a", out _, out var reason));
        Assert.Contains("512", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void TheNodeDerivesTheCentersUrlsItself()
    {
        var center = CenterEndpoint.Parse("https://arcforges.com/api");
        byte[] flow = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];

        // fleet.proto authorize_url: the RFC 9562 form of the 16 bytes in order, never a platform GUID byte order.
        Assert.Equal("https://arcforges.com/api/connect#flow=01234567-89ab-cdef-fedc-ba9876543210", center.ConnectUrl(flow));
        Assert.NotEqual(center.ConnectUrl(flow), "https://arcforges.com/api/connect#flow=" + new Guid(flow).ToString("D"));
        Assert.Equal("https://arcforges.com/api/activate", center.ActivateUrl);
        Assert.Equal("https://arcforges.com/api/activate#code=BCDF-GHJK", center.ActivateCompleteUrl("BCDFGHJK"));
        Assert.Throws<ArgumentException>(() => center.ActivateCompleteUrl("BCDFGHJA"));
        Assert.Throws<ArgumentException>(() => center.ConnectUrl(new byte[15]));
    }
}
