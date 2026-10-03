// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Security.Egress;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>EG-05: a destination is one exact lower-case HTTPS origin; everything that could widen or disguise it is not an identity.</summary>
public sealed class EgressDestinationTests
{
    [Theory]
    [InlineData("https://api.example.com", "https://api.example.com", "api.example.com", 443)]
    [InlineData("https://api.example.com/", "https://api.example.com", "api.example.com", 443)]
    [InlineData("HTTPS://API.Example.COM/", "https://api.example.com", "api.example.com", 443)]
    [InlineData("https://api.example.com:443", "https://api.example.com", "api.example.com", 443)]
    [InlineData("https://api.example.com:8443", "https://api.example.com:8443", "api.example.com", 8443)]
    [InlineData("https://api.example.com:1", "https://api.example.com:1", "api.example.com", 1)]
    [InlineData("https://api.example.com:65535/", "https://api.example.com:65535", "api.example.com", 65535)]
    [InlineData("https://xn--bcher-kva.example", "https://xn--bcher-kva.example", "xn--bcher-kva.example", 443)]
    [InlineData("https://a-b.c-d.example.co.uk", "https://a-b.c-d.example.co.uk", "a-b.c-d.example.co.uk", 443)]
    [InlineData("https://1password.com", "https://1password.com", "1password.com", 443)]
    public void AnExactHttpsOriginIsCanonicalisedToLowerCaseWithTheDefaultPortImplied(string text, string origin, string host, int port)
    {
        Assert.True(EgressDestinationIdentity.TryParse(text, out var identity));
        Assert.Equal(origin, identity.Origin);
        Assert.Equal(host, identity.Host);
        Assert.Equal(port, identity.Port);
        Assert.Equal(origin, EgressDestinationIdentity.Parse(text).Origin);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("api.example.com")]
    [InlineData("//api.example.com")]
    [InlineData("http://api.example.com")]
    [InlineData("ftp://api.example.com")]
    [InlineData("wss://api.example.com")]
    [InlineData("https:/api.example.com")]
    [InlineData("https://")]
    [InlineData("https:///")]
    [InlineData("https://api.example.com//")]
    [InlineData("https://api.example.com/path")]
    [InlineData("https://api.example.com/v1/")]
    [InlineData("https://api.example.com?x=1")]
    [InlineData("https://api.example.com/?x=1")]
    [InlineData("https://api.example.com#fragment")]
    [InlineData("https://user@api.example.com")]
    [InlineData("https://user:pw@api.example.com")]
    [InlineData("https://api.example.com@evil.example")]
    [InlineData("https://evil.example\\@api.example.com")]
    [InlineData("https://*.example.com")]
    [InlineData("https://*")]
    [InlineData("https://api.*.com")]
    [InlineData("https://api.example.com.")]
    [InlineData("https://.example.com")]
    [InlineData("https://api..example.com")]
    [InlineData("https://-api.example.com")]
    [InlineData("https://api-.example.com")]
    [InlineData("https://api_x.example.com")]
    [InlineData("https://api.example.com:")]
    [InlineData("https://api.example.com:0")]
    [InlineData("https://api.example.com:0443")]
    [InlineData("https://api.example.com:65536")]
    [InlineData("https://api.example.com:99999")]
    [InlineData("https://api.example.com:123456")]
    [InlineData("https://api.example.com:-1")]
    [InlineData("https://api.example.com:44a")]
    [InlineData("https://api.example.com:443:443")]
    [InlineData("https://api.example.com%2f")]
    [InlineData("https://api.example.com%40evil.example")]
    [InlineData("https://api example.com")]
    [InlineData("https://api.example.com\t")]
    [InlineData("https://api.example.com\n")]
    [InlineData("https://api.example.com\0")]
    [InlineData("https://bücher.example")]
    [InlineData("https://аpi.example.com")]
    [InlineData("https://localhost")]
    [InlineData("https://localhost:8443")]
    [InlineData("https://intranet")]
    [InlineData("https://app.localhost")]
    [InlineData("https://printer.local")]
    [InlineData("https://db.internal")]
    [InlineData("https://host.localdomain")]
    [InlineData("https://nas.lan")]
    [InlineData("https://router.home.arpa")]
    [InlineData("https://127.0.0.1")]
    [InlineData("https://10.0.0.5")]
    [InlineData("https://192.168.1.1:8443")]
    [InlineData("https://169.254.169.254")]
    [InlineData("https://8.8.8.8")]
    [InlineData("https://[::1]")]
    [InlineData("https://[2001:db8::1]:443")]
    [InlineData("https://example.123")]
    public void AnythingThatIsNotAnExactPublicHttpsNameIsNotADestination(string? text)
    {
        Assert.False(EgressDestinationIdentity.TryParse(text, out var identity));
        Assert.Null(identity);
        if (text is not null)
        {
            Assert.Throws<ArgumentException>(() => EgressDestinationIdentity.Parse(text));
        }
    }

    [Fact]
    public void ALookalikeIsADifferentDestination()
    {
        var exact = EgressDestinationIdentity.Parse("https://api.example.com");
        foreach (var other in new[]
        {
            "https://api.example.com.evil.net",
            "https://evilapi.example.com",
            "https://sub.api.example.com",
            "https://example.com",
            "https://api.example.org",
            "https://api.example.com:8443",
            "https://api.example.co",
        })
        {
            var identity = EgressDestinationIdentity.Parse(other);
            Assert.NotEqual(exact, identity);
            Assert.False(exact.Equals(identity));
        }

        Assert.Equal(exact, EgressDestinationIdentity.Parse("HTTPS://API.EXAMPLE.COM:443/"));
        Assert.Equal(exact.GetHashCode(), EgressDestinationIdentity.Parse("HTTPS://API.EXAMPLE.COM:443/").GetHashCode());
    }

    [Fact]
    public void HostLabelAndLengthBoundsAreExact()
    {
        var label63 = new string('a', 63);
        var label64 = new string('a', 64);
        Assert.True(EgressDestinationIdentity.TryParse($"https://{label63}.example", out _));
        Assert.False(EgressDestinationIdentity.TryParse($"https://{label64}.example", out _));

        // 253 characters: three 63-character labels, one 61-character label and the final "com" label with its dots.
        var host253 = string.Join('.', label63, label63, label63, new string('b', 57), "com");
        Assert.Equal(253, host253.Length);
        Assert.True(EgressDestinationIdentity.TryParse($"https://{host253}", out _));
        Assert.False(EgressDestinationIdentity.TryParse($"https://{host253}x", out _));
        Assert.False(EgressDestinationIdentity.TryParse("https://" + new string('a', 400) + ".example", out _));
    }

    [Fact]
    public void AnOverlongTextIsRefusedBeforeAnyParsing()
    {
        var text = "https://api.example.com/" + new string('/', EgressDestinationIdentity.MaximumLength);
        Assert.False(EgressDestinationIdentity.TryParse(text, out _));
    }
}
