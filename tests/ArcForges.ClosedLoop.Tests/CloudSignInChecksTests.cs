// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// The checks of <see cref="CloudSignInTests"/> fail on the behaviour they exist to catch: the refresh step on a first reading with no
/// contact (the old <c>?? 0</c> form passed at once), and the key check on a set that lacks one kid.
/// </summary>
[Trait("loop", "local")]
public sealed class CloudSignInChecksTests
{
    private static CloudSignInChecks.RefreshCounter Feed(params long?[] readings)
    {
        var counter = new CloudSignInChecks.RefreshCounter(15);
        foreach (var reading in readings)
        {
            counter.Observe(reading);
        }

        return counter;
    }

    [Fact]
    public void NoContactYetNeverCountsAsARefresh()
    {
        var counter = Feed(null, null, null);
        Assert.False(counter.HasBaseline);
        Assert.Equal(0, counter.Refreshes);

        // The old form: contact = 0 when the first read has none, then 'LastContactAt >= contact + 25' passes at the first real contact.
        var old = 1_800_000_000L >= 0 + 25;
        Assert.True(old, "documents the broken form: it passed at the first contact");
        Assert.Equal(0, Feed(null, 1_800_000_000).Refreshes);
    }

    [Fact]
    public void OnlyContactsOneCadenceApartCountAndTwoAreNeeded()
    {
        Assert.Equal(0, Feed(100, 100, 101, 105).Refreshes);
        Assert.Equal(1, Feed(null, 100, 115, 115).Refreshes);
        var two = Feed(null, 100, 101, 115, 116, 130);
        Assert.Equal(2, two.Refreshes);
        Assert.Contains("2 refreshes", two.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void KeyExpectationsParseStrictly()
    {
        Assert.Null(CloudSignInChecks.KeyExpectation.Parse(null));
        Assert.Null(CloudSignInChecks.KeyExpectation.Parse("  "));
        var parsed = CloudSignInChecks.KeyExpectation.Parse("command:k1,k2;entitlement:e1")!;
        Assert.Equal(["command", "entitlement"], parsed.Select(item => item.Purpose));
        Assert.Equal(["k1", "k2"], parsed[0].Kids);
        Assert.Throws<FormatException>(() => CloudSignInChecks.KeyExpectation.Parse("signing:k1"));
        Assert.Throws<FormatException>(() => CloudSignInChecks.KeyExpectation.Parse("command:"));
        Assert.Throws<FormatException>(() => CloudSignInChecks.KeyExpectation.Parse("command:k1,k1"));
        Assert.Throws<FormatException>(() => CloudSignInChecks.KeyExpectation.Parse("command:k1;command:k2"));
    }

    [Fact]
    public void AKeySetMissingOneKidOrHoldingAnExtraOneFails()
    {
        var expected = CloudSignInChecks.KeyExpectation.Parse("command:k1,k2")!;
        const string both = """{"centerUrl":"https://c","installationId":"ab","commandKeys":[{"kid":"k1"},{"kid":"k2"}],"entitlementKeys":[]}""";
        const string one = """{"commandKeys":[{"kid":"k1"}],"entitlementKeys":[]}""";
        const string extra = """{"commandKeys":[{"kid":"k1"},{"kid":"k2"},{"kid":"k3"}]}""";
        Assert.Null(CloudSignInChecks.CompareKeys(both, expected));
        Assert.Contains("missing [k2]", CloudSignInChecks.CompareKeys(one, expected), StringComparison.Ordinal);
        Assert.Contains("unexpected [k3]", CloudSignInChecks.CompareKeys(extra, expected), StringComparison.Ordinal);
        Assert.NotNull(CloudSignInChecks.CompareKeys(null, expected));
        Assert.NotNull(CloudSignInChecks.CompareKeys("{", expected));
        Assert.NotNull(CloudSignInChecks.CompareKeys("""{"entitlementKeys":[]}""", expected));
        Assert.Null(CloudSignInChecks.CompareKeys(one, CloudSignInChecks.KeyExpectation.Parse("command:k1")!));
    }
}
