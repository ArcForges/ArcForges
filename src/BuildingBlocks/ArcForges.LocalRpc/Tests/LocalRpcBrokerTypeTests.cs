// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>The value types of the brokered transfer: digests, canonical identifiers, the limits and their bounds.</summary>
public sealed class LocalRpcBrokerTypeTests
{
    [Fact]
    public void ADigestIsTheSha256OfTheData()
    {
        byte[] data = [1, 2, 3, 4, 5];

        var digest = LocalRpcDigest.Compute(data);

        Assert.Equal(LocalRpcDigest.Length, digest.AsSpan().Length);
        Assert.Equal(32, LocalRpcDigest.Length);
        Assert.True(digest.AsSpan().SequenceEqual(SHA256.HashData(data)));
        Assert.False(digest.AsSpan().SequenceEqual(SHA256.HashData([1, 2, 3, 4, 6])));
    }

    [Fact]
    public void TheWireFormIsSixtyFourLowercaseHexCharactersAndRoundTrips()
    {
        var digest = LocalRpcDigest.Compute([9, 8, 7]);
        var expected = Convert.ToHexStringLower(SHA256.HashData([9, 8, 7]));

        Assert.Equal(expected, digest.ToHex());
        Assert.Equal(expected, digest.ToString());
        Assert.Equal(64, digest.ToHex().Length);
        Assert.True(LocalRpcDigest.TryParse(expected, out var parsed));
        Assert.Equal(digest, parsed);
        Assert.True(parsed!.AsSpan().SequenceEqual(digest.AsSpan()));
    }

    [Fact]
    public void OnlyExactlySixtyFourLowercaseHexCharactersParse()
    {
        var valid = Convert.ToHexStringLower(SHA256.HashData([1]));
        Assert.True(LocalRpcDigest.TryParse(valid, out _));

        Assert.False(LocalRpcDigest.TryParse(null, out var none));
        Assert.Null(none);
        Assert.False(LocalRpcDigest.TryParse(string.Empty, out _));
        Assert.False(LocalRpcDigest.TryParse(valid[..63], out _));
        Assert.False(LocalRpcDigest.TryParse(valid + "0", out _));
        Assert.False(LocalRpcDigest.TryParse(valid.ToUpperInvariant().Replace('0', 'A'), out _));

        // Every character just outside each accepted range is refused wherever it stands, and so is every character class that is not hex.
        foreach (var bad in new[] { '/', ':', '`', 'g', 'G', 'F', 'A', ' ', '\0', 'x', '-' })
        {
            Assert.False(LocalRpcDigest.TryParse(bad + valid[1..], out _), "first character " + bad);
            Assert.False(LocalRpcDigest.TryParse(valid[..63] + bad, out _), "last character " + bad);
            Assert.False(LocalRpcDigest.TryParse(valid[..31] + bad + valid[32..], out _), "middle character " + bad);
        }

        // The accepted range boundaries themselves are accepted.
        Assert.True(LocalRpcDigest.TryParse(new string('0', 32) + new string('9', 16) + new string('a', 8) + new string('f', 8), out _));
    }

    [Fact]
    public void ADigestIsBuiltFromExactlyThirtyTwoBytesAndCopiesThem()
    {
        Assert.Throws<ArgumentException>(() => LocalRpcDigest.FromBytes(new byte[31]));
        Assert.Throws<ArgumentException>(() => LocalRpcDigest.FromBytes(new byte[33]));
        Assert.Throws<ArgumentException>(() => LocalRpcDigest.FromBytes([]));

        var source = SHA256.HashData([4]);
        var digest = LocalRpcDigest.FromBytes(source);
        source[0] ^= 0xFF;

        Assert.True(digest.AsSpan().SequenceEqual(SHA256.HashData([4])));
    }

    [Fact]
    public void DigestsAreEqualOnlyWhenEveryByteIs()
    {
        var bytes = SHA256.HashData([5]);
        var digest = LocalRpcDigest.FromBytes(bytes);

        Assert.Equal(digest, LocalRpcDigest.FromBytes(bytes));
        Assert.True(digest.Equals((object)LocalRpcDigest.FromBytes(bytes)));
        Assert.Equal(digest.GetHashCode(), LocalRpcDigest.FromBytes(bytes).GetHashCode());
        Assert.False(digest.Equals(null));
        Assert.False(digest.Equals((object?)"text"));
        for (var index = 0; index < bytes.Length; index++)
        {
            var other = (byte[])bytes.Clone();
            other[index] ^= 1;
            Assert.NotEqual(digest, LocalRpcDigest.FromBytes(other));
        }
    }

    [Fact]
    public void AnIdentifierIsSixteenBytesInCanonicalUuidOrder()
    {
        byte[] bytes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        Assert.True(LocalRpcCanonicalId.TryRead(bytes, out var id));

        Assert.Equal(new Guid("00010203-0405-0607-0809-0a0b0c0d0e0f"), id);
        Assert.NotEqual(new Guid(bytes), id);
        var written = new byte[16];
        LocalRpcCanonicalId.Write(id, written);
        Assert.Equal(bytes, written);
        Assert.Equal(16, LocalRpcCanonicalId.Length);
        Assert.NotEqual(id.ToByteArray(), written);
    }

    [Fact]
    public void AnIdentifierOfAnotherLengthOrZeroIsRefused()
    {
        Assert.False(LocalRpcCanonicalId.TryRead(new byte[16], out var zero));
        Assert.Equal(Guid.Empty, zero);
        Assert.False(LocalRpcCanonicalId.TryRead(new byte[15], out _));
        Assert.False(LocalRpcCanonicalId.TryRead(new byte[17], out _));
        Assert.False(LocalRpcCanonicalId.TryRead([], out _));
        var oneBit = new byte[16];
        oneBit[15] = 1;
        Assert.True(LocalRpcCanonicalId.TryRead(oneBit, out var small));
        Assert.NotEqual(Guid.Empty, small);

        Assert.Throws<ArgumentException>(() => LocalRpcCanonicalId.Write(Guid.NewGuid(), new byte[15]));
        Assert.Throws<ArgumentException>(() => LocalRpcCanonicalId.Write(Guid.NewGuid(), new byte[17]));
    }

    [Fact]
    public void TheDefaultLimitsAreTheProfileValues()
    {
        var limits = new LocalRpcBrokerLimits();

        Assert.Equal(3, LocalRpcBrokerLimits.MaxSlots);
        Assert.Equal(64L * 1024 * 1024, LocalRpcBrokerLimits.MaxSlotBytes);
        Assert.Equal(TimeSpan.FromSeconds(30), LocalRpcBrokerLimits.MaxSessionLease);
        Assert.Equal(TimeSpan.FromSeconds(5), LocalRpcBrokerLimits.MaxCancelGrace);
        Assert.Equal(256 * 1024, limits.ChunkBytes);
        Assert.Equal(TimeSpan.FromSeconds(30), limits.SessionLease);
        Assert.Equal(TimeSpan.FromSeconds(5), limits.CancelGrace);
        Assert.Equal(8, limits.MaxSessions);
    }

    [Theory]
    [InlineData(4095, false)]
    [InlineData(4096, true)]
    [InlineData(4 * 1024 * 1024, true)]
    [InlineData((4 * 1024 * 1024) + 1, false)]
    [InlineData(0, false)]
    [InlineData(-1, false)]
    public void TheChunkSizeIsFourKibThroughFourMib(int chunk, bool accepted) =>
        AssertLimit(new LocalRpcBrokerLimits { ChunkBytes = chunk }, accepted, nameof(LocalRpcBrokerLimits.ChunkBytes));

    [Theory]
    [InlineData(0, false)]
    [InlineData(-1, false)]
    [InlineData(1, true)]
    [InlineData(30_000, true)]
    [InlineData(30_001, false)]
    public void TheSessionLeaseIsPositiveAndAtMostThirtySeconds(int milliseconds, bool accepted) =>
        AssertLimit(new LocalRpcBrokerLimits { SessionLease = TimeSpan.FromMilliseconds(milliseconds) }, accepted, nameof(LocalRpcBrokerLimits.SessionLease));

    [Theory]
    [InlineData(0, false)]
    [InlineData(-1, false)]
    [InlineData(1, true)]
    [InlineData(5_000, true)]
    [InlineData(5_001, false)]
    public void TheCancelGraceIsPositiveAndAtMostFiveSeconds(int milliseconds, bool accepted) =>
        AssertLimit(new LocalRpcBrokerLimits { CancelGrace = TimeSpan.FromMilliseconds(milliseconds) }, accepted, nameof(LocalRpcBrokerLimits.CancelGrace));

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(64, true)]
    [InlineData(65, false)]
    [InlineData(-1, false)]
    public void TheSessionBoundIsOneThroughSixtyFour(int sessions, bool accepted) =>
        AssertLimit(new LocalRpcBrokerLimits { MaxSessions = sessions }, accepted, nameof(LocalRpcBrokerLimits.MaxSessions));

    [Fact]
    public void AResultIsASuccessOnlyWithAValueAndNoRefusal()
    {
        var value = new LocalRpcSlotGrant(0, 1, 10);

        Assert.True(new LocalRpcBrokerResult<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.None, value).IsSuccess);
        Assert.False(new LocalRpcBrokerResult<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.Expired, value).IsSuccess);
        Assert.False(new LocalRpcBrokerResult<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.None, null).IsSuccess);
        Assert.False(new LocalRpcBrokerResult<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.Expired, null).IsSuccess);
    }

    private static void AssertLimit(LocalRpcBrokerLimits limits, bool accepted, string parameter)
    {
        if (accepted)
        {
            using var registry = new LocalRpcBrokerRegistry(limits);
            Assert.Equal(0, registry.OpenSessions);
            return;
        }

        var failure = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcBrokerRegistry(limits));
        Assert.Equal(parameter, failure.ParamName);
    }
}
