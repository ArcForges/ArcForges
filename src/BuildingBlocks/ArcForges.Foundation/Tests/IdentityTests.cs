// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Serialization;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using Xunit;

namespace ArcForges.Foundation.Tests;

public sealed class IdentityTests
{
    [Fact]
    public void CanonicalUuidRoundTripUsesNetworkOrderAndRejectsDefault()
    {
        var id = new WorkspaceId(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"));
        Assert.Equal("00112233445566778899AABBCCDDEEFF", Convert.ToHexString(id.ToWire().Value.Span));
        Assert.Equal(id, WorkspaceId.FromWire(id.ToWire()));
        Assert.Throws<ArgumentException>(() => default(WorkspaceId).ToWire());
        Assert.Throws<ArgumentException>(() => WorkspaceId.FromWire(new Id()));
        Assert.NotEqual(IdentityGeneration.NewCommand(), IdentityGeneration.NewCommand());
    }

    [Fact]
    public void ExactPublishedValuesNeverPassThroughFloatingPoint()
    {
        Assert.Equal(9_007_199_254_740_993L, ExactInteger.ParseInt64("9007199254740993"));
        Assert.Equal(ulong.MaxValue, ExactInteger.ParseUInt64("18446744073709551615"));
        Assert.Equal("0.000000001", new ExactDecimal("0.000000001").ToWire().Value);
        Assert.Throws<FormatException>(() => ExactInteger.ParseInt64("+1"));
        Assert.Throws<FormatException>(() => ExactInteger.ParseInt64("01"));
    }

    [Fact]
    public void ExplicitEpochAndAbsenceRemainDifferent()
    {
        Assert.Throws<ArgumentException>(() => WireValues.ReadInstant(new ArcForges.Contracts.Foundation.V1.Instant()));
        var epoch = WireValues.ToWire(default(Instant));
        Assert.True(epoch.HasUnixSeconds);
        Assert.True(epoch.HasNanos);
        Assert.Equal(default, WireValues.ReadInstant(epoch));
        Assert.Equal(new Instant(0, 1), WireValues.ReadInstant(WireValues.ToWire(new Instant(0, 1))));
    }

    [Fact]
    public void UnknownResponseEnumsPreserveBitsButNeverAuthorizeMutation()
    {
        var future = new EnumProjection<EffectCertainty>((EffectCertainty)999);
        Assert.False(future.IsKnown);
        Assert.Equal((EffectCertainty)999, future.Value);
        Assert.Throws<InvalidOperationException>(() => future.RequireKnown());
        Assert.False(default(EnumProjection<EffectCertainty>).IsKnown);
    }

    [Fact]
    public void PublishedCodecPreservesUnknownFields()
    {
        byte[] futureId = [0xA0, 0x06, 0x01];
        var value = ContractWire.Decode(Id.Parser, futureId, WireLimit.UnaryMessage);
        Assert.Equal(futureId, ContractWire.Encode(value, WireLimit.UnaryMessage));
        Assert.Throws<ArgumentException>(() => UuidBoundary.FromWire(value));
    }
}
