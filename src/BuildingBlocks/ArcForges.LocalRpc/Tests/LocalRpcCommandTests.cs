// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcCommandTests
{
    private const string Operation = "arcforges.local.platform.v1.ConnectorBrokerService/CompleteConnection";

    private static byte[] Digest(byte fill = 7) => Enumerable.Repeat(fill, LocalRpcCommand.DigestBytes).ToArray();

    [Fact]
    public void TheEffectEnumEqualsThePublishedEffectCertaintyValueForValueAndNameForName()
    {
        // The library does not reference the Foundation packages; this is what keeps its own enum from drifting from the published one.
        var ours = Enum.GetValues<LocalRpcEffect>().ToDictionary(value => value.ToString(), value => (int)value);
        var published = Enum.GetValues<EffectCertainty>().ToDictionary(value => value.ToString(), value => (int)value);

        Assert.Equal(published.OrderBy(pair => pair.Key), ours.OrderBy(pair => pair.Key));
        Assert.Equal((int)EffectCertainty.DidNotHappen, (int)LocalRpcEffect.DidNotHappen);
        Assert.Equal((int)EffectCertainty.Happened, (int)LocalRpcEffect.Happened);
        Assert.Equal((int)EffectCertainty.Unknown, (int)LocalRpcEffect.Unknown);
        Assert.Equal((int)EffectCertainty.Unspecified, (int)LocalRpcEffect.Unspecified);
    }

    [Fact]
    public void AValidCommandKeepsItsIdentityAndCopiesTheDigest()
    {
        var id = Guid.NewGuid();
        var digest = Digest(9);

        var command = new LocalRpcCommand(id, Operation, digest, LocalRpcIdempotency.DuplicateSafe, replayAfterUnknown: true);
        digest[0] ^= 0xFF;

        Assert.Equal(id, command.CommandId);
        Assert.Equal(Operation, command.Operation);
        Assert.Equal(LocalRpcIdempotency.DuplicateSafe, command.Idempotency);
        Assert.True(command.ReplayAfterUnknown);
        Assert.Equal(Digest(9), command.InputDigest.ToArray());
        Assert.False(new LocalRpcCommand(id, Operation, Digest(), LocalRpcIdempotency.DuplicateSafe).ReplayAfterUnknown);
    }

    [Fact]
    public void ACommandNeedsARealIdAnOperationAndA32ByteDigest()
    {
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcCommand(Guid.Empty, Operation, Digest(), LocalRpcIdempotency.NonIdempotent));
        _ = Assert.Throws<ArgumentNullException>(() => new LocalRpcCommand(Guid.NewGuid(), null!, Digest(), LocalRpcIdempotency.NonIdempotent));
        foreach (var length in new[] { 0, 1, 31, 33, 64 })
        {
            _ = Assert.Throws<ArgumentException>(() => new LocalRpcCommand(Guid.NewGuid(), Operation, new byte[length], LocalRpcIdempotency.NonIdempotent));
        }

        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcCommand(Guid.NewGuid(), Operation, Digest(), LocalRpcIdempotency.None));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcCommand(Guid.NewGuid(), Operation, Digest(), (LocalRpcIdempotency)99));
    }

    [Theory]
    [InlineData("")]
    [InlineData("NoSlash")]
    [InlineData("/Method")]
    [InlineData("pkg.Service/")]
    [InlineData("pkg.Service/Method/Extra")]
    [InlineData("pkg.Service//Method")]
    [InlineData("pkg.Service/Meth.od")]
    [InlineData("pkg..Service/Method")]
    [InlineData(".pkg.Service/Method")]
    [InlineData("1pkg.Service/Method")]
    [InlineData("pkg.Service/1Method")]
    [InlineData("pkg.Service/Method ")]
    [InlineData("pkg.Ser vice/Method")]
    [InlineData("pkg.Service/Méthod")]
    public void AnOperationThatIsNotAServiceAndAMethodIsRefused(string operation)
    {
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcCommand(Guid.NewGuid(), operation, Digest(), LocalRpcIdempotency.NonIdempotent));
    }

    [Theory]
    [InlineData("pkg.Service/Method")]
    [InlineData("a/b")]
    [InlineData("arcforges.local.platform.v1.LocalBootstrapService/Renew")]
    [InlineData("_pkg.v1_2.Service_3/Method_4")]
    public void AnOperationThatIsAServiceAndAMethodIsAccepted(string operation)
    {
        Assert.Equal(operation, new LocalRpcCommand(Guid.NewGuid(), operation, Digest(), LocalRpcIdempotency.Query).Operation);
    }

    [Theory]
    [InlineData(LocalRpcIdempotency.Query)]
    [InlineData(LocalRpcIdempotency.NonIdempotent)]
    public void OnlyADuplicateSafeCommandMayAskToBeReplayedAfterAnUnknownEffect(LocalRpcIdempotency idempotency)
    {
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcCommand(Guid.NewGuid(), Operation, Digest(), idempotency, replayAfterUnknown: true));
    }

    [Fact]
    public void ThePlainDigestIsTheSha256OfTheCanonicalInput()
    {
        var input = "canonical input"u8.ToArray();

        var digest = LocalRpcCommand.DigestOf(input);

        Assert.Equal(SHA256.HashData(input), digest);
        Assert.Equal(LocalRpcCommand.DigestBytes, digest.Length);
        Assert.NotEqual(digest, LocalRpcCommand.DigestOf("canonical inpuT"u8));
        Assert.Equal(32, LocalRpcCommand.DigestBytes);
    }

    [Fact]
    public void ASameCommandMatchesOnlyTheSameOperationDigestAndIdempotency()
    {
        var command = new LocalRpcCommand(Guid.NewGuid(), Operation, Digest(), LocalRpcIdempotency.DuplicateSafe);

        Assert.True(command.IsSameCommandAs(Operation, Digest(), LocalRpcIdempotency.DuplicateSafe));
        Assert.False(command.IsSameCommandAs(Operation + "2", Digest(), LocalRpcIdempotency.DuplicateSafe));
        Assert.False(command.IsSameCommandAs(Operation, Digest(8), LocalRpcIdempotency.DuplicateSafe));
        Assert.False(command.IsSameCommandAs(Operation, Digest(), LocalRpcIdempotency.NonIdempotent));
        var lastByte = Digest();
        lastByte[^1] ^= 1;
        Assert.False(command.IsSameCommandAs(Operation, lastByte, LocalRpcIdempotency.DuplicateSafe));
    }

    [Fact]
    public void AGenerationIsTheLaunchIdAndEpochOfADescriptor()
    {
        var descriptor = Launches.Descriptor(epoch: 5);

        var generation = LocalRpcPeerGeneration.From(descriptor);

        Assert.Equal(descriptor.LaunchId, generation.LaunchId);
        Assert.Equal(5UL, generation.Epoch);
        Assert.NotEqual(generation, new LocalRpcPeerGeneration(descriptor.LaunchId, 6));
        Assert.NotEqual(generation, new LocalRpcPeerGeneration(Guid.NewGuid(), 5));
        Assert.Equal(generation, new LocalRpcPeerGeneration(descriptor.LaunchId, 5));
        _ = Assert.Throws<ArgumentNullException>(() => LocalRpcPeerGeneration.From(null!));
    }
}
