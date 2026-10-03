#pragma warning disable CA2000 // Test mappings are handed to the session under test, which owns and disposes them.
// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// The parent side of the slot protocol: grant, seal, bounded private copy with the digest checked on the copy, and the
/// acknowledgement that frees the slot. Every refusal is checked together with the state it must leave behind.
/// </summary>
// One collection with the other heavy LocalRpc tests: the real-clock, 64 MiB and many-thread cases must not load the machine beside timing-sensitive tests.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcBrokerSessionTests
{
    private const uint Slot0 = 0;
    private const uint Slot1 = 1;

    [Fact]
    public void AGrantCarriesTheSlotItsFirstSequenceAndTheCapacityAndStartsWriting()
    {
        using var rig = BrokerRig.Create();

        var grant = rig.Session.Grant(Slot1, 4096);

        Assert.True(grant.IsSuccess);
        Assert.Equal(new LocalRpcSlotGrant(Slot1, 1, 4096), grant.Value);
        var snapshot = rig.Session.GetSnapshot();
        Assert.Equal([LocalRpcSlotState.Free, LocalRpcSlotState.Writing, LocalRpcSlotState.Free], snapshot.Slots);
        Assert.Equal([1UL, 1UL, 1UL], snapshot.NextSequences);
        Assert.Equal(0, snapshot.Refusals);
        Assert.Equal(LocalRpcBrokerSessionState.Open, snapshot.State);
    }

    [Fact]
    public void ASlotThatIsNotOneOfTheSessionsIsRefusedWithoutWrapping()
    {
        using var rig = BrokerRig.Create(slots: 2);

        foreach (var slot in new[] { 2U, 3U, 255U, uint.MaxValue })
        {
            var grant = rig.Session.Grant(slot, 10);
            Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, grant.Refusal);
            Assert.Null(grant.Value);
        }

        Assert.Equal([LocalRpcSlotState.Free, LocalRpcSlotState.Free], rig.Session.GetSnapshot().Slots);
        Assert.Equal(4, rig.Session.GetSnapshot().Refusals);
    }

    [Fact]
    public void TheCapacityIsPositiveAndNoLargerThanTheSlotsMapping()
    {
        using var rig = BrokerRig.Create(slotBytes: 8192);

        Assert.Equal(LocalRpcBrokerRefusal.CapacityExceeded, rig.Session.Grant(Slot0, 0).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.CapacityExceeded, rig.Session.Grant(Slot0, 8193).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.CapacityExceeded, rig.Session.Grant(Slot0, ulong.MaxValue).Refusal);
        Assert.Equal(LocalRpcSlotState.Free, rig.Session.GetSnapshot().Slots[0]);

        Assert.Equal(8192UL, rig.Session.Grant(Slot0, 8192).Value!.Capacity);
        Assert.Equal(1UL, rig.Session.Grant(Slot1, 1).Value!.Capacity);
    }

    [Fact]
    public async Task ASlotThatIsNotFreeIsNeverGrantedAgain()
    {
        using var rig = BrokerRig.Create();
        var first = rig.Session.Grant(Slot0, 4096).Value!;

        var writing = rig.Session.Grant(Slot0, 4096);
        Assert.Equal(LocalRpcBrokerRefusal.SlotBusy, writing.Refusal);
        Assert.Equal(LocalRpcSlotState.Writing, rig.Session.GetSnapshot().Slots[0]);

        var content = BrokerRig.Pattern(100);
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(rig.HonestSeal(first, content)));
        Assert.Equal(LocalRpcBrokerRefusal.SlotBusy, rig.Session.Grant(Slot0, 4096).Refusal);
        Assert.Equal(LocalRpcSlotState.Sealed, rig.Session.GetSnapshot().Slots[0]);

        using var buffer = (await CopyAsync(rig, Slot0, first.Sequence)).Value!;
        Assert.Equal(LocalRpcBrokerRefusal.SlotBusy, rig.Session.Grant(Slot0, 4096).Refusal);
        Assert.Equal(LocalRpcSlotState.Reading, rig.Session.GetSnapshot().Slots[0]);
    }

    [Fact]
    public async Task SequencesGrowByOneAfterEachAcknowledgementAndNeverRepeat()
    {
        using var rig = BrokerRig.Create();
        for (var round = 1UL; round <= 4; round++)
        {
            var grant = rig.Session.Grant(Slot0, 1024).Value!;
            Assert.Equal(round, grant.Sequence);
            var content = BrokerRig.Pattern(10, (byte)round);
            Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(rig.HonestSeal(grant, content)));
            using var buffer = (await CopyAsync(rig, Slot0, grant.Sequence)).Value!;
            Assert.True(rig.Session.Acknowledge(Slot0, grant.Sequence).IsSuccess);
            Assert.Equal(round + 1, rig.Session.GetSnapshot().NextSequences[0]);
        }

        // The other slots keep their own sequence.
        Assert.Equal(1UL, rig.Session.Grant(Slot1, 1024).Value!.Sequence);
    }

    [Fact]
    public async Task ASequenceNeverWrapsAndTheLastOneBeforeTheEndStillWorks()
    {
        using var rig = BrokerRig.Create(firstSequence: ulong.MaxValue);
        Assert.Equal(LocalRpcBrokerRefusal.SequenceExhausted, rig.Session.Grant(Slot0, 10).Refusal);
        Assert.Equal(LocalRpcSlotState.Free, rig.Session.GetSnapshot().Slots[0]);

        using var last = BrokerRig.Create(firstSequence: ulong.MaxValue - 1);
        var grant = last.Session.Grant(Slot0, 100).Value!;
        Assert.Equal(ulong.MaxValue - 1, grant.Sequence);
        Assert.Equal(LocalRpcBrokerRefusal.None, last.Session.Seal(last.HonestSeal(grant, BrokerRig.Pattern(10))));
        using var buffer = (await CopyAsync(last, Slot0, grant.Sequence)).Value!;
        Assert.True(last.Session.Acknowledge(Slot0, grant.Sequence).IsSuccess);
        Assert.Equal(ulong.MaxValue, last.Session.GetSnapshot().NextSequences[0]);
        Assert.Equal(LocalRpcBrokerRefusal.SequenceExhausted, last.Session.Grant(Slot0, 10).Refusal);
    }

    [Fact]
    public void AnHonestSealIsAcceptedAndTheSlotIsSealed()
    {
        using var rig = BrokerRig.Create();
        var grant = rig.Session.Grant(Slot0, 4096).Value!;

        var refusal = rig.Session.Seal(rig.HonestSeal(grant, BrokerRig.Pattern(100)));

        Assert.Equal(LocalRpcBrokerRefusal.None, refusal);
        Assert.Equal(LocalRpcSlotState.Sealed, rig.Session.GetSnapshot().Slots[0]);
    }

    [Theory]
    [InlineData("invocation")]
    [InlineData("lease")]
    [InlineData("generation")]
    public void ASealOfAnotherInvocationLeaseOrGenerationIsAWrongResourceGrant(string which)
    {
        using var rig = BrokerRig.Create();
        var grant = rig.Session.Grant(Slot0, 4096).Value!;
        var honest = rig.HonestSeal(grant, BrokerRig.Pattern(100));
        var forged = which switch
        {
            "invocation" => honest with { InvocationId = Guid.NewGuid() },
            "lease" => honest with { LeaseId = Guid.NewGuid() },
            _ => honest with { Generation = honest.Generation + 1 },
        };

        Assert.Equal(LocalRpcBrokerRefusal.WrongSession, rig.Session.Seal(forged));

        // Nothing changed: the real seal is still welcome.
        Assert.Equal(LocalRpcSlotState.Writing, rig.Session.GetSnapshot().Slots[0]);
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(honest));
    }

    [Fact]
    public void ASealMintedForAnotherSessionOfTheSameRegistryIsRefused()
    {
        using var registry = new LocalRpcBrokerRegistry(null, new ManualTimeProvider());
        var other = new Guid("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        var mapA = new MemoryMapping(4096);
        var mapB = new MemoryMapping(4096);
        var a = registry.CreateSession(new LocalRpcBrokerSessionOptions { InvocationId = BrokerRig.Invocation, LeaseId = BrokerRig.Lease, Generation = 1, Slots = [mapA] }).Value!;
        var b = registry.CreateSession(new LocalRpcBrokerSessionOptions { InvocationId = other, LeaseId = BrokerRig.Lease, Generation = 1, Slots = [mapB] }).Value!;
        var grantA = a.Grant(Slot0, 100).Value!;
        var grantB = b.Grant(Slot0, 100).Value!;
        Assert.Equal(grantA, grantB);
        var content = BrokerRig.Pattern(50);
        content.CopyTo(mapA.Bytes, 0);
        var sealForA = new LocalRpcBufferSeal(BrokerRig.Invocation, BrokerRig.Lease, 1, Slot0, grantA.Sequence, 0, 50, LocalRpcDigest.Compute(content), 0);

        // Same slot, same sequence, same lease: only the invocation differs, and a transfer cannot be replayed into another product's session.
        Assert.Equal(LocalRpcBrokerRefusal.WrongSession, b.Seal(sealForA));
        Assert.Equal(LocalRpcBrokerRefusal.None, a.Seal(sealForA));
        Assert.Equal(LocalRpcSlotState.Writing, b.GetSnapshot().Slots[0]);
    }

    [Fact]
    public void ASealForASlotTheSessionDoesNotHaveIsRefused()
    {
        using var rig = BrokerRig.Create(slots: 2);
        var grant = rig.Session.Grant(Slot0, 4096).Value!;
        var honest = rig.HonestSeal(grant, BrokerRig.Pattern(10));

        foreach (var slot in new[] { 2U, 3U, uint.MaxValue })
        {
            Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, rig.Session.Seal(honest with { SlotId = slot }));
        }

        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(honest));
    }

    [Fact]
    public async Task ASealIsHonouredOnlyForAnOutstandingGrant()
    {
        using var rig = BrokerRig.Create();
        var never = new LocalRpcBufferSeal(BrokerRig.Invocation, BrokerRig.Lease, BrokerRig.GenerationValue, Slot0, 1, 0, 10, LocalRpcDigest.Compute([1]), 0);
        Assert.Equal(LocalRpcBrokerRefusal.NotGranted, rig.Session.Seal(never));

        var grant = rig.Session.Grant(Slot0, 4096).Value!;
        var honest = rig.HonestSeal(grant, BrokerRig.Pattern(10));
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(honest));

        // A replay of the same seal, while sealed and while being read, is refused and changes nothing.
        Assert.Equal(LocalRpcBrokerRefusal.AlreadySealed, rig.Session.Seal(honest));
        Assert.Equal(LocalRpcSlotState.Sealed, rig.Session.GetSnapshot().Slots[0]);
        using var buffer = (await CopyAsync(rig, Slot0, grant.Sequence)).Value!;
        Assert.Equal(LocalRpcBrokerRefusal.AlreadySealed, rig.Session.Seal(honest));
        Assert.Equal(LocalRpcSlotState.Reading, rig.Session.GetSnapshot().Slots[0]);

        // After the acknowledgement the slot is free again and the old seal is not a grant.
        Assert.True(rig.Session.Acknowledge(Slot0, grant.Sequence).IsSuccess);
        Assert.Equal(LocalRpcBrokerRefusal.NotGranted, rig.Session.Seal(honest));
    }

    [Fact]
    public async Task ASealOfAnotherSequenceIsStaleWhetherOlderOrNewer()
    {
        using var rig = BrokerRig.Create();
        var first = rig.Session.Grant(Slot0, 4096).Value!;
        var firstSeal = rig.HonestSeal(first, BrokerRig.Pattern(10));
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(firstSeal));
        using (var buffer = (await CopyAsync(rig, Slot0, first.Sequence)).Value!)
        {
            Assert.True(rig.Session.Acknowledge(Slot0, first.Sequence).IsSuccess);
        }

        var second = rig.Session.Grant(Slot0, 4096).Value!;
        Assert.Equal(2UL, second.Sequence);
        var secondSeal = rig.HonestSeal(second, BrokerRig.Pattern(10, 9));

        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, rig.Session.Seal(firstSeal));
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, rig.Session.Seal(secondSeal with { Sequence = 3 }));
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, rig.Session.Seal(secondSeal with { Sequence = 0 }));
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, rig.Session.Seal(secondSeal with { Sequence = ulong.MaxValue }));
        Assert.Equal(LocalRpcSlotState.Writing, rig.Session.GetSnapshot().Slots[0]);
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(secondSeal));
    }

    [Theory]
    [InlineData(0UL, 0UL, false)]
    [InlineData(0UL, 1UL, true)]
    [InlineData(0UL, 4096UL, true)]
    [InlineData(0UL, 4097UL, false)]
    [InlineData(4095UL, 1UL, true)]
    [InlineData(4095UL, 2UL, false)]
    [InlineData(4096UL, 1UL, false)]
    [InlineData(4096UL, 0UL, false)]
    [InlineData(100UL, 3996UL, true)]
    [InlineData(100UL, 3997UL, false)]
    [InlineData(5000UL, 1UL, false)]
    [InlineData(ulong.MaxValue, 2UL, false)]
    [InlineData(2UL, ulong.MaxValue, false)]
    [InlineData(ulong.MaxValue, ulong.MaxValue, false)]
    [InlineData(1UL, ulong.MaxValue - 1, false)]
    public void TheSealedRangeMustLieInsideTheGrantedCapacity(ulong offset, ulong length, bool fits)
    {
        using var rig = BrokerRig.Create(slotBytes: 65536);
        var grant = rig.Session.Grant(Slot0, 4096).Value!;
        var seal = new LocalRpcBufferSeal(BrokerRig.Invocation, BrokerRig.Lease, BrokerRig.GenerationValue, Slot0, grant.Sequence, offset, length, LocalRpcDigest.Compute([1]), 0);

        var refusal = rig.Session.Seal(seal);

        Assert.Equal(fits ? LocalRpcBrokerRefusal.None : LocalRpcBrokerRefusal.RangeInvalid, refusal);
        Assert.Equal(fits ? LocalRpcSlotState.Sealed : LocalRpcSlotState.Writing, rig.Session.GetSnapshot().Slots[0]);
        Assert.Equal(fits, LocalRpcBrokerSession.RangeFits(offset, length, 4096));
    }

    [Fact]
    public void TheRangeIsHeldToTheGrantedCapacityNotToTheLargerMapping()
    {
        using var rig = BrokerRig.Create(slotBytes: 65536);
        var grant = rig.Session.Grant(Slot0, 1000).Value!;
        var seal = rig.HonestSeal(grant, BrokerRig.Pattern(1000));

        Assert.Equal(LocalRpcBrokerRefusal.RangeInvalid, rig.Session.Seal(seal with { Length = 1001 }));
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(seal));
    }

    [Fact]
    public void ASealWithoutAnExpectedLayoutMustNotDeclareAStride()
    {
        using var rig = BrokerRig.Create();
        var grant = rig.Session.Grant(Slot0, 4096).Value!;
        var seal = rig.HonestSeal(grant, BrokerRig.Pattern(100));

        Assert.Equal(LocalRpcBrokerRefusal.GeometryInvalid, rig.Session.Seal(seal with { RowStride = 10 }));
        Assert.Equal(LocalRpcSlotState.Writing, rig.Session.GetSnapshot().Slots[0]);
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(seal));
    }

    [Theory]
    [InlineData(4UL, 10UL, 16UL, 57UL, false)]
    [InlineData(4UL, 10UL, 16UL, 58UL, true)]
    [InlineData(4UL, 10UL, 16UL, 64UL, true)]
    [InlineData(4UL, 10UL, 16UL, 65UL, false)]
    [InlineData(4UL, 10UL, 10UL, 40UL, true)]
    [InlineData(4UL, 10UL, 10UL, 39UL, false)]
    [InlineData(4UL, 10UL, 10UL, 41UL, false)]
    [InlineData(4UL, 10UL, 9UL, 40UL, false)]
    [InlineData(4UL, 10UL, 0UL, 40UL, false)]
    [InlineData(1UL, 10UL, 10UL, 10UL, true)]
    [InlineData(1UL, 10UL, 12UL, 10UL, true)]
    [InlineData(1UL, 10UL, 12UL, 12UL, true)]
    [InlineData(1UL, 10UL, 12UL, 13UL, false)]
    [InlineData(1UL, 10UL, 12UL, 9UL, false)]
    [InlineData(ulong.MaxValue, 2UL, ulong.MaxValue, 100UL, false)]
    [InlineData(ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, 100UL, false)]
    [InlineData(1UL << 63, 1UL, 1UL << 63, 100UL, false)]
    public void TheDeclaredStrideMustFitTheLengthAndTheExpectedRows(ulong rows, ulong rowBytes, ulong stride, ulong length, bool fits)
    {
        Assert.Equal(fits, LocalRpcBrokerSession.GeometryFits(length, stride, new LocalRpcBufferLayout(rows, rowBytes)));

        using var rig = BrokerRig.Create(slotBytes: 4096);
        var grant = rig.Session.Grant(Slot0, 4096).Value!;
        var seal = new LocalRpcBufferSeal(BrokerRig.Invocation, BrokerRig.Lease, BrokerRig.GenerationValue, Slot0, grant.Sequence, 0, length, LocalRpcDigest.Compute([1]), stride);
        var refusal = rig.Session.Seal(seal, new LocalRpcBufferLayout(rows, rowBytes));

        // A length beyond the grant fails the range check first; the geometry decides the rest.
        var expectedRefusal = length > 4096 ? LocalRpcBrokerRefusal.RangeInvalid : fits ? LocalRpcBrokerRefusal.None : LocalRpcBrokerRefusal.GeometryInvalid;
        Assert.Equal(expectedRefusal, refusal);
    }

    [Fact]
    public void ARangeFailureIsReportedBeforeAGeometryFailure()
    {
        using var rig = BrokerRig.Create();
        var grant = rig.Session.Grant(Slot0, 100).Value!;
        var seal = new LocalRpcBufferSeal(BrokerRig.Invocation, BrokerRig.Lease, BrokerRig.GenerationValue, Slot0, grant.Sequence, 90, 20, LocalRpcDigest.Compute([1]), 0);

        Assert.Equal(LocalRpcBrokerRefusal.RangeInvalid, rig.Session.Seal(seal with { RowStride = 5 }, new LocalRpcBufferLayout(2, 10)));
    }

    [Fact]
    public void AnExpectedLayoutNeedsRowsAndRowBytes()
    {
        using var rig = BrokerRig.Create();
        var grant = rig.Session.Grant(Slot0, 100).Value!;
        var seal = rig.HonestSeal(grant, BrokerRig.Pattern(10));

        Assert.Throws<ArgumentOutOfRangeException>(() => rig.Session.Seal(seal, new LocalRpcBufferLayout(0, 10)));
        Assert.Throws<ArgumentOutOfRangeException>(() => rig.Session.Seal(seal, new LocalRpcBufferLayout(1, 0)));
        Assert.Throws<ArgumentNullException>(() => rig.Session.Seal(null!));
        Assert.Throws<ArgumentNullException>(() => rig.Session.Seal(seal with { Digest = null! }));
        Assert.Equal(LocalRpcSlotState.Writing, rig.Session.GetSnapshot().Slots[0]);
    }

    [Fact]
    public void AValidGeometricSealIsAccepted()
    {
        using var rig = BrokerRig.Create();
        var grant = rig.Session.Grant(Slot0, 4096).Value!;
        var content = BrokerRig.Pattern(58);
        var seal = rig.HonestSeal(grant, content, rowStride: 16);

        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(seal, new LocalRpcBufferLayout(4, 10)));
    }

    [Fact]
    public async Task TheCopyIsMadeInBoundedChunksAtTheSealedOffsetAndEqualsTheSealedBytes()
    {
        var limits = new LocalRpcBrokerLimits { ChunkBytes = 4096 };
        using var rig = BrokerRig.Create(slotBytes: 32768, limits: limits);
        var grant = rig.Session.Grant(Slot0, 20000).Value!;
        var content = BrokerRig.Pattern(10000, 5);
        var seal = rig.HonestSeal(grant, content, offset: 100);
        var offsets = new List<long>();
        rig.Maps[0].BeforeRead = (offset, _) => offsets.Add(offset);
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(seal));

        var result = await CopyAsync(rig, Slot0, grant.Sequence);

        Assert.True(result.IsSuccess);
        using var buffer = result.Value!;
        Assert.Equal(content, buffer.Bytes.ToArray());
        Assert.Equal(10000, buffer.Length);
        Assert.Equal(Slot0, buffer.SlotId);
        Assert.Equal(grant.Sequence, buffer.Sequence);
        Assert.Equal(seal.Digest, buffer.Digest);
        Assert.Equal([4096, 4096, 1808], rig.Maps[0].ReadSizes);
        Assert.Equal([100L, 4196L, 8292L], offsets);
        var snapshot = rig.Session.GetSnapshot();
        Assert.Equal(LocalRpcSlotState.Reading, snapshot.Slots[0]);
        Assert.True(snapshot.CopyActive);
    }

    [Fact]
    public async Task TheDefaultChunkIsTwoHundredFiftySixKibAndAChunkNeverExceedsTheBound()
    {
        using var rig = BrokerRig.Create(slotBytes: 1024 * 1024);
        var (grant, _, content) = rig.GrantAndSeal(Slot0, 600_000);

        var result = await CopyAsync(rig, Slot0, grant.Sequence);

        using var buffer = result.Value!;
        Assert.Equal(content, buffer.Bytes.ToArray());
        Assert.Equal([262_144, 262_144, 75_712], rig.Maps[0].ReadSizes);
    }

    [Fact]
    public async Task ASingleByteAndAFullSlotBothCopy()
    {
        using var rig = BrokerRig.Create(slotBytes: 1024);
        var (grant, _, content) = rig.GrantAndSeal(Slot0, 1);
        using (var one = (await CopyAsync(rig, Slot0, grant.Sequence)).Value!)
        {
            Assert.Equal(content, one.Bytes.ToArray());
            Assert.Equal([1], rig.Maps[0].ReadSizes);
        }

        Assert.True(rig.Session.Acknowledge(Slot0, grant.Sequence).IsSuccess);
        var (grant2, _, content2) = rig.GrantAndSeal(Slot0, 1024);
        using var full = (await CopyAsync(rig, Slot0, grant2.Sequence)).Value!;
        Assert.Equal(content2, full.Bytes.ToArray());
    }

    [Fact]
    public async Task AFullSixtyFourMibSlotCopiesAndIsVerified()
    {
        using var rig = BrokerRig.Create(slots: 1, slotBytes: 64 * 1024 * 1024);
        var (grant, seal, content) = rig.GrantAndSeal(Slot0, 64 * 1024 * 1024);

        var result = await CopyAsync(rig, Slot0, grant.Sequence);

        Assert.True(result.IsSuccess);
        using var buffer = result.Value!;
        Assert.Equal(seal.Digest, buffer.Digest);
        Assert.True(buffer.Bytes.Span.SequenceEqual(content));
        Assert.Equal(256, rig.Maps[0].ReadSizes.Count);
    }

    [Fact]
    public async Task TheVerifiedBytesAreAPrivateCopyThatLaterWritesCannotChange()
    {
        using var rig = BrokerRig.Create();
        var (grant, _, content) = rig.GrantAndSeal(Slot0, 5000);
        using var buffer = (await CopyAsync(rig, Slot0, grant.Sequence)).Value!;

        Array.Fill(rig.Maps[0].Bytes, (byte)0xEE);

        Assert.Equal(content, buffer.Bytes.ToArray());
    }

    [Fact]
    public async Task ABufferTheHelperRewritesBeforeItIsReadIsRefusedAndEndsTheInvocation()
    {
        var limits = new LocalRpcBrokerLimits { ChunkBytes = 4096 };
        using var rig = BrokerRig.Create(slotBytes: 32768, limits: limits);
        var (grant, _, _) = rig.GrantAndSeal(Slot0, 12000);
        var reads = 0;
        rig.Maps[0].BeforeRead = (_, _) =>
        {
            // The helper changes bytes the parent has not read yet, after the first chunk.
            if (++reads == 2)
            {
                rig.Maps[0].Bytes[9000] ^= 0x55;
            }
        };

        var result = await CopyAsync(rig, Slot0, grant.Sequence);

        Assert.Equal(LocalRpcBrokerRefusal.DigestMismatch, result.Refusal);
        Assert.Null(result.Value);
        AssertEnded(rig, LocalRpcBrokerEndReason.IntegrityViolation);
        Assert.Equal([LocalRpcSlotState.Quarantined, LocalRpcSlotState.Free, LocalRpcSlotState.Free], rig.Session.GetSnapshot().Slots);
        Assert.False(rig.Session.GetSnapshot().CopyActive);
    }

    [Fact]
    public async Task AWriteToBytesAlreadyCopiedCannotReachTheVerifiedCopy()
    {
        var limits = new LocalRpcBrokerLimits { ChunkBytes = 4096 };
        using var rig = BrokerRig.Create(slotBytes: 32768, limits: limits);
        var (grant, seal, content) = rig.GrantAndSeal(Slot0, 12000);
        var reads = 0;
        rig.Maps[0].BeforeRead = (_, _) =>
        {
            // The helper rewrites the first chunk after the parent copied it: the private copy keeps the sealed bytes.
            if (++reads == 3)
            {
                Array.Fill(rig.Maps[0].Bytes, (byte)0, 0, 4096);
            }
        };

        var result = await CopyAsync(rig, Slot0, grant.Sequence);

        Assert.True(result.IsSuccess);
        using var buffer = result.Value!;
        Assert.Equal(content, buffer.Bytes.ToArray());
        Assert.Equal(seal.Digest, buffer.Digest);
    }

    [Fact]
    public async Task ASealWithTheWrongDigestIsRefusedOnTheCopy()
    {
        using var rig = BrokerRig.Create();
        var grant = rig.Session.Grant(Slot0, 4096).Value!;
        var seal = rig.HonestSeal(grant, BrokerRig.Pattern(100)) with { Digest = LocalRpcDigest.Compute([1, 2, 3]) };
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(seal));

        var result = await CopyAsync(rig, Slot0, grant.Sequence);

        Assert.Equal(LocalRpcBrokerRefusal.DigestMismatch, result.Refusal);
        AssertEnded(rig, LocalRpcBrokerEndReason.IntegrityViolation);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("long")]
    [InlineData("zero")]
    [InlineData("throws")]
    public async Task AMappingThatFailsOrFallsShortEndsTheInvocation(string failure)
    {
        var limits = new LocalRpcBrokerLimits { ChunkBytes = 4096 };
        using var rig = BrokerRig.Create(slotBytes: 32768, limits: limits);
        var (grant, _, _) = rig.GrantAndSeal(Slot0, 10000);
        var reads = 0;
        switch (failure)
        {
            case "short":
                rig.Maps[0].ReadResult = (_, count) => ++reads == 2 ? count - 1 : count;
                break;
            case "long":
                rig.Maps[0].ReadResult = (_, count) => ++reads == 2 ? count + 1 : count;
                break;
            case "zero":
                rig.Maps[0].ReadResult = (_, count) => ++reads == 3 ? 0 : count;
                break;
            default:
                rig.Maps[0].BeforeRead = (_, _) =>
                {
                    if (++reads == 2)
                    {
                        throw new IOException("The mapping is gone.");
                    }
                };
                break;
        }

        var result = await CopyAsync(rig, Slot0, grant.Sequence);

        Assert.Equal(LocalRpcBrokerRefusal.MappingFailed, result.Refusal);
        AssertEnded(rig, LocalRpcBrokerEndReason.MappingFailed);
    }

    [Fact]
    public async Task TheCallersOwnCancellationOnlyAbandonsTheAttemptAndItCanBeRetried()
    {
        var limits = new LocalRpcBrokerLimits { ChunkBytes = 4096 };
        using var rig = BrokerRig.Create(slotBytes: 32768, limits: limits);
        var (grant, _, content) = rig.GrantAndSeal(Slot0, 12000);
        using var cancel = new CancellationTokenSource();
        rig.Maps[0].BeforeRead = (_, _) =>
        {
            if (rig.Maps[0].ReadSizes.Count == 2)
            {
                cancel.Cancel();
            }
        };

        var aborted = await CopyWithAsync(rig, Slot0, grant.Sequence, cancel.Token);

        Assert.Equal(LocalRpcBrokerRefusal.Aborted, aborted.Refusal);
        Assert.Equal(2, rig.Maps[0].ReadSizes.Count);
        var snapshot = rig.Session.GetSnapshot();
        Assert.Equal(LocalRpcBrokerSessionState.Open, snapshot.State);
        Assert.Equal(LocalRpcSlotState.Sealed, snapshot.Slots[0]);
        Assert.False(snapshot.CopyActive);
        Assert.Empty(rig.Ends);

        rig.Maps[0].BeforeRead = null;
        using var retried = (await CopyAsync(rig, Slot0, grant.Sequence)).Value!;
        Assert.Equal(content, retried.Bytes.ToArray());
    }

    [Fact]
    public async Task ACallerTokenCancelledBeforeTheCopyReadsNothing()
    {
        using var rig = BrokerRig.Create();
        var (grant, _, _) = rig.GrantAndSeal(Slot0, 100);
        using var cancel = new CancellationTokenSource();
        await cancel.CancelAsync();

        var result = await CopyWithAsync(rig, Slot0, grant.Sequence, cancel.Token);

        Assert.Equal(LocalRpcBrokerRefusal.Aborted, result.Refusal);
        Assert.Empty(rig.Maps[0].ReadSizes);
        Assert.Equal(LocalRpcSlotState.Sealed, rig.Session.GetSnapshot().Slots[0]);
    }

    [Fact]
    public async Task OnlyASealedSlotOfTheCurrentSequenceCanBeCopied()
    {
        using var rig = BrokerRig.Create();
        Assert.Equal(LocalRpcBrokerRefusal.NotSealed, (await CopyAsync(rig, Slot0, 1)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, (await CopyAsync(rig, 3, 1)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, (await CopyAsync(rig, uint.MaxValue, 1)).Refusal);

        var grant = rig.Session.Grant(Slot0, 4096).Value!;
        Assert.Equal(LocalRpcBrokerRefusal.NotSealed, (await CopyAsync(rig, Slot0, grant.Sequence)).Refusal);

        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(rig.HonestSeal(grant, BrokerRig.Pattern(10))));
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, (await CopyAsync(rig, Slot0, grant.Sequence + 1)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, (await CopyAsync(rig, Slot0, 0)).Refusal);
        Assert.Empty(rig.Maps[0].ReadSizes);
        Assert.Equal(LocalRpcSlotState.Sealed, rig.Session.GetSnapshot().Slots[0]);
        Assert.False(rig.Session.GetSnapshot().CopyActive);
    }

    [Fact]
    public async Task OnlyOneCopyAndItsUndisposedBufferExistPerSession()
    {
        using var rig = BrokerRig.Create();
        var (grant0, _, _) = rig.GrantAndSeal(Slot0, 100, seed: 1);
        var (grant1, _, content1) = rig.GrantAndSeal(Slot1, 100, seed: 2);

        var first = (await CopyAsync(rig, Slot0, grant0.Sequence)).Value!;
        Assert.Equal(LocalRpcBrokerRefusal.CopyBusy, (await CopyAsync(rig, Slot0, grant0.Sequence)).Refusal);
        var other = await CopyAsync(rig, Slot1, grant1.Sequence);
        Assert.Equal(LocalRpcBrokerRefusal.CopyBusy, other.Refusal);
        Assert.Equal(LocalRpcSlotState.Sealed, rig.Session.GetSnapshot().Slots[1]);

        first.Dispose();
        Assert.False(rig.Session.GetSnapshot().CopyActive);
        using var second = (await CopyAsync(rig, Slot1, grant1.Sequence)).Value!;
        Assert.Equal(content1, second.Bytes.ToArray());
    }

    [Fact]
    public async Task ADisposedBufferIsZeroedAndUnreadableAndDisposingTwiceDoesNotFreeANewCopysBudget()
    {
        var limits = new LocalRpcBrokerLimits { ChunkBytes = 4096 };
        using var rig = BrokerRig.Create(slotBytes: 16384, limits: limits);
        var (grant0, _, _) = rig.GrantAndSeal(Slot0, 5000);
        var (grant1, _, _) = rig.GrantAndSeal(Slot1, 5000);
        var first = (await CopyAsync(rig, Slot0, grant0.Sequence)).Value!;
        Assert.True(MemoryMarshal.TryGetArray(first.Bytes, out var segment));
        Assert.Contains(segment.Array!, value => value != 0);

        first.Dispose();

        Assert.All(segment.Array!, value => Assert.Equal(0, value));
        Assert.Throws<ObjectDisposedException>(() => first.Bytes);
        Assert.Equal(5000, first.Length);

        // A second copy is now in progress; disposing the first buffer again must not release that copy's budget.
        using var started = new ManualResetEventSlim();
        using var gate = new ManualResetEventSlim();
        rig.Maps[1].BeforeRead = (_, _) =>
        {
            started.Set();
            gate.Wait(TimeSpan.FromSeconds(20));
        };
        var second = Task.Run(() => CopyAsync(rig, Slot1, grant1.Sequence).AsTask());
        Assert.True(started.Wait(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken));
        first.Dispose();
        Assert.True(rig.Session.GetSnapshot().CopyActive);
        gate.Set();
        using var buffer = (await second).Value!;
        Assert.Equal(5000, buffer.Length);
    }

    [Fact]
    public async Task AnAcknowledgementFreesTheSlotAndCarriesTheDigestOfTheVerifiedCopy()
    {
        using var rig = BrokerRig.Create();
        var (grant, seal, _) = rig.GrantAndSeal(Slot1, 100);
        using var buffer = (await CopyAsync(rig, Slot1, grant.Sequence)).Value!;

        var ack = rig.Session.Acknowledge(Slot1, grant.Sequence);

        Assert.True(ack.IsSuccess);
        Assert.Equal(new LocalRpcBufferAck(BrokerRig.Invocation, BrokerRig.Lease, BrokerRig.GenerationValue, Slot1, grant.Sequence, buffer.Digest), ack.Value);
        Assert.Equal(seal.Digest, ack.Value!.Digest);
        var snapshot = rig.Session.GetSnapshot();
        Assert.Equal(LocalRpcSlotState.Free, snapshot.Slots[1]);
        Assert.Equal(2UL, snapshot.NextSequences[1]);
        Assert.Equal(1UL, snapshot.NextSequences[0]);
        Assert.Equal(2UL, rig.Session.Grant(Slot1, 100).Value!.Sequence);
    }

    [Fact]
    public async Task ADuplicateAcknowledgementReturnsTheSameOneAndChangesNothing()
    {
        using var rig = BrokerRig.Create();
        var (grant, _, _) = rig.GrantAndSeal(Slot0, 100);
        using var buffer = (await CopyAsync(rig, Slot0, grant.Sequence)).Value!;
        var first = rig.Session.Acknowledge(Slot0, grant.Sequence).Value!;

        var duplicate = rig.Session.Acknowledge(Slot0, grant.Sequence);

        Assert.True(duplicate.IsSuccess);
        Assert.Equal(first, duplicate.Value);
        Assert.Equal(2UL, rig.Session.GetSnapshot().NextSequences[0]);
        Assert.Equal(LocalRpcSlotState.Free, rig.Session.GetSnapshot().Slots[0]);

        // Once the next grant is out, the old acknowledgement is not a duplicate of anything pending.
        var next = rig.Session.Grant(Slot0, 100).Value!;
        Assert.Equal(LocalRpcBrokerRefusal.NotSealed, rig.Session.Acknowledge(Slot0, next.Sequence).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.NotSealed, rig.Session.Acknowledge(Slot0, grant.Sequence).Refusal);
    }

    [Fact]
    public async Task OnlyTheLastAcknowledgedSequenceIsAHarmlessDuplicate()
    {
        using var rig = BrokerRig.Create();
        for (var round = 1UL; round <= 2; round++)
        {
            var (grant, _, _) = rig.GrantAndSeal(Slot0, 100, seed: (byte)round);
            using var buffer = (await CopyAsync(rig, Slot0, grant.Sequence)).Value!;
            Assert.True(rig.Session.Acknowledge(Slot0, grant.Sequence).IsSuccess);
        }

        Assert.True(rig.Session.Acknowledge(Slot0, 2).IsSuccess);
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, rig.Session.Acknowledge(Slot0, 1).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, rig.Session.Acknowledge(Slot0, 3).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, rig.Session.Acknowledge(Slot0, 0).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, rig.Session.Acknowledge(Slot1, 2).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, rig.Session.Acknowledge(3, 2).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, rig.Session.Acknowledge(7, 2).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, rig.Session.Acknowledge(uint.MaxValue, 2).Refusal);
    }

    [Fact]
    public async Task AnAcknowledgementBeforeTheCopyFinishedOrOfAnotherSequenceIsRefused()
    {
        using var rig = BrokerRig.Create();
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, rig.Session.Acknowledge(Slot0, 1).Refusal);

        var grant = rig.Session.Grant(Slot0, 4096).Value!;
        Assert.Equal(LocalRpcBrokerRefusal.NotSealed, rig.Session.Acknowledge(Slot0, grant.Sequence).Refusal);

        var seal = rig.HonestSeal(grant, BrokerRig.Pattern(100));
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(seal));
        Assert.Equal(LocalRpcBrokerRefusal.CopyPending, rig.Session.Acknowledge(Slot0, grant.Sequence).Refusal);
        Assert.Equal(LocalRpcSlotState.Sealed, rig.Session.GetSnapshot().Slots[0]);

        using var started = new ManualResetEventSlim();
        using var gate = new ManualResetEventSlim();
        rig.Maps[0].BeforeRead = (_, _) =>
        {
            started.Set();
            gate.Wait(TimeSpan.FromSeconds(20));
        };
        var copy = Task.Run(() => CopyAsync(rig, Slot0, grant.Sequence).AsTask());
        Assert.True(started.Wait(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken));
        Assert.Equal(LocalRpcBrokerRefusal.CopyPending, rig.Session.Acknowledge(Slot0, grant.Sequence).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, rig.Session.Acknowledge(Slot0, grant.Sequence + 1).Refusal);
        Assert.Equal(LocalRpcSlotState.Reading, rig.Session.GetSnapshot().Slots[0]);
        gate.Set();
        using var buffer = (await copy).Value!;

        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, rig.Session.Acknowledge(Slot0, grant.Sequence + 1).Refusal);
        Assert.Equal(LocalRpcSlotState.Reading, rig.Session.GetSnapshot().Slots[0]);
        Assert.True(rig.Session.Acknowledge(Slot0, grant.Sequence).IsSuccess);
    }

    [Fact]
    public async Task EveryRefusalIsCounted()
    {
        using var rig = BrokerRig.Create(slots: 1);
        _ = rig.Session.Grant(5, 10);
        _ = rig.Session.Grant(Slot0, 0);
        var ok = rig.Session.Grant(Slot0, 10);
        _ = rig.Session.Grant(Slot0, 10);
        _ = rig.Session.Acknowledge(Slot0, 1);
        _ = rig.Session.Seal(new LocalRpcBufferSeal(Guid.NewGuid(), BrokerRig.Lease, BrokerRig.GenerationValue, Slot0, 1, 0, 1, LocalRpcDigest.Compute([1]), 0));
        _ = await CopyAsync(rig, Slot0, 1);

        Assert.True(ok.IsSuccess);
        Assert.Equal(6, rig.Session.GetSnapshot().Refusals);
    }

    [Fact]
    public async Task AHundredThousandRefusalsStayCheapAndCounted()
    {
        using var rig = BrokerRig.Create(slots: 1);
        var timer = System.Diagnostics.Stopwatch.StartNew();
        await Task.WhenAll(Enumerable.Range(0, 4).Select(worker => Task.Run(() =>
        {
            for (var index = 0; index < 25_000; index++)
            {
                _ = rig.Session.Grant(9, 1 + (uint)worker);
            }
        })));

        Assert.Equal(100_000, rig.Session.GetSnapshot().Refusals);
        Assert.True(timer.Elapsed < TimeSpan.FromSeconds(20), "refusals took " + timer.Elapsed);
        Assert.Equal(LocalRpcSlotState.Free, rig.Session.GetSnapshot().Slots[0]);
    }

    internal static ValueTask<LocalRpcBrokerResult<LocalRpcVerifiedBuffer>> CopyAsync(BrokerRig rig, uint slot, ulong sequence) =>
        rig.Session.CopyAsync(slot, sequence, TestContext.Current.CancellationToken);

    internal static ValueTask<LocalRpcBrokerResult<LocalRpcVerifiedBuffer>> CopyWithAsync(BrokerRig rig, uint slot, ulong sequence, CancellationToken cancellationToken) =>
        rig.Session.CopyAsync(slot, sequence, cancellationToken);

    internal static void AssertEnded(BrokerRig rig, LocalRpcBrokerEndReason reason)
    {
        Assert.Equal(LocalRpcBrokerSessionState.Closed, rig.Session.State);
        Assert.Equal(reason, rig.Session.EndReason);
        var end = Assert.Single(rig.Ends);
        Assert.Equal(reason, end.Reason);
        Assert.Equal(BrokerRig.Invocation, end.InvocationId);
        Assert.Equal(0, rig.Registry.OpenSessions);
        Assert.All(rig.Maps, map => Assert.Equal(1, map.Disposals));
    }
}
