#pragma warning disable CA2000 // Test mappings are handed to the session or helper under test, which owns and disposes them.
// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>The helper's side: it fills only what the parent granted, seals exactly that grant and reuses a slot only after the matching acknowledgement.</summary>
// One collection with the other heavy LocalRpc tests: the real-clock, 64 MiB and many-thread cases must not load the machine beside timing-sensitive tests.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcBrokerChildTests
{
    private const uint Slot0 = 0;
    private const uint Slot1 = 1;
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    private static LocalRpcBrokerChild NewChild(params long[] capacities) =>
        new(BrokerRig.Invocation, BrokerRig.Lease, BrokerRig.GenerationValue, capacities.Length == 0 ? [4096, 4096, 4096] : capacities);

    [Fact]
    public void TheHelperNeedsAnInvocationALeaseAGenerationAndOneToThreeSlotsOfBoundedSize()
    {
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcBrokerChild(Guid.Empty, BrokerRig.Lease, 1, [10]));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcBrokerChild(BrokerRig.Invocation, Guid.Empty, 1, [10]));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcBrokerChild(BrokerRig.Invocation, BrokerRig.Lease, 0, [10]));
        _ = Assert.Throws<ArgumentNullException>(() => new LocalRpcBrokerChild(BrokerRig.Invocation, BrokerRig.Lease, 1, null!));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcBrokerChild(BrokerRig.Invocation, BrokerRig.Lease, 1, []));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcBrokerChild(BrokerRig.Invocation, BrokerRig.Lease, 1, [10, 10, 10, 10]));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcBrokerChild(BrokerRig.Invocation, BrokerRig.Lease, 1, [0]));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcBrokerChild(BrokerRig.Invocation, BrokerRig.Lease, 1, [-5]));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcBrokerChild(BrokerRig.Invocation, BrokerRig.Lease, 1, [10, LocalRpcBrokerLimits.MaxSlotBytes + 1]));

        using var smallest = new LocalRpcBrokerChild(BrokerRig.Invocation, BrokerRig.Lease, 1, [1]);
        using var biggest = new LocalRpcBrokerChild(BrokerRig.Invocation, BrokerRig.Lease, ulong.MaxValue, [LocalRpcBrokerLimits.MaxSlotBytes, 1, 1]);
        Assert.Equal(BrokerRig.Invocation, biggest.InvocationId);
        Assert.Equal(BrokerRig.Lease, biggest.LeaseId);
        Assert.Equal(ulong.MaxValue, biggest.Generation);
        Assert.Equal([LocalRpcSlotState.Free], smallest.SlotStates);
    }

    [Fact]
    public void AGrantFromTheParentMakesTheSlotWritable()
    {
        using var child = NewChild();
        var grant = new LocalRpcSlotGrant(Slot1, 1, 4096);

        var result = child.Accept(grant);

        Assert.True(result.IsSuccess);
        Assert.Equal(grant, result.Value);
        Assert.Equal([LocalRpcSlotState.Free, LocalRpcSlotState.Writing, LocalRpcSlotState.Free], child.SlotStates);
    }

    [Fact]
    public void ARepeatedGrantIsHarmlessButAnotherOneForABusySlotIsNot()
    {
        using var child = NewChild();
        var grant = new LocalRpcSlotGrant(Slot0, 1, 4096);
        _ = child.Accept(grant);

        Assert.True(child.Accept(new LocalRpcSlotGrant(Slot0, 1, 4096)).IsSuccess);
        Assert.Equal(LocalRpcBrokerRefusal.SlotBusy, child.Accept(new LocalRpcSlotGrant(Slot0, 1, 2048)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.SlotBusy, child.Accept(new LocalRpcSlotGrant(Slot0, 2, 4096)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.SlotBusy, child.Accept(new LocalRpcSlotGrant(Slot0, 0, 4096)).Refusal);
        Assert.Equal([LocalRpcSlotState.Writing, LocalRpcSlotState.Free, LocalRpcSlotState.Free], child.SlotStates);

        // A sealed slot is not writable either, and an identical grant is no longer "the same grant".
        Assert.True(child.Seal(Slot0, 1, 0, new byte[10]).IsSuccess);
        Assert.Equal(LocalRpcBrokerRefusal.SlotBusy, child.Accept(grant).Refusal);
    }

    [Fact]
    public void AGrantForASlotTheHelperDoesNotHaveIsRefused()
    {
        using var child = NewChild(4096, 4096);

        foreach (var slot in new[] { 2U, 3U, uint.MaxValue })
        {
            Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, child.Accept(new LocalRpcSlotGrant(slot, 1, 10)).Refusal);
        }

        Assert.Equal([LocalRpcSlotState.Free, LocalRpcSlotState.Free], child.SlotStates);
    }

    [Fact]
    public void ASequenceMustBePositiveAndHigherThanEveryGrantAcceptedForTheSlot()
    {
        using var child = NewChild();
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Accept(new LocalRpcSlotGrant(Slot0, 0, 10)).Refusal);
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 3, 4096));
        _ = child.Seal(Slot0, 3, 0, new byte[10]);
        var seal = child.Seal(Slot1, 1, 0, new byte[1]);
        Assert.Equal(LocalRpcBrokerRefusal.NotGranted, seal.Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.None, child.Acknowledge(Ack(child, Slot0, 3, new byte[10])));

        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Accept(new LocalRpcSlotGrant(Slot0, 3, 10)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Accept(new LocalRpcSlotGrant(Slot0, 2, 10)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Accept(new LocalRpcSlotGrant(Slot0, 1, 10)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Accept(new LocalRpcSlotGrant(Slot0, 0, 10)).Refusal);
        Assert.Equal(LocalRpcSlotState.Free, child.SlotStates[0]);

        // Slots count their sequences on their own, and a later sequence is fine.
        Assert.True(child.Accept(new LocalRpcSlotGrant(Slot1, 1, 10)).IsSuccess);
        Assert.True(child.Accept(new LocalRpcSlotGrant(Slot0, 4, 10)).IsSuccess);
    }

    [Fact]
    public void TheCapacityIsPositiveAndWithinTheSlotsMapping()
    {
        using var child = NewChild();

        Assert.Equal(LocalRpcBrokerRefusal.CapacityExceeded, child.Accept(new LocalRpcSlotGrant(Slot0, 1, 0)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.CapacityExceeded, child.Accept(new LocalRpcSlotGrant(Slot0, 1, 4097)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.CapacityExceeded, child.Accept(new LocalRpcSlotGrant(Slot0, 1, ulong.MaxValue)).Refusal);
        Assert.Equal(LocalRpcSlotState.Free, child.SlotStates[0]);
        Assert.True(child.Accept(new LocalRpcSlotGrant(Slot0, 1, 4096)).IsSuccess);
        Assert.True(child.Accept(new LocalRpcSlotGrant(Slot1, 1, 1)).IsSuccess);

        // The stale check comes before the capacity check.
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Accept(new LocalRpcSlotGrant(2, 0, 0)).Refusal);
    }

    [Fact]
    public void SealingReturnsTheDigestOfExactlyTheBytesWrittenAndSealsTheSlot()
    {
        using var child = NewChild();
        _ = child.Accept(new LocalRpcSlotGrant(Slot1, 1, 4096));
        var written = BrokerRig.Pattern(300);

        var result = child.Seal(Slot1, 1, 100, written, rowStride: 40);

        Assert.True(result.IsSuccess);
        Assert.Equal(new LocalRpcBufferSeal(BrokerRig.Invocation, BrokerRig.Lease, BrokerRig.GenerationValue, Slot1, 1, 100, 300, LocalRpcDigest.Compute(written), 40), result.Value);
        Assert.Equal([LocalRpcSlotState.Free, LocalRpcSlotState.Sealed, LocalRpcSlotState.Free], child.SlotStates);
    }

    [Fact]
    public void ASealIsRefusedUnlessTheGrantIsOutstandingAndCurrent()
    {
        using var child = NewChild();
        var written = new byte[10];
        Assert.Equal(LocalRpcBrokerRefusal.NotGranted, child.Seal(Slot0, 1, 0, written).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, child.Seal(3, 1, 0, written).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, child.Seal(uint.MaxValue, 1, 0, written).Refusal);

        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 5, 4096));
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Seal(Slot0, 4, 0, written).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Seal(Slot0, 6, 0, written).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Seal(Slot0, 0, 0, written).Refusal);
        Assert.Equal(LocalRpcSlotState.Writing, child.SlotStates[0]);

        Assert.True(child.Seal(Slot0, 5, 0, written).IsSuccess);
        Assert.Equal(LocalRpcBrokerRefusal.AlreadySealed, child.Seal(Slot0, 5, 0, written).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.AlreadySealed, child.Seal(Slot0, 4, 0, written).Refusal);
    }

    [Theory]
    [InlineData(0UL, 0, false)]
    [InlineData(0UL, 1, true)]
    [InlineData(0UL, 4096, true)]
    [InlineData(0UL, 4097, false)]
    [InlineData(4095UL, 1, true)]
    [InlineData(4095UL, 2, false)]
    [InlineData(4096UL, 1, false)]
    [InlineData(100UL, 3996, true)]
    [InlineData(100UL, 3997, false)]
    [InlineData(ulong.MaxValue, 2, false)]
    [InlineData(ulong.MaxValue, 1, false)]
    public void TheHelperMayWriteOnlyInsideTheGrantedCapacity(ulong offset, int length, bool fits)
    {
        using var child = NewChild(65536);
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 1, 4096));

        var result = child.Seal(Slot0, 1, offset, new byte[length]);

        Assert.Equal(fits ? LocalRpcBrokerRefusal.None : LocalRpcBrokerRefusal.RangeInvalid, result.Refusal);
        Assert.Equal(fits ? LocalRpcSlotState.Sealed : LocalRpcSlotState.Writing, child.SlotStates[0]);
    }

    [Fact]
    public async Task ACancellationNeverWaitsForTheDigestAndAnInFlightSealIsRefused()
    {
        using var child = NewChild();
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 1, 4096));
        using var started = new ManualResetEventSlim();
        using var gate = new ManualResetEventSlim();
        child.BeforeDigest = () =>
        {
            started.Set();
            _ = gate.Wait(Patience);
        };
        var seal = Task.Run(() => child.Seal(Slot0, 1, 0, new byte[100]));
        Assert.True(started.Wait(Patience, TestContext.Current.CancellationToken));

        var cancel = Task.Run(child.Cancel, TestContext.Current.CancellationToken);
        var finished = await Task.WhenAny(cancel, Task.Delay(Patience, TestContext.Current.CancellationToken));
        gate.Set();

        Assert.Same(cancel, finished);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, (await seal).Refusal);
        Assert.Equal(LocalRpcSlotState.Quarantined, child.SlotStates[0]);
    }

    [Fact]
    public void ARefusedSealChangesNothing()
    {
        using var child = NewChild();
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 1, 100));

        Assert.Equal(LocalRpcBrokerRefusal.RangeInvalid, child.Seal(Slot0, 1, 0, new byte[101]).Refusal);

        Assert.Equal(LocalRpcSlotState.Writing, child.SlotStates[0]);
        Assert.True(child.Seal(Slot0, 1, 0, new byte[100]).IsSuccess);
    }

    [Fact]
    public void TheMatchingAcknowledgementFreesTheSlotForTheNextGrant()
    {
        using var child = NewChild();
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 1, 4096));
        var written = BrokerRig.Pattern(50);
        _ = child.Seal(Slot0, 1, 0, written);

        Assert.Equal(LocalRpcBrokerRefusal.None, child.Acknowledge(Ack(child, Slot0, 1, written)));

        Assert.Equal(LocalRpcSlotState.Free, child.SlotStates[0]);
        Assert.True(child.Accept(new LocalRpcSlotGrant(Slot0, 2, 4096)).IsSuccess);
    }

    [Theory]
    [InlineData("invocation")]
    [InlineData("lease")]
    [InlineData("generation")]
    public void AnAcknowledgementOfAnotherSessionIsAWrongResourceGrant(string which)
    {
        using var child = NewChild();
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 1, 4096));
        var written = BrokerRig.Pattern(50);
        _ = child.Seal(Slot0, 1, 0, written);
        var honest = Ack(child, Slot0, 1, written);
        var forged = which switch
        {
            "invocation" => honest with { InvocationId = Guid.NewGuid() },
            "lease" => honest with { LeaseId = Guid.NewGuid() },
            _ => honest with { Generation = honest.Generation + 1 },
        };

        Assert.Equal(LocalRpcBrokerRefusal.WrongSession, child.Acknowledge(forged));

        Assert.Equal(LocalRpcSlotState.Sealed, child.SlotStates[0]);
        Assert.Equal(LocalRpcBrokerRefusal.None, child.Acknowledge(honest));
    }

    [Fact]
    public void AStaleOrMismatchedAcknowledgementIsRefusedAndTheSlotStaysSealed()
    {
        using var child = NewChild();
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 4, 4096));
        var written = BrokerRig.Pattern(50);
        _ = child.Seal(Slot0, 4, 0, written);
        var honest = Ack(child, Slot0, 4, written);

        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Acknowledge(honest with { Sequence = 3 }));
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Acknowledge(honest with { Sequence = 5 }));
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Acknowledge(honest with { Sequence = 0 }));
        Assert.Equal(LocalRpcBrokerRefusal.DigestMismatch, child.Acknowledge(honest with { Digest = LocalRpcDigest.Compute([1]) }));
        var flipped = (byte[])honest.Digest.AsSpan().ToArray().Clone();
        flipped[^1] ^= 1;
        Assert.Equal(LocalRpcBrokerRefusal.DigestMismatch, child.Acknowledge(honest with { Digest = LocalRpcDigest.FromBytes(flipped) }));
        Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, child.Acknowledge(honest with { SlotId = 3 }));
        Assert.Equal(LocalRpcBrokerRefusal.UnknownSlot, child.Acknowledge(honest with { SlotId = uint.MaxValue }));
        Assert.Equal(LocalRpcSlotState.Sealed, child.SlotStates[0]);
        Assert.Equal(LocalRpcBrokerRefusal.None, child.Acknowledge(honest));
    }

    [Fact]
    public void ADuplicateIdenticalAcknowledgementIsHarmlessAndAnyOtherOneAfterwardsIsNot()
    {
        using var child = NewChild();
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 1, 4096));
        var written = BrokerRig.Pattern(50);
        _ = child.Seal(Slot0, 1, 0, written);
        var honest = Ack(child, Slot0, 1, written);
        Assert.Equal(LocalRpcBrokerRefusal.None, child.Acknowledge(honest));

        Assert.Equal(LocalRpcBrokerRefusal.None, child.Acknowledge(honest));
        Assert.Equal(LocalRpcSlotState.Free, child.SlotStates[0]);
        Assert.Equal(LocalRpcBrokerRefusal.DigestMismatch, child.Acknowledge(honest with { Digest = LocalRpcDigest.Compute([9]) }));
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Acknowledge(honest with { Sequence = 2 }));
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Acknowledge(honest with { Sequence = 0 }));

        // A slot that never had an acknowledgement has no duplicate to be harmless about.
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Acknowledge(honest with { SlotId = Slot1, Sequence = 0 }));
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Acknowledge(honest with { SlotId = Slot1 }));

        // After a second round only the latest acknowledgement is a duplicate.
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 2, 4096));
        _ = child.Seal(Slot0, 2, 0, written);
        Assert.Equal(LocalRpcBrokerRefusal.None, child.Acknowledge(honest with { Sequence = 2 }));
        Assert.Equal(LocalRpcBrokerRefusal.StaleSequence, child.Acknowledge(honest));
    }

    [Fact]
    public void AnAcknowledgementForAWritingSlotIsRefusedAsNotSealed()
    {
        using var child = NewChild();
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 1, 4096));

        Assert.Equal(LocalRpcBrokerRefusal.NotSealed, child.Acknowledge(Ack(child, Slot0, 1, new byte[1])));
        Assert.Equal(LocalRpcSlotState.Writing, child.SlotStates[0]);
    }

    [Fact]
    public void NullGrantSealAndAcknowledgementArgumentsAreRejected()
    {
        using var child = NewChild();

        _ = Assert.Throws<ArgumentNullException>(() => child.Accept(null!));
        _ = Assert.Throws<ArgumentNullException>(() => child.Acknowledge(null!));
        _ = Assert.Throws<ArgumentNullException>(() => child.Acknowledge(new LocalRpcBufferAck(BrokerRig.Invocation, BrokerRig.Lease, BrokerRig.GenerationValue, 0, 1, null!)));
    }

    [Fact]
    public void CancellingWithdrawsEverySlotInUseCancelsTheTokenAndRefusesEverythingAfterIt()
    {
        using var child = NewChild();
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 1, 4096));
        _ = child.Accept(new LocalRpcSlotGrant(Slot1, 1, 4096));
        _ = child.Seal(Slot1, 1, 0, new byte[10]);
        var reachedFromAnotherThread = false;
        using var registration = child.Cancelled.Register(() => reachedFromAnotherThread = Task.Run(() => child.SlotStates).Wait(Patience));
        Assert.False(child.Cancelled.IsCancellationRequested);

        child.Cancel();
        child.Cancel();

        Assert.True(child.Cancelled.IsCancellationRequested);
        Assert.True(reachedFromAnotherThread);
        Assert.Equal([LocalRpcSlotState.Quarantined, LocalRpcSlotState.Quarantined, LocalRpcSlotState.Free], child.SlotStates);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, child.Accept(new LocalRpcSlotGrant(2, 1, 10)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, child.Seal(Slot0, 1, 0, new byte[1]).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, child.Acknowledge(Ack(child, Slot1, 1, new byte[10])));
    }

    [Fact]
    public void DisposingCancels()
    {
        var child = NewChild();
        _ = child.Accept(new LocalRpcSlotGrant(Slot0, 1, 10));
        var token = child.Cancelled;

        child.Dispose();

        Assert.True(token.IsCancellationRequested);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, child.Accept(new LocalRpcSlotGrant(Slot1, 1, 10)).Refusal);

        // Cancelling or disposing again after the source is gone is harmless.
        child.Cancel();
        child.Dispose();
    }

    [Fact]
    public async Task AnInputWithTheParentMintedLengthAndDigestIsAccepted()
    {
        var content = BrokerRig.Pattern(10_000, 3);
        var map = new MemoryMapping(10_000);
        content.CopyTo(map.Bytes, 0);
        var offsets = new List<long>();
        map.BeforeRead = (offset, _) => offsets.Add(offset);

        var refusal = await LocalRpcBrokerChild.VerifyInputAsync(map, 10_000, LocalRpcDigest.Compute(content), 4096, TestContext.Current.CancellationToken);

        Assert.Equal(LocalRpcBrokerRefusal.None, refusal);
        Assert.Equal([4096, 4096, 1808], map.ReadSizes);
        Assert.Equal([0L, 4096L, 8192L], offsets);
        Assert.Equal(0, map.Disposals);
    }

    [Fact]
    public async Task ALargeInputIsReadInBoundedChunksAcrossYields()
    {
        var content = BrokerRig.Pattern(9 * 1024 * 1024, 3);
        var map = new MemoryMapping(content.Length);
        content.CopyTo(map.Bytes, 0);

        var refusal = await LocalRpcBrokerChild.VerifyInputAsync(map, (ulong)content.Length, LocalRpcDigest.Compute(content), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(LocalRpcBrokerRefusal.None, refusal);
        Assert.Equal(36, map.ReadSizes.Count);
        Assert.All(map.ReadSizes, size => Assert.Equal(256 * 1024, size));
    }

    [Theory]
    [InlineData(9_999UL)]
    [InlineData(10_001UL)]
    [InlineData(0UL)]
    [InlineData(ulong.MaxValue)]
    [InlineData((ulong)long.MaxValue + 1)]
    public async Task AnInputOfAnotherLengthIsRefusedBeforeAnythingIsRead(ulong declared)
    {
        var content = BrokerRig.Pattern(10_000);
        var map = new MemoryMapping(10_000);
        content.CopyTo(map.Bytes, 0);

        var refusal = await LocalRpcBrokerChild.VerifyInputAsync(map, declared, LocalRpcDigest.Compute(content), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(LocalRpcBrokerRefusal.InputMismatch, refusal);
        Assert.Empty(map.ReadSizes);
    }

    [Fact]
    public async Task AnEmptyInputIsRefusedEvenWhenItsDigestMatches()
    {
        var map = new MemoryMapping(0);

        var refusal = await LocalRpcBrokerChild.VerifyInputAsync(map, 0, LocalRpcDigest.Compute([]), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(LocalRpcBrokerRefusal.InputMismatch, refusal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4095)]
    [InlineData(9_999)]
    public async Task AnInputWithAnyOtherByteIsRefused(int position)
    {
        var content = BrokerRig.Pattern(10_000);
        var digest = LocalRpcDigest.Compute(content);
        var map = new MemoryMapping(10_000);
        content.CopyTo(map.Bytes, 0);
        map.Bytes[position] ^= 1;

        var refusal = await LocalRpcBrokerChild.VerifyInputAsync(map, 10_000, digest, 4096, TestContext.Current.CancellationToken);

        Assert.Equal(LocalRpcBrokerRefusal.InputMismatch, refusal);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("long")]
    [InlineData("throws")]
    public async Task AnInputMappingThatFailsIsRefused(string failure)
    {
        var content = BrokerRig.Pattern(10_000);
        var map = new MemoryMapping(10_000);
        content.CopyTo(map.Bytes, 0);
        var reads = 0;
        if (failure == "throws")
        {
            map.BeforeRead = (_, _) =>
            {
                if (++reads == 2)
                {
                    throw new IOException("The mapping is gone.");
                }
            };
        }
        else
        {
            map.ReadResult = (_, count) => ++reads == 2 ? (failure == "short" ? count - 1 : count + 1) : count;
        }

        var refusal = await LocalRpcBrokerChild.VerifyInputAsync(map, 10_000, LocalRpcDigest.Compute(content), 4096, TestContext.Current.CancellationToken);

        Assert.Equal(LocalRpcBrokerRefusal.MappingFailed, refusal);
        Assert.Equal(2, map.ReadSizes.Count);
    }

    [Fact]
    public async Task CancellingTheInputCheckStopsItWithinOneChunk()
    {
        var content = BrokerRig.Pattern(100_000);
        var map = new MemoryMapping(100_000);
        content.CopyTo(map.Bytes, 0);
        using var cancel = new CancellationTokenSource();
        map.BeforeRead = (_, _) =>
        {
            if (map.ReadSizes.Count == 2)
            {
                cancel.Cancel();
            }
        };

        var refusal = await LocalRpcBrokerChild.VerifyInputAsync(map, 100_000, LocalRpcDigest.Compute(content), 4096, cancel.Token);

        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, refusal);
        Assert.Equal(2, map.ReadSizes.Count);

        using var already = new CancellationTokenSource();
        await already.CancelAsync();
        var fresh = new MemoryMapping(100_000);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, await LocalRpcBrokerChild.VerifyInputAsync(fresh, 100_000, LocalRpcDigest.Compute(content), 4096, already.Token));
        Assert.Empty(fresh.ReadSizes);
    }

    [Fact]
    public async Task TheInputCheckValidatesItsArgumentsAndTheChunkBounds()
    {
        var map = new MemoryMapping(10);
        var digest = LocalRpcDigest.Compute(new byte[10]);
        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await LocalRpcBrokerChild.VerifyInputAsync(null!, 10, digest, cancellationToken: TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await LocalRpcBrokerChild.VerifyInputAsync(map, 10, null!, cancellationToken: TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await LocalRpcBrokerChild.VerifyInputAsync(map, 10, digest, 4095, cancellationToken: TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await LocalRpcBrokerChild.VerifyInputAsync(map, 10, digest, (4 * 1024 * 1024) + 1, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(LocalRpcBrokerRefusal.None, await LocalRpcBrokerChild.VerifyInputAsync(map, 10, digest, 4096, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(LocalRpcBrokerRefusal.None, await LocalRpcBrokerChild.VerifyInputAsync(map, 10, digest, 4 * 1024 * 1024, cancellationToken: TestContext.Current.CancellationToken));
    }

    private static LocalRpcBufferAck Ack(LocalRpcBrokerChild child, uint slot, ulong sequence, byte[] written) =>
        new(child.InvocationId, child.LeaseId, child.Generation, slot, sequence, LocalRpcDigest.Compute(written));
}
