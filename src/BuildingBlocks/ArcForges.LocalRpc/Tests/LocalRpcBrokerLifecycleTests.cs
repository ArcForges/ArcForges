#pragma warning disable CA2000 // Test mappings are handed to the session under test, which owns and disposes them.
#pragma warning disable CA5394 // The stress test's random choices are test data, seeded for repeatability.
// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Everything that ends or withdraws a transfer: the registry bounds, the session lease and its renewal, cancellation and
/// its grace period, closing, the pair going away, and the cleanup of mappings and private copies that none of them may skip.
/// </summary>
// One collection with the other heavy LocalRpc tests: the real-clock, 64 MiB and many-thread cases must not load the machine beside timing-sensitive tests.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcBrokerLifecycleTests
{
    private const uint Slot0 = 0;
    private const uint Slot1 = 1;
    private const uint Slot2 = 2;
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    [Fact]
    public void MalformedOptionsAreRefusedAndTheMappingsStayWithTheCaller()
    {
        using var registry = new LocalRpcBrokerRegistry(null, new ManualTimeProvider());
        var good = () => new MemoryMapping(4096);
        var oversized = new MemoryMapping(16) { ReportedLength = LocalRpcBrokerLimits.MaxSlotBytes + 1 };
        var empty = new MemoryMapping(16) { ReportedLength = 0 };
        var shared = new MemoryMapping(4096);
        var variants = new Dictionary<string, LocalRpcBrokerSessionOptions>
        {
            ["no invocation"] = new() { InvocationId = Guid.Empty, LeaseId = BrokerRig.Lease, Generation = 1, Slots = [good()] },
            ["no lease"] = new() { InvocationId = BrokerRig.Invocation, LeaseId = Guid.Empty, Generation = 1, Slots = [good()] },
            ["no generation"] = new() { InvocationId = BrokerRig.Invocation, LeaseId = BrokerRig.Lease, Generation = 0, Slots = [good()] },
            ["no slots"] = new() { InvocationId = BrokerRig.Invocation, LeaseId = BrokerRig.Lease, Generation = 1, Slots = [] },
            ["null slots"] = new() { InvocationId = BrokerRig.Invocation, LeaseId = BrokerRig.Lease, Generation = 1, Slots = null! },
            ["four slots"] = new() { InvocationId = BrokerRig.Invocation, LeaseId = BrokerRig.Lease, Generation = 1, Slots = [good(), good(), good(), good()] },
            ["null mapping"] = new() { InvocationId = BrokerRig.Invocation, LeaseId = BrokerRig.Lease, Generation = 1, Slots = [good(), null!] },
            ["empty mapping"] = new() { InvocationId = BrokerRig.Invocation, LeaseId = BrokerRig.Lease, Generation = 1, Slots = [empty] },
            ["oversized mapping"] = new() { InvocationId = BrokerRig.Invocation, LeaseId = BrokerRig.Lease, Generation = 1, Slots = [oversized] },
            ["shared mapping"] = new() { InvocationId = BrokerRig.Invocation, LeaseId = BrokerRig.Lease, Generation = 1, Slots = [good(), shared, shared] },
        };

        foreach (var (name, options) in variants)
        {
            _ = Assert.ThrowsAny<ArgumentException>(() => registry.CreateSession(options));
            Assert.True(options.Slots is null || options.Slots.OfType<MemoryMapping>().All(map => map.Disposals == 0), name);
        }

        _ = Assert.Throws<ArgumentNullException>(() => registry.CreateSession(null!));
        Assert.Equal(0, registry.OpenSessions);
    }

    [Fact]
    public void OneToThreeSlotsOfOneByteThroughSixtyFourMibAreAccepted()
    {
        using var registry = new LocalRpcBrokerRegistry(null, new ManualTimeProvider());
        var tiny = new MemoryMapping(1);
        var biggest = new MemoryMapping(16) { ReportedLength = LocalRpcBrokerLimits.MaxSlotBytes };
        var third = new MemoryMapping(4096);

        var result = registry.CreateSession(new LocalRpcBrokerSessionOptions
        {
            InvocationId = BrokerRig.Invocation,
            LeaseId = BrokerRig.Lease,
            Generation = 1,
            Slots = [tiny, biggest, third],
        });

        Assert.True(result.IsSuccess);
        Assert.Equal(3, result.Value!.GetSnapshot().Slots.Count);
        Assert.Equal(1UL, result.Value.Grant(Slot0, 1).Value!.Capacity);
        Assert.Equal(1UL, result.Value.Generation);
        Assert.Equal(BrokerRig.Invocation, result.Value.InvocationId);
        Assert.Equal(BrokerRig.Lease, result.Value.LeaseId);
        Assert.Equal((ulong)LocalRpcBrokerLimits.MaxSlotBytes, result.Value.Grant(Slot1, (ulong)LocalRpcBrokerLimits.MaxSlotBytes).Value!.Capacity);
        Assert.Equal(LocalRpcBrokerRefusal.CapacityExceeded, result.Value.Grant(Slot2, 4097).Refusal);
    }

    [Fact]
    public void TheRegistryAdmitsOnlyItsLimitOfSessionsAndOnlyOnePerInvocation()
    {
        var limits = new LocalRpcBrokerLimits { MaxSessions = 2 };
        using var registry = new LocalRpcBrokerRegistry(limits, new ManualTimeProvider());
        LocalRpcBrokerResult<LocalRpcBrokerSession> Open(Guid invocation, MemoryMapping map) =>
            registry.CreateSession(new LocalRpcBrokerSessionOptions { InvocationId = invocation, LeaseId = BrokerRig.Lease, Generation = 1, Slots = [map] });
        var one = Guid.NewGuid();
        var two = Guid.NewGuid();
        var three = Guid.NewGuid();
        var firstMap = new MemoryMapping(64);
        var first = Open(one, firstMap).Value!;
        Assert.True(Open(two, new MemoryMapping(64)).IsSuccess);

        var refusedMap = new MemoryMapping(64);
        Assert.Equal(LocalRpcBrokerRefusal.TooManySessions, Open(three, refusedMap).Refusal);
        var duplicateMap = new MemoryMapping(64);
        Assert.Equal(LocalRpcBrokerRefusal.DuplicateInvocation, Open(one, duplicateMap).Refusal);
        Assert.Equal(0, refusedMap.Disposals);
        Assert.Equal(0, duplicateMap.Disposals);
        Assert.Equal(2, registry.OpenSessions);

        first.Close();
        Assert.Equal(1, registry.OpenSessions);
        Assert.Equal(1, firstMap.Disposals);
        Assert.True(Open(three, refusedMap).IsSuccess);
        Assert.Equal(LocalRpcBrokerRefusal.TooManySessions, Open(one, new MemoryMapping(64)).Refusal);
        Assert.Equal(2, registry.OpenSessions);
    }

    [Fact]
    public async Task ManyThreadsCreatingSessionsNeverExceedTheBound()
    {
        var limits = new LocalRpcBrokerLimits { MaxSessions = 8 };
        using var registry = new LocalRpcBrokerRegistry(limits);
        using var barrier = new Barrier(32);
        // Each caller blocks at the barrier, so each needs a thread of its own: a small hosted runner's pool would never release 32.
        var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Factory.StartNew(
            () =>
            {
                Assert.True(barrier.SignalAndWait(Patience, TestContext.Current.CancellationToken));
                return registry.CreateSession(new LocalRpcBrokerSessionOptions { InvocationId = Guid.NewGuid(), LeaseId = BrokerRig.Lease, Generation = 1, Slots = [new MemoryMapping(64)] });
            },
            TestContext.Current.CancellationToken,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default)));

        Assert.Equal(8, results.Count(result => result.IsSuccess));
        Assert.Equal(24, results.Count(result => result.Refusal == LocalRpcBrokerRefusal.TooManySessions));
        Assert.Equal(8, registry.OpenSessions);
    }

    [Fact]
    public void AnInvocationWhosePairIsAlreadyGoneGetsNoSession()
    {
        using var registry = new LocalRpcBrokerRegistry(null, new ManualTimeProvider());
        using var gone = new CancellationTokenSource();
        gone.Cancel();
        var map = new MemoryMapping(64);

        var result = registry.CreateSession(new LocalRpcBrokerSessionOptions { InvocationId = Guid.NewGuid(), LeaseId = BrokerRig.Lease, Generation = 1, Slots = [map], PairGone = gone.Token });

        Assert.Equal(LocalRpcBrokerRefusal.PairGone, result.Refusal);
        Assert.Equal(0, registry.OpenSessions);
        Assert.Equal(0, map.Disposals);
    }

    [Fact]
    public void DisposingTheRegistryClosesEverySessionAndRefusesNewOnes()
    {
        var ends = new List<LocalRpcBrokerEnd>();
        var registry = new LocalRpcBrokerRegistry(null, new ManualTimeProvider());
        var maps = new[] { new MemoryMapping(64), new MemoryMapping(64) };
        var sessions = maps.Select(map => registry.CreateSession(new LocalRpcBrokerSessionOptions
        {
            InvocationId = Guid.NewGuid(),
            LeaseId = BrokerRig.Lease,
            Generation = 1,
            Slots = [map],
            Ended = end =>
            {
                lock (ends)
                {
                    ends.Add(end);
                }
            },
        }).Value!).ToArray();

        registry.Dispose();
        registry.Dispose();

        Assert.Equal(0, registry.OpenSessions);
        Assert.All(maps, map => Assert.Equal(1, map.Disposals));
        Assert.Equal(2, ends.Count);
        Assert.All(ends, end => Assert.Equal(LocalRpcBrokerEndReason.RegistryDisposed, end.Reason));
        Assert.All(sessions, session => Assert.Equal(LocalRpcBrokerSessionState.Closed, session.State));
        Assert.Equal(LocalRpcBrokerRefusal.Closed, registry.CreateSession(new LocalRpcBrokerSessionOptions { InvocationId = Guid.NewGuid(), LeaseId = BrokerRig.Lease, Generation = 1, Slots = [new MemoryMapping(64)] }).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Closed, sessions[0].Grant(Slot0, 1).Refusal);
    }

    [Fact]
    public void TheLeaseRunsOutAtThirtySecondsAndTheSessionClosesByItself()
    {
        using var rig = BrokerRig.Create();

        rig.Time!.Advance(TimeSpan.FromMilliseconds(29_999));
        Assert.Equal(LocalRpcBrokerSessionState.Open, rig.Session.State);
        Assert.Empty(rig.Ends);

        rig.Time.Advance(TimeSpan.FromMilliseconds(1));

        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.Expired);
        Assert.Equal(LocalRpcBrokerRefusal.Expired, rig.Session.Grant(Slot0, 1).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Expired, rig.Session.Renew());
        Assert.Equal(LocalRpcBrokerRefusal.Expired, rig.Session.Acknowledge(Slot0, 1).Refusal);
        Assert.Equal(0, rig.Time.ArmedTimers);
    }

    [Fact]
    public void TheLeaseLengthIsTheConfiguredLimit()
    {
        using var rig = BrokerRig.Create(limits: new LocalRpcBrokerLimits { SessionLease = TimeSpan.FromSeconds(10) });

        rig.Time!.Advance(TimeSpan.FromMilliseconds(9_999));
        Assert.Equal(LocalRpcBrokerSessionState.Open, rig.Session.State);
        rig.Time.Advance(TimeSpan.FromMilliseconds(1));

        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.Expired);
    }

    [Fact]
    public void RenewalGivesAFullLeaseFromNowAndNeverMore()
    {
        using var rig = BrokerRig.Create();
        rig.Time!.Advance(TimeSpan.FromSeconds(20));

        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Renew());

        rig.Time.Advance(TimeSpan.FromSeconds(20));
        Assert.Equal(LocalRpcBrokerSessionState.Open, rig.Session.State);
        rig.Time.Advance(TimeSpan.FromMilliseconds(9_999));
        Assert.Equal(LocalRpcBrokerSessionState.Open, rig.Session.State);
        rig.Time.Advance(TimeSpan.FromMilliseconds(1));
        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.Expired);
    }

    [Fact]
    public void ARenewalJustBeforeTheDeadlineIsHonouredAndOneAfterItIsNotARevival()
    {
        using var rig = BrokerRig.Create();
        rig.Time!.Advance(TimeSpan.FromMilliseconds(29_999));
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Renew());
        rig.Time.Advance(TimeSpan.FromMilliseconds(29_999));
        Assert.Equal(LocalRpcBrokerSessionState.Open, rig.Session.State);
        rig.Time.Advance(TimeSpan.FromMilliseconds(1));
        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.Expired);

        Assert.Equal(LocalRpcBrokerRefusal.Expired, rig.Session.Renew());
        Assert.Equal(LocalRpcBrokerSessionState.Closed, rig.Session.State);
        Assert.Single(rig.Ends);
    }

    [Fact]
    public void TheLeaseExpiryIsReportedFromTheRegistryClock()
    {
        using var rig = BrokerRig.Create();
        var start = rig.Time!.GetUtcNow();
        Assert.Equal(start + TimeSpan.FromSeconds(30), rig.Session.LeaseExpiresAt);

        rig.Time.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(start + TimeSpan.FromSeconds(30), rig.Session.LeaseExpiresAt);

        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Renew());
        Assert.Equal(start + TimeSpan.FromSeconds(40), rig.Session.LeaseExpiresAt);
    }

    [Theory]
    [InlineData("grant")]
    [InlineData("seal")]
    [InlineData("copy")]
    [InlineData("acknowledge")]
    [InlineData("renew")]
    public async Task ATimerThatNeverFiresStillCannotLetAnExpiredSessionBeUsed(string operation)
    {
        var clock = new FrozenTimerClock();
        using var rig = BrokerRig.Create(clock: clock);
        var grant = rig.Session.Grant(Slot0, 100).Value!;
        var seal = rig.HonestSeal(grant, BrokerRig.Pattern(10));
        clock.Advance(TimeSpan.FromSeconds(31));

        var refusal = operation switch
        {
            "grant" => rig.Session.Grant(Slot1, 10).Refusal,
            "seal" => rig.Session.Seal(seal),
            "copy" => (await rig.Session.CopyAsync(Slot0, grant.Sequence, TestContext.Current.CancellationToken)).Refusal,
            "acknowledge" => rig.Session.Acknowledge(Slot0, grant.Sequence).Refusal,
            _ => rig.Session.Renew(),
        };

        Assert.Equal(LocalRpcBrokerRefusal.Expired, refusal);
        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.Expired);
    }

    [Fact]
    public async Task ALeaseThatRunsOutDuringACopyStopsTheCopyAndEndsTheSession()
    {
        var clock = new FrozenTimerClock();
        var limits = new LocalRpcBrokerLimits { ChunkBytes = 4096 };
        using var rig = BrokerRig.Create(slotBytes: 32768, limits: limits, clock: clock);
        var (grant, _, _) = rig.GrantAndSeal(Slot0, 20000);
        rig.Maps[0].BeforeRead = (_, _) =>
        {
            if (rig.Maps[0].ReadSizes.Count == 2)
            {
                clock.Advance(TimeSpan.FromSeconds(31));
            }
        };

        var result = await rig.Session.CopyAsync(Slot0, grant.Sequence, TestContext.Current.CancellationToken);

        Assert.Equal(LocalRpcBrokerRefusal.Expired, result.Refusal);
        Assert.Equal(2, rig.Maps[0].ReadSizes.Count);
        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.Expired);
    }

    [Fact]
    public void ATimerThatFiresEarlyWaitsOutTheRemainderInsteadOfEndingOrDroppingTheLease()
    {
        using var rig = BrokerRig.Create();

        rig.Time!.FireNextEarly(TimeSpan.FromMilliseconds(5));

        Assert.Equal(LocalRpcBrokerSessionState.Open, rig.Session.State);
        Assert.Empty(rig.Ends);
        Assert.Equal(1, rig.Time.ArmedTimers);
        rig.Time.Advance(TimeSpan.FromMilliseconds(4));
        Assert.Equal(LocalRpcBrokerSessionState.Open, rig.Session.State);
        rig.Time.Advance(TimeSpan.FromMilliseconds(2));
        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.Expired);
    }

    [Fact]
    public async Task ManyShortLeasesAllExpireOnTheRealClock()
    {
        var limits = new LocalRpcBrokerLimits { SessionLease = TimeSpan.FromMilliseconds(40), MaxSessions = 64 };
        using var registry = new LocalRpcBrokerRegistry(limits);
        var ends = new List<LocalRpcBrokerEnd>();
        for (var index = 0; index < 60; index++)
        {
            var created = registry.CreateSession(new LocalRpcBrokerSessionOptions
            {
                InvocationId = Guid.NewGuid(),
                LeaseId = BrokerRig.Lease,
                Generation = 1,
                Slots = [new MemoryMapping(64)],
                Ended = end =>
                {
                    lock (ends)
                    {
                        ends.Add(end);
                    }
                },
            });
            Assert.True(created.IsSuccess);
        }

        await BoundsHarness.WaitUntilAsync(() => registry.OpenSessions == 0, "every short lease to expire", TestContext.Current.CancellationToken);

        Assert.Equal(60, ends.Count);
        Assert.All(ends, end => Assert.Equal(LocalRpcBrokerEndReason.Expired, end.Reason));
    }

    [Fact]
    public async Task ARenewedSessionOutlivesItsLeaseAndExpiresOnceRenewalStops()
    {
        var limits = new LocalRpcBrokerLimits { SessionLease = TimeSpan.FromMilliseconds(600) };
        using var rig = BrokerRig.Create(manualClock: false, limits: limits);
        var stop = System.Diagnostics.Stopwatch.StartNew();
        while (stop.Elapsed < TimeSpan.FromMilliseconds(2000))
        {
            Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Renew());
            await Task.Delay(50, TestContext.Current.CancellationToken);
        }

        Assert.Equal(LocalRpcBrokerSessionState.Open, rig.Session.State);
        await BoundsHarness.WaitUntilAsync(() => rig.Session.State == LocalRpcBrokerSessionState.Closed, "the unrenewed session to expire", TestContext.Current.CancellationToken);
        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.Expired);
    }

    [Fact]
    public async Task CancelWithdrawsEverySlotInUseAndRefusesEverythingAfterIt()
    {
        using var rig = BrokerRig.Create();
        var writing = rig.Session.Grant(Slot0, 100).Value!;
        var (sealedGrant, _, _) = rig.GrantAndSeal(Slot1, 100);
        var (readGrant, _, _) = rig.GrantAndSeal(Slot2, 100);
        using var buffer = (await rig.Session.CopyAsync(Slot2, readGrant.Sequence, TestContext.Current.CancellationToken)).Value!;
        var honest = rig.HonestSeal(writing, BrokerRig.Pattern(10));

        rig.Session.Cancel();

        var snapshot = rig.Session.GetSnapshot();
        Assert.Equal(LocalRpcBrokerSessionState.Cancelled, snapshot.State);
        Assert.Equal([LocalRpcSlotState.Quarantined, LocalRpcSlotState.Quarantined, LocalRpcSlotState.Quarantined], snapshot.Slots);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, rig.Session.Grant(Slot0, 10).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, rig.Session.Seal(honest));
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, (await rig.Session.CopyAsync(Slot1, sealedGrant.Sequence, TestContext.Current.CancellationToken)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, rig.Session.Acknowledge(Slot2, readGrant.Sequence).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, rig.Session.Renew());
        Assert.Empty(rig.Ends);
        Assert.All(rig.Maps, map => Assert.Equal(0, map.Disposals));
    }

    [Fact]
    public void CancelLeavesAFreeSlotFreeButStillGrantsNothing()
    {
        using var rig = BrokerRig.Create();
        _ = rig.Session.Grant(Slot0, 100);

        rig.Session.Cancel();

        Assert.Equal([LocalRpcSlotState.Quarantined, LocalRpcSlotState.Free, LocalRpcSlotState.Free], rig.Session.GetSnapshot().Slots);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, rig.Session.Grant(Slot1, 10).Refusal);
    }

    [Fact]
    public void ACancelledSessionClosesItselfAfterTheGraceAndAsksForTheHelpersTermination()
    {
        using var rig = BrokerRig.Create();
        rig.Time!.Advance(TimeSpan.FromSeconds(1));
        rig.Session.Cancel();

        rig.Time.Advance(TimeSpan.FromMilliseconds(4_999));
        Assert.Equal(LocalRpcBrokerSessionState.Cancelled, rig.Session.State);
        Assert.Empty(rig.Ends);

        rig.Time.Advance(TimeSpan.FromMilliseconds(1));

        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.CancelUnresponsive);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, rig.Session.Grant(Slot0, 10).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, rig.Session.Renew());
    }

    [Fact]
    public void RepeatingCancelNeitherRestartsTheGraceNorChangesAnything()
    {
        using var rig = BrokerRig.Create();
        rig.Session.Cancel();
        rig.Time!.Advance(TimeSpan.FromSeconds(3));

        rig.Session.Cancel();
        rig.Time.Advance(TimeSpan.FromMilliseconds(1_999));
        Assert.Equal(LocalRpcBrokerSessionState.Cancelled, rig.Session.State);
        rig.Time.Advance(TimeSpan.FromMilliseconds(1));

        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.CancelUnresponsive);
    }

    [Fact]
    public void TheGraceIsTheConfiguredLimit()
    {
        using var rig = BrokerRig.Create(limits: new LocalRpcBrokerLimits { CancelGrace = TimeSpan.FromSeconds(2) });
        rig.Session.Cancel();

        rig.Time!.Advance(TimeSpan.FromMilliseconds(1_999));
        Assert.Equal(LocalRpcBrokerSessionState.Cancelled, rig.Session.State);
        rig.Time.Advance(TimeSpan.FromMilliseconds(1));

        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.CancelUnresponsive);
    }

    [Fact]
    public void TheOwnerClosingWithinTheGraceEndsTheSessionNormallyAndOnlyOnce()
    {
        using var rig = BrokerRig.Create();
        rig.Session.Cancel();
        rig.Time!.Advance(TimeSpan.FromSeconds(3));

        rig.Session.Close();
        Assert.Equal(0, rig.Time.ArmedTimers);
        rig.Time.Advance(TimeSpan.FromSeconds(30));

        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.Closed);
        Assert.Equal(0, rig.Time!.ArmedTimers);
        Assert.Equal(LocalRpcBrokerRefusal.Closed, rig.Session.Grant(Slot0, 10).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Closed, rig.Session.Renew());
    }

    [Fact]
    public void ALeaseShorterThanTheGraceStillEndsTheCancelledSessionAsExpired()
    {
        using var rig = BrokerRig.Create(limits: new LocalRpcBrokerLimits { SessionLease = TimeSpan.FromSeconds(2) });
        rig.Session.Cancel();

        rig.Time!.Advance(TimeSpan.FromMilliseconds(1_999));
        Assert.Equal(LocalRpcBrokerSessionState.Cancelled, rig.Session.State);
        rig.Time.Advance(TimeSpan.FromMilliseconds(1));

        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.Expired);
    }

    [Fact]
    public void CancellingAClosedSessionChangesNothing()
    {
        using var rig = BrokerRig.Create();
        rig.Session.Close();

        rig.Session.Cancel();
        rig.Time!.Advance(TimeSpan.FromSeconds(60));

        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.Closed);
    }

    [Fact]
    public async Task CancelStopsACopyInProgressWithinOneChunkAndDeliversNothing()
    {
        var limits = new LocalRpcBrokerLimits { ChunkBytes = 4096 };
        using var rig = BrokerRig.Create(slotBytes: 65536, limits: limits);
        var (grant, _, _) = rig.GrantAndSeal(Slot0, 60000);
        using var started = new ManualResetEventSlim();
        using var gate = new ManualResetEventSlim();
        rig.Maps[0].BeforeRead = (_, _) =>
        {
            if (rig.Maps[0].ReadSizes.Count == 2)
            {
                started.Set();
                gate.Wait(Patience);
            }
        };
        var copy = Task.Run(() => rig.Session.CopyAsync(Slot0, grant.Sequence, TestContext.Current.CancellationToken).AsTask());
        Assert.True(started.Wait(Patience, TestContext.Current.CancellationToken));

        rig.Session.Cancel();
        gate.Set();
        var result = await copy;

        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, result.Refusal);
        Assert.Null(result.Value);
        Assert.Equal(2, rig.Maps[0].ReadSizes.Count);
        var snapshot = rig.Session.GetSnapshot();
        Assert.False(snapshot.CopyActive);
        Assert.Equal(LocalRpcSlotState.Quarantined, snapshot.Slots[0]);
        rig.Session.Close();
        Assert.All(rig.Maps, map => Assert.Equal(1, map.Disposals));
    }

    [Fact]
    public async Task ClosingReleasesEveryMappingOnceAndEndsOnceWhateverHowOftenItIsCalled()
    {
        var rig = BrokerRig.Create();
        _ = rig.Session.Grant(Slot0, 100);

        rig.Session.Close();
        rig.Session.Close();
        rig.Session.Dispose();
        rig.Session.Cancel();
        rig.Registry.Dispose();

        Assert.Equal(LocalRpcBrokerSessionState.Closed, rig.Session.State);
        Assert.Equal(LocalRpcBrokerEndReason.Closed, rig.Session.EndReason);
        Assert.Single(rig.Ends);
        Assert.Equal(0, rig.Registry.OpenSessions);
        Assert.All(rig.Maps, map => Assert.Equal(1, map.Disposals));
        Assert.Equal(LocalRpcBrokerRefusal.Closed, rig.Session.Grant(Slot1, 10).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Closed, rig.Session.Seal(new LocalRpcBufferSeal(BrokerRig.Invocation, BrokerRig.Lease, BrokerRig.GenerationValue, Slot0, 1, 0, 1, LocalRpcDigest.Compute([1]), 0)));
        Assert.Equal(LocalRpcBrokerRefusal.Closed, rig.Session.Acknowledge(Slot0, 1).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Closed, rig.Session.Renew());
        Assert.Equal(LocalRpcBrokerRefusal.Closed, (await rig.Session.CopyAsync(Slot0, 1, TestContext.Current.CancellationToken)).Refusal);
    }

    [Fact]
    public async Task MappingsAreNotReleasedWhileACopyIsStillReadingThem()
    {
        using var rig = BrokerRig.Create(limits: new LocalRpcBrokerLimits { ChunkBytes = 4096 });
        var (grant, _, _) = rig.GrantAndSeal(Slot0, 20000);
        using var started = new ManualResetEventSlim();
        using var gate = new ManualResetEventSlim();
        rig.Maps[0].BeforeRead = (_, _) =>
        {
            started.Set();
            gate.Wait(Patience);
        };
        var copy = Task.Run(() => rig.Session.CopyAsync(Slot0, grant.Sequence, TestContext.Current.CancellationToken).AsTask());
        Assert.True(started.Wait(Patience, TestContext.Current.CancellationToken));

        rig.Session.Close();

        Assert.Equal(LocalRpcBrokerSessionState.Closed, rig.Session.State);
        Assert.Single(rig.Ends);
        Assert.Equal(0, rig.Registry.OpenSessions);
        Assert.All(rig.Maps, map => Assert.Equal(0, map.Disposals));
        gate.Set();
        var result = await copy;

        Assert.Equal(LocalRpcBrokerRefusal.Closed, result.Refusal);
        Assert.Single(rig.Maps[0].ReadSizes);
        Assert.All(rig.Maps, map => Assert.Equal(1, map.Disposals));
        Assert.False(rig.Maps[0].DisposedWhileReading);
        Assert.False(rig.Session.GetSnapshot().CopyActive);
    }

    [Fact]
    public void AnEndedCallbackThatThrowsDoesNotUndoTheClose()
    {
        using var registry = new LocalRpcBrokerRegistry(null, new ManualTimeProvider());
        var map = new MemoryMapping(64);
        var calls = 0;
        var session = registry.CreateSession(new LocalRpcBrokerSessionOptions
        {
            InvocationId = Guid.NewGuid(),
            LeaseId = BrokerRig.Lease,
            Generation = 1,
            Slots = [map],
            Ended = _ =>
            {
                calls++;
                throw new InvalidOperationException("The owner failed.");
            },
        }).Value!;

        session.Close();

        Assert.Equal(1, calls);
        Assert.Equal(1, map.Disposals);
        Assert.Equal(0, registry.OpenSessions);
        Assert.Equal(LocalRpcBrokerSessionState.Closed, session.State);
    }

    [Fact]
    public void TheEndedCallbackRunsOutsideEverySessionAndRegistryLock()
    {
        using var registry = new LocalRpcBrokerRegistry(null, new ManualTimeProvider());
        LocalRpcBrokerSession? session = null;
        var reachedFromAnotherThread = false;
        session = registry.CreateSession(new LocalRpcBrokerSessionOptions
        {
            InvocationId = Guid.NewGuid(),
            LeaseId = BrokerRig.Lease,
            Generation = 1,
            Slots = [new MemoryMapping(64)],
            Ended = _ => reachedFromAnotherThread = Task.Run(() => (session!.GetSnapshot(), registry.OpenSessions)).Wait(Patience),
        }).Value!;

        session.Close();

        Assert.True(reachedFromAnotherThread);
    }

    [Fact]
    public void ThePairGoingAwayClosesTheSessionAndEveryLaterCallSaysSo()
    {
        using var gone = new CancellationTokenSource();
        using var rig = BrokerRig.Create(pairGone: gone.Token);
        _ = rig.Session.Grant(Slot0, 100);

        gone.Cancel();

        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.PairGone);
        Assert.Equal(LocalRpcBrokerRefusal.PairGone, rig.Session.Grant(Slot1, 10).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.PairGone, rig.Session.Renew());
    }

    [Fact]
    public void ThePairCheckDecidesRenewalAndAFailingOneClosesTheSession()
    {
        var alive = true;
        using var rig = BrokerRig.Create(pairLives: () => alive);
        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Renew());
        Assert.Equal(LocalRpcBrokerSessionState.Open, rig.Session.State);

        alive = false;
        Assert.Equal(LocalRpcBrokerRefusal.PairGone, rig.Session.Renew());

        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.PairGone);
    }

    [Fact]
    public void AThrowingPairCheckCountsAsTheCheckFailing()
    {
        using var rig = BrokerRig.Create(pairLives: () => throw new InvalidOperationException("The check failed."));

        Assert.Equal(LocalRpcBrokerRefusal.PairGone, rig.Session.Renew());

        LocalRpcBrokerSessionTests.AssertEnded(rig, LocalRpcBrokerEndReason.PairGone);
    }

    [Fact]
    public void ThePairCheckRunsOutsideEverySessionLock()
    {
        var holder = new SessionHolder();
        var reached = false;
        using var rig = BrokerRig.Create(pairLives: () =>
        {
            reached = Task.Run(() => holder.Session!.GetSnapshot()).Wait(Patience);
            return true;
        });
        holder.Session = rig.Session;

        Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Renew());

        Assert.True(reached);
    }

    [Fact]
    public async Task ManyThreadsDrivingTheProtocolAtOnceKeepEveryInvariant()
    {
        const int sessions = 3;
        var rigs = Enumerable.Range(0, sessions).Select(_ => BrokerRig.Create(manualClock: false, slotBytes: 8192)).ToArray();
        var concurrentReads = new int[sessions];
        var peakReads = new int[sessions];
        for (var index = 0; index < sessions; index++)
        {
            var capture = index;
            foreach (var map in rigs[index].Maps)
            {
                map.BeforeRead = (_, _) =>
                {
                    var now = Interlocked.Increment(ref concurrentReads[capture]);
                    int peak;
                    while (now > (peak = Volatile.Read(ref peakReads[capture])) && Interlocked.CompareExchange(ref peakReads[capture], now, peak) != peak)
                    {
                    }
                };
                map.ReadResult = (_, count) =>
                {
                    _ = Interlocked.Decrement(ref concurrentReads[capture]);
                    return count;
                };
            }
        }

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
        var workers = rigs.SelectMany((rig, index) => Enumerable.Range(0, 3).Select(worker => Task.Run(async () =>
        {
            var random = new Random((index * 100) + worker);
            while (DateTime.UtcNow < deadline)
            {
                var slot = (uint)random.Next(0, 3);
                var grant = rig.Session.Grant(slot, 4096);
                if (grant.IsSuccess)
                {
                    var seal = rig.HonestSeal(grant.Value!, BrokerRig.Pattern(random.Next(1, 4096)));
                    if (rig.Session.Seal(seal) == LocalRpcBrokerRefusal.None)
                    {
                        var copy = await rig.Session.CopyAsync(slot, grant.Value!.Sequence);
                        while (copy.Refusal == LocalRpcBrokerRefusal.CopyBusy && DateTime.UtcNow < deadline)
                        {
                            await Task.Delay(1);
                            copy = await rig.Session.CopyAsync(slot, grant.Value.Sequence, TestContext.Current.CancellationToken);
                        }

                        copy.Value?.Dispose();
                        _ = rig.Session.Acknowledge(slot, grant.Value.Sequence);
                    }
                }

                _ = rig.Session.Renew();
                _ = rig.Session.GetSnapshot();
                await Task.Delay(1);
                if (worker == 2 && random.Next(0, 4000) == 0)
                {
                    rig.Session.Cancel();
                }
            }
        }))).ToArray();
        await Task.WhenAll(workers).WaitAsync(TimeSpan.FromSeconds(120), TestContext.Current.CancellationToken);

        foreach (var (rig, index) in rigs.Select((rig, index) => (rig, index)))
        {
            rig.Session.Close();
            Assert.Single(rig.Ends);
            Assert.All(rig.Maps, map =>
            {
                Assert.Equal(1, map.Disposals);
                Assert.False(map.DisposedWhileReading);
            });
            Assert.True(peakReads[index] <= 1, "two copies read at once: " + peakReads[index]);
            Assert.False(rig.Session.GetSnapshot().CopyActive);
        }

        Assert.All(rigs, rig => Assert.Equal(0, rig.Registry.OpenSessions));
    }

    private sealed class SessionHolder
    {
        internal LocalRpcBrokerSession? Session { get; set; }
    }
}
