// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>The admission gate in isolation: bounds, arrival order, cancellation and slot accounting.</summary>
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcCallGateTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    [Fact]
    public async Task AdmitsUpToTheActiveLimitQueuesUpToTheQueueLimitAndRefusesTheRest()
    {
        var ct = TestContext.Current.CancellationToken;
        var gate = new LocalRpcCallGate(activeLimit: 2, queueLimit: 3);

        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(gate, true, ct));
        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(gate, true, ct));
        var waiting = Enumerable.Range(0, 3).Select(_ => gate.EnterAsync(true, ct).AsTask()).ToArray();
        var refused = await Immediate(gate, true, ct);

        Assert.Equal(LocalRpcGateOutcome.Refused, refused);
        Assert.Equal(2, gate.Active);
        Assert.Equal(3, gate.Queued);
        Assert.All(waiting, task => Assert.False(task.IsCompleted));
        for (var index = 0; index < 5; index++)
        {
            gate.Exit();
        }

        _ = await Task.WhenAll(waiting).WaitAsync(Patience, ct);
        Assert.Equal(0, gate.Active);
    }

    [Fact]
    public async Task ARefusedCallTakesNothingAndAZeroQueueNeverWaits()
    {
        var ct = TestContext.Current.CancellationToken;
        var gate = new LocalRpcCallGate(activeLimit: 1, queueLimit: 0);

        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(gate, true, ct));
        Assert.Equal(LocalRpcGateOutcome.Refused, await Immediate(gate, true, ct));
        Assert.Equal(1, gate.Active);
        Assert.Equal(0, gate.Queued);
        gate.Exit();
        Assert.Equal(0, gate.Active);
        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(gate, true, ct));
    }

    [Fact]
    public async Task ACallThatMayNotQueueIsRefusedWhenSaturatedButAdmittedWhenFree()
    {
        var ct = TestContext.Current.CancellationToken;
        var gate = new LocalRpcCallGate(activeLimit: 1, queueLimit: 4);

        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(gate, false, ct));
        Assert.Equal(LocalRpcGateOutcome.Refused, await Immediate(gate, false, ct));
        Assert.Equal(0, gate.Queued);
        gate.Exit();
        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(gate, false, ct));
    }

    [Fact]
    public async Task QueuedCallsAreAdmittedInArrivalOrderAndNoNewcomerOvertakesThem()
    {
        var ct = TestContext.Current.CancellationToken;
        var gate = new LocalRpcCallGate(activeLimit: 1, queueLimit: 8);
        var order = new List<int>();
        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(gate, true, ct));
        var waiters = new List<Task>();
        for (var index = 0; index < 8; index++)
        {
            var id = index;
            waiters.Add(Task.Run(async () =>
            {
                _ = await gate.EnterAsync(true, ct);
                lock (order)
                {
                    order.Add(id);
                }
            }, ct));
            await WaitUntilAsync(() => gate.Queued == id + 1, ct);
        }

        for (var index = 0; index < 8; index++)
        {
            gate.Exit();
            await WaitUntilAsync(() => { lock (order) { return order.Count == index + 1; } }, ct);
            // The slot was handed over, not freed: a newcomer that may not wait finds the gate still full.
            Assert.Equal(1, gate.Active);
            Assert.Equal(LocalRpcGateOutcome.Refused, await Immediate(gate, false, ct));
        }

        await Task.WhenAll(waiters).WaitAsync(Patience, ct);
        Assert.Equal(Enumerable.Range(0, 8), order);
        gate.Exit();
        Assert.Equal(0, gate.Active);
    }

    [Fact]
    public async Task ACancelledWaiterLeavesTheQueueAndTakesNoSlot()
    {
        var ct = TestContext.Current.CancellationToken;
        var gate = new LocalRpcCallGate(activeLimit: 1, queueLimit: 2);
        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(gate, true, ct));
        using var cancel = new CancellationTokenSource();
        var cancelled = gate.EnterAsync(true, cancel.Token).AsTask();
        var survivor = gate.EnterAsync(true, ct).AsTask();
        Assert.Equal(2, gate.Queued);

        await cancel.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await cancelled);

        Assert.Equal(1, gate.Queued);
        gate.Exit();
        Assert.Equal(LocalRpcGateOutcome.Admitted, await survivor.WaitAsync(Patience, ct));
        Assert.Equal(1, gate.Active);
        gate.Exit();
        Assert.Equal(0, gate.Active);
        Assert.Equal(0, gate.Queued);
    }

    [Fact]
    public async Task AnAlreadyCancelledTokenNeverLeavesAWaiterBehind()
    {
        var ct = TestContext.Current.CancellationToken;
        var gate = new LocalRpcCallGate(activeLimit: 1, queueLimit: 2);
        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(gate, true, ct));
        using var cancel = new CancellationTokenSource();
        await cancel.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await gate.EnterAsync(true, cancel.Token));

        Assert.Equal(0, gate.Queued);
        Assert.Equal(1, gate.Active);
    }

    [Fact]
    public async Task CancellationRacingAdmissionNeverLeaksASlot()
    {
        var ct = TestContext.Current.CancellationToken;
        for (var round = 0; round < 300; round++)
        {
            var gate = new LocalRpcCallGate(activeLimit: 1, queueLimit: 1);
            Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(gate, true, ct));
            using var cancel = new CancellationTokenSource();
            var waiter = gate.EnterAsync(true, cancel.Token).AsTask();

            var exit = Task.Run(gate.Exit, ct);
            var abandon = Task.Run(cancel.Cancel, ct);
            await Task.WhenAll(exit, abandon);
            try
            {
                Assert.Equal(LocalRpcGateOutcome.Admitted, await waiter.WaitAsync(Patience, ct));
                gate.Exit();
            }
            catch (OperationCanceledException)
            {
                // The cancellation won: the waiter took nothing.
            }

            Assert.Equal(0, gate.Active);
            Assert.Equal(0, gate.Queued);
        }
    }

    [Fact]
    public async Task ConcurrentCallersNeverExceedTheActiveLimit()
    {
        var ct = TestContext.Current.CancellationToken;
        var gate = new LocalRpcCallGate(activeLimit: 4, queueLimit: 300);
        var running = 0;
        var peak = 0;
        var completed = 0;

        var callers = Enumerable.Range(0, 300).Select(_ => Task.Run(async () =>
        {
            Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(gate, true, ct));
            var now = Interlocked.Increment(ref running);
            int seen;
            while (now > (seen = Volatile.Read(ref peak)) && Interlocked.CompareExchange(ref peak, now, seen) != seen)
            {
            }

            await Task.Yield();
            _ = Interlocked.Decrement(ref running);
            gate.Exit();
            _ = Interlocked.Increment(ref completed);
        }, ct)).ToArray();
        await Task.WhenAll(callers).WaitAsync(Patience, ct);

        Assert.Equal(300, completed);
        Assert.InRange(peak, 1, 4);
        Assert.Equal(0, gate.Active);
        Assert.Equal(0, gate.Queued);
    }

    [Fact]
    public void ReturningASlotThatWasNeverTakenAndInvalidBoundsAreRefused()
    {
        var gate = new LocalRpcCallGate(activeLimit: 1, queueLimit: 0);

        Assert.Throws<InvalidOperationException>(gate.Exit);
        Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcCallGate(0, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcCallGate(1, -1));
    }

    /// <summary>Enters a gate that must answer at once; a gate that wrongly queues the caller fails the test instead of hanging it.</summary>
    private static async Task<LocalRpcGateOutcome> Immediate(LocalRpcCallGate gate, bool mayQueue, CancellationToken cancellationToken) =>
        await gate.EnterAsync(mayQueue, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);

    private static async Task WaitUntilAsync(Func<bool> condition, CancellationToken cancellationToken)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(Patience);
        while (!condition())
        {
            await Task.Delay(1, bounded.Token);
        }
    }
}
