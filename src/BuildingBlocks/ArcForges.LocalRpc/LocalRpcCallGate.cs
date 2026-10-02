// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.LocalRpc;

/// <summary>What a call gate decided for one entering call.</summary>
internal enum LocalRpcGateOutcome
{
    /// <summary>The caller holds an active slot and must call <see cref="LocalRpcCallGate.Exit"/> exactly once.</summary>
    Admitted,

    /// <summary>The lane is saturated and the call may not wait (or the bounded queue is full). Nothing was taken.</summary>
    Refused,
}

/// <summary>
/// A bounded, strictly first-in-first-out admission gate: at most <c>activeLimit</c> holders run at once and at most
/// <c>queueLimit</c> callers wait for a slot. A waiter costs one fixed-size node, so the memory held by waiting calls is
/// bounded by <c>queueLimit</c>. A freed slot is handed directly to the oldest waiter, so a newcomer can never overtake
/// a queued call.
/// </summary>
internal sealed class LocalRpcCallGate
{
    private readonly object _gate = new();
    private readonly LinkedList<Waiter> _queue = new();
    private readonly int _activeLimit;
    private readonly int _queueLimit;
    private int _active;

    internal LocalRpcCallGate(int activeLimit, int queueLimit)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(activeLimit, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(queueLimit);
        _activeLimit = activeLimit;
        _queueLimit = queueLimit;
    }

    internal int Active
    {
        get
        {
            lock (_gate)
            {
                return _active;
            }
        }
    }

    internal int Queued
    {
        get
        {
            lock (_gate)
            {
                return _queue.Count;
            }
        }
    }

    /// <summary>
    /// Takes a slot, waiting in order when <paramref name="mayQueue"/> allows it and the queue has room. Throws
    /// <see cref="OperationCanceledException"/> when <paramref name="cancellationToken"/> fires while waiting; a cancelled
    /// waiter leaves the queue and takes nothing.
    /// </summary>
    internal ValueTask<LocalRpcGateOutcome> EnterAsync(bool mayQueue, CancellationToken cancellationToken)
    {
        Waiter waiter;
        lock (_gate)
        {
            if (_active < _activeLimit && _queue.Count == 0)
            {
                _active++;
                return ValueTask.FromResult(LocalRpcGateOutcome.Admitted);
            }

            if (!mayQueue || _queue.Count >= _queueLimit)
            {
                return ValueTask.FromResult(LocalRpcGateOutcome.Refused);
            }

            waiter = new Waiter();
            waiter.Node = _queue.AddLast(waiter);
        }

        return WaitAsync(waiter, cancellationToken);
    }

    /// <summary>Returns a slot. It passes to the oldest waiter if there is one.</summary>
    internal void Exit()
    {
        Waiter? next = null;
        lock (_gate)
        {
            if (_queue.First is { } first)
            {
                next = first.Value;
                _queue.RemoveFirst();
                next.Node = null;
            }
            else
            {
                if (_active == 0)
                {
                    throw new InvalidOperationException("A gate slot is returned once per admission.");
                }

                _active--;
            }
        }

        next?.Completion.TrySetResult();
    }

    private async ValueTask<LocalRpcGateOutcome> WaitAsync(Waiter waiter, CancellationToken cancellationToken)
    {
        using var registration = cancellationToken.Register(() => Cancel(waiter));
        await waiter.Completion.Task.ConfigureAwait(false);
        return LocalRpcGateOutcome.Admitted;
    }

    private void Cancel(Waiter waiter)
    {
        lock (_gate)
        {
            if (waiter.Node is not { } node)
            {
                // Already handed a slot: the waiting caller continues as an admitted caller and exits normally.
                return;
            }

            _queue.Remove(node);
            waiter.Node = null;
        }

        _ = waiter.Completion.TrySetCanceled();
    }

    private sealed class Waiter
    {
        internal TaskCompletionSource Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal LinkedListNode<Waiter>? Node { get; set; }
    }
}
