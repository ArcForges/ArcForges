// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Collections.Frozen;

namespace ArcForges.LocalRpc;

/// <summary>
/// The call bounds of one connected peer: a data lane (active and queued calls in arrival order), the reserved control
/// slots that no data call can take, and the watchdog that closes a connection that never starts a call or sits idle.
/// </summary>
internal sealed class LocalRpcPeerBounds : IDisposable
{
    private readonly LocalRpcBoundsRegistry _registry;
    private readonly object _sync = new();
    private ITimer? _timer;
    private Action? _abort;
    private long _armedAt;
    private TimeSpan _armedFor;
    private int _inFlight;
    private bool _disposed;

    internal LocalRpcPeerBounds(LocalRpcBoundsRegistry registry, string connectionId)
    {
        _registry = registry;
        ConnectionId = connectionId;
        Data = new LocalRpcCallGate(registry.Limits.MaxActiveCalls, registry.Limits.MaxQueuedCalls);
        Control = new LocalRpcCallGate(LocalRpcLimits.ControlSlots, 0);
    }

    internal string ConnectionId { get; }

    internal LocalRpcCallGate Data { get; }

    internal LocalRpcCallGate Control { get; }

    /// <summary>Starts the handshake clock. <paramref name="abort"/> closes the connection when a watchdog limit passes.</summary>
    internal void Start(Action abort)
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _abort = abort;
            _timer = _registry.Time.CreateTimer(OnTimer, null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            Arm(_registry.Limits.HandshakeTimeout);
        }
    }

    /// <summary>A call began (it may still be waiting for a slot): the connection is not idle.</summary>
    internal void CallStarted()
    {
        lock (_sync)
        {
            _inFlight++;
            _ = _timer?.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }
    }

    /// <summary>A call ended. With none left in flight the idle clock starts.</summary>
    internal void CallFinished()
    {
        lock (_sync)
        {
            _inFlight--;
            if (_inFlight == 0 && !_disposed && _timer is not null)
            {
                Arm(_registry.Limits.IdleTimeout);
            }
        }
    }

    public void Dispose()
    {
        ITimer? timer;
        lock (_sync)
        {
            _disposed = true;
            timer = _timer;
            _timer = null;
            _abort = null;
        }

        timer?.Dispose();
    }

    private void Arm(TimeSpan dueTime)
    {
        _armedAt = _registry.Time.GetTimestamp();
        _armedFor = dueTime;
        _ = _timer!.Change(dueTime, Timeout.InfiniteTimeSpan);
    }

    internal void OnTimer(object? state)
    {
        Action? abort;
        lock (_sync)
        {
            if (_disposed || _inFlight > 0)
            {
                return;
            }

            // A real timer can fire a fraction of a millisecond before the stopwatch says its due time has passed, and a
            // callback queued by an earlier arming can run after a call restarted the clock. Either way the limit is still
            // owed: wait out the remainder instead of dropping it, so a silent peer can never keep its slot.
            var elapsed = _registry.Time.GetElapsedTime(_armedAt);
            if (elapsed < _armedFor)
            {
                _ = _timer?.Change(_armedFor - elapsed, Timeout.InfiniteTimeSpan);
                return;
            }

            abort = _abort;
        }

        abort?.Invoke();
    }
}

/// <summary>The peers of one server and the totals its bounds layer keeps.</summary>
internal sealed class LocalRpcBoundsRegistry
{
    private static readonly LocalRpcControlOperation[] Operations = Enum.GetValues<LocalRpcControlOperation>().Where(operation => operation != LocalRpcControlOperation.None).ToArray();
    private static readonly LocalRpcRefusalReason[] Reasons = Enum.GetValues<LocalRpcRefusalReason>().Where(reason => reason != LocalRpcRefusalReason.None).ToArray();

    private readonly ConcurrentDictionary<string, LocalRpcPeerBounds> _peers = new(StringComparer.Ordinal);
    private readonly long[] _controlAdmitted = new long[Operations.Length + 1];
    private readonly long[] _refused = new long[Reasons.Length + 1];
    private long _dataAdmitted;

    internal LocalRpcBoundsRegistry(LocalRpcLimits limits, TimeProvider time)
    {
        Limits = limits;
        Time = time;
    }

    internal LocalRpcLimits Limits { get; }

    internal TimeProvider Time { get; }

    internal LocalRpcPeerBounds Add(string connectionId)
    {
        var peer = new LocalRpcPeerBounds(this, connectionId);
        _peers[connectionId] = peer;
        return peer;
    }

    internal void Remove(LocalRpcPeerBounds peer)
    {
        _ = _peers.TryRemove(new KeyValuePair<string, LocalRpcPeerBounds>(peer.ConnectionId, peer));
        peer.Dispose();
    }

    internal bool TryGet(string connectionId, out LocalRpcPeerBounds? peer)
    {
        var found = _peers.TryGetValue(connectionId, out var value);
        peer = value;
        return found;
    }

    internal void CountDataAdmitted() => Interlocked.Increment(ref _dataAdmitted);

    internal void CountControlAdmitted(LocalRpcControlOperation operation) => Interlocked.Increment(ref _controlAdmitted[(int)operation]);

    internal void CountRefused(LocalRpcRefusalReason reason) => Interlocked.Increment(ref _refused[(int)reason]);

    internal LocalRpcBoundsSnapshot Snapshot()
    {
        int peers = 0, dataActive = 0, dataQueued = 0, controlActive = 0;
        foreach (var peer in _peers.Values)
        {
            peers++;
            dataActive += peer.Data.Active;
            dataQueued += peer.Data.Queued;
            controlActive += peer.Control.Active;
        }

        return new LocalRpcBoundsSnapshot(
            peers,
            dataActive,
            dataQueued,
            controlActive,
            Interlocked.Read(ref _dataAdmitted),
            Operations.ToFrozenDictionary(operation => operation, operation => Interlocked.Read(ref _controlAdmitted[(int)operation])),
            Reasons.ToFrozenDictionary(reason => reason, reason => Interlocked.Read(ref _refused[(int)reason])));
    }
}
