// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.LocalRpc;

/// <summary>
/// The parent's bounded set of brokered sessions. It admits at most <see cref="LocalRpcBrokerLimits.MaxSessions"/> sessions
/// at once and one session per invocation, so the memory the broker can hold is bounded by that many private copies of at
/// most 64 MiB, whatever the connections do. Disposing it closes every session.
/// </summary>
public sealed class LocalRpcBrokerRegistry : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<Guid, LocalRpcBrokerSession> _sessions = [];
    private bool _disposed;

    /// <summary>Creates a registry with the given limits (the profile's own when none are given).</summary>
    public LocalRpcBrokerRegistry(LocalRpcBrokerLimits? limits = null)
        : this(limits, TimeProvider.System)
    {
    }

    internal LocalRpcBrokerRegistry(LocalRpcBrokerLimits? limits, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(time);
        Limits = (limits ?? new LocalRpcBrokerLimits()).Validated();
        Time = time;
    }

    /// <summary>The sessions currently open.</summary>
    public int OpenSessions
    {
        get
        {
            lock (_gate)
            {
                return _sessions.Count;
            }
        }
    }

    internal LocalRpcBrokerLimits Limits { get; }

    internal TimeProvider Time { get; }

    /// <summary>
    /// Opens the session of one invocation. Malformed options throw. A refusal (<see cref="LocalRpcBrokerRefusal.TooManySessions"/>,
    /// <see cref="LocalRpcBrokerRefusal.DuplicateInvocation"/>, <see cref="LocalRpcBrokerRefusal.PairGone"/> or
    /// <see cref="LocalRpcBrokerRefusal.Closed"/> for a disposed registry) leaves the mappings with the caller; success
    /// transfers them to the session, which disposes them when it ends.
    /// </summary>
    public LocalRpcBrokerResult<LocalRpcBrokerSession> CreateSession(LocalRpcBrokerSessionOptions options)
    {
        var (mappings, lengths) = ValidateOptions(options);
        if (options.PairGone.IsCancellationRequested)
        {
            return BrokerResult.Fail<LocalRpcBrokerSession>(LocalRpcBrokerRefusal.PairGone);
        }

        LocalRpcBrokerSession session;
        lock (_gate)
        {
            if (_disposed)
            {
                return BrokerResult.Fail<LocalRpcBrokerSession>(LocalRpcBrokerRefusal.Closed);
            }

            if (_sessions.ContainsKey(options.InvocationId))
            {
                return BrokerResult.Fail<LocalRpcBrokerSession>(LocalRpcBrokerRefusal.DuplicateInvocation);
            }

            if (_sessions.Count >= Limits.MaxSessions)
            {
                return BrokerResult.Fail<LocalRpcBrokerSession>(LocalRpcBrokerRefusal.TooManySessions);
            }

            session = new LocalRpcBrokerSession(this, options, mappings, lengths);
            _sessions.Add(options.InvocationId, session);
        }

        session.Start();
        return BrokerResult.Ok(session);
    }

    /// <summary>Closes every session; their mappings are released.</summary>
    public void Dispose()
    {
        LocalRpcBrokerSession[] sessions;
        lock (_gate)
        {
            _disposed = true;
            sessions = [.. _sessions.Values];
        }

        foreach (var session in sessions)
        {
            session.CloseWith(LocalRpcBrokerEndReason.RegistryDisposed);
        }
    }

    internal void Remove(LocalRpcBrokerSession session)
    {
        lock (_gate)
        {
            // Only this very session is removed: a later session of the same invocation is never taken out by an earlier one's close.
            _ = ((ICollection<KeyValuePair<Guid, LocalRpcBrokerSession>>)_sessions).Remove(new KeyValuePair<Guid, LocalRpcBrokerSession>(session.InvocationId, session));
        }
    }

    private static (ILocalRpcBufferMapping[] Mappings, long[] Lengths) ValidateOptions(LocalRpcBrokerSessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.InvocationId == Guid.Empty)
        {
            throw new ArgumentException("The invocation identifier is never zero.", nameof(options));
        }

        if (options.LeaseId == Guid.Empty)
        {
            throw new ArgumentException("The lease identifier is never zero.", nameof(options));
        }

        if (options.Generation == 0)
        {
            throw new ArgumentException("The generation is positive.", nameof(options));
        }

        var slots = options.Slots?.ToArray();
        if (slots is null || slots.Length is < 1 or > LocalRpcBrokerLimits.MaxSlots)
        {
            throw new ArgumentException("An invocation has one to three slots.", nameof(options));
        }

        var lengths = new long[slots.Length];
        for (var index = 0; index < slots.Length; index++)
        {
            var mapping = slots[index];
            if (mapping is null)
            {
                throw new ArgumentException("A slot mapping is required.", nameof(options));
            }

            var length = mapping.Length;
            if (length is < 1 or > LocalRpcBrokerLimits.MaxSlotBytes)
            {
                throw new ArgumentException("A slot is 1 byte through 64 MiB.", nameof(options));
            }

            lengths[index] = length;

            for (var earlier = 0; earlier < index; earlier++)
            {
                if (ReferenceEquals(slots[earlier], mapping))
                {
                    throw new ArgumentException("Each slot has its own mapping.", nameof(options));
                }
            }
        }

        return (slots, lengths);
    }
}
