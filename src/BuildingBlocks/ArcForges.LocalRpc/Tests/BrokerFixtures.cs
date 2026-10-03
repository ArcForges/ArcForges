// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// An in-process stand-in for a shared mapping: a byte array that a test can change between the parent's chunk reads, make
/// short or failing, and watch for being disposed while a read is running. It proves the broker's logic, never the behavior
/// of an OS shared-memory object.
/// </summary>
internal sealed class MemoryMapping(int length) : ILocalRpcBufferMapping
{
    private readonly object _gate = new();
    private readonly List<int> _readSizes = [];
    private int _reading;
    private int _disposed;
    private int _disposals;

    internal byte[] Bytes { get; } = new byte[length];

    /// <summary>When not negative, the length the mapping reports instead of its real one.</summary>
    internal long ReportedLength { get; set; } = -1;

    /// <summary>Runs before every read with the offset and the requested size; it may block, change <see cref="Bytes"/> or throw.</summary>
    internal Action<long, int>? BeforeRead { get; set; }

    /// <summary>When set, decides how many bytes a read reports (a short or an over-long read).</summary>
    internal Func<long, int, int>? ReadResult { get; set; }

    internal bool IsDisposed => Volatile.Read(ref _disposed) == 1;

    internal int Disposals => Volatile.Read(ref _disposals);

    internal bool DisposedWhileReading { get; private set; }

    internal IReadOnlyList<int> ReadSizes
    {
        get
        {
            lock (_gate)
            {
                return [.. _readSizes];
            }
        }
    }

    public long Length => ReportedLength >= 0 ? ReportedLength : Bytes.Length;

    public int Read(long offset, Span<byte> destination)
    {
        _ = Interlocked.Increment(ref _reading);
        try
        {
            lock (_gate)
            {
                _readSizes.Add(destination.Length);
            }

            ObjectDisposedException.ThrowIf(IsDisposed, this);
            BeforeRead?.Invoke(offset, destination.Length);
            var available = (int)Math.Clamp(Math.Min(destination.Length, Bytes.Length - offset), 0, int.MaxValue);
            Bytes.AsSpan((int)offset, available).CopyTo(destination);
            return ReadResult?.Invoke(offset, destination.Length) ?? available;
        }
        finally
        {
            _ = Interlocked.Decrement(ref _reading);
        }
    }

    public void Dispose()
    {
        _ = Interlocked.Increment(ref _disposals);
        if (Interlocked.Exchange(ref _disposed, 1) == 0 && Volatile.Read(ref _reading) > 0)
        {
            DisposedWhileReading = true;
        }
    }
}

/// <summary>One brokered session with its mappings, a clock a test controls and a record of how the session ended.</summary>
internal sealed class BrokerRig : IDisposable
{
    internal static readonly Guid Invocation = new("11111111-2222-4333-8444-555555555555");
    internal static readonly Guid Lease = new("66666666-7777-4888-9999-aaaaaaaaaaaa");
    internal const ulong GenerationValue = 7;

    private readonly List<LocalRpcBrokerEnd> _ends;

    private BrokerRig(LocalRpcBrokerRegistry registry, LocalRpcBrokerSession session, MemoryMapping[] maps, TimeProvider clock, List<LocalRpcBrokerEnd> ends)
    {
        _ends = ends;
        Registry = registry;
        Session = session;
        Maps = maps;
        Clock = clock;
    }

    internal LocalRpcBrokerRegistry Registry { get; }

    internal LocalRpcBrokerSession Session { get; }

    internal MemoryMapping[] Maps { get; }

    internal TimeProvider Clock { get; }

    /// <summary>The clock as a manual one that fires timers; null when the rig runs on another clock.</summary>
    internal ManualTimeProvider? Time => Clock as ManualTimeProvider;

    /// <summary>The clock as one whose timers never fire; null when the rig runs on another clock.</summary>
    internal FrozenTimerClock? Frozen => Clock as FrozenTimerClock;

    internal IReadOnlyList<LocalRpcBrokerEnd> Ends
    {
        get
        {
            lock (_ends)
            {
                return [.. _ends];
            }
        }
    }

    internal static BrokerRig Create(
        int slots = 3,
        int slotBytes = 64 * 1024,
        LocalRpcBrokerLimits? limits = null,
        bool manualClock = true,
        TimeProvider? clock = null,
        ulong firstSequence = 1,
        Func<bool>? pairLives = null,
        CancellationToken? pairGone = null)
    {
        var time = clock ?? (manualClock ? new ManualTimeProvider() : TimeProvider.System);
        var registry = new LocalRpcBrokerRegistry(limits, time);
        var maps = Enumerable.Range(0, slots).Select(_ => new MemoryMapping(slotBytes)).ToArray();
        var ends = new List<LocalRpcBrokerEnd>();
        var result = registry.CreateSession(new LocalRpcBrokerSessionOptions
        {
            InvocationId = Invocation,
            LeaseId = Lease,
            Generation = GenerationValue,
            Slots = maps,
            PairGone = pairGone ?? default,
            PairLives = pairLives,
            FirstSequence = firstSequence,
            Ended = end =>
            {
                lock (ends)
                {
                    ends.Add(end);
                }
            },
        });
        Assert.True(result.IsSuccess);
        return new BrokerRig(registry, result.Value!, maps, time, ends);
    }

    /// <summary>The bytes of a recognisable test pattern.</summary>
    internal static byte[] Pattern(int length, byte seed = 1)
    {
        var bytes = new byte[length];
        for (var index = 0; index < length; index++)
        {
            bytes[index] = unchecked((byte)((index * 31) + seed));
        }

        return bytes;
    }

    /// <summary>What an honest helper returns for <paramref name="grant"/> after writing <paramref name="content"/> at <paramref name="offset"/>.</summary>
    internal LocalRpcBufferSeal HonestSeal(LocalRpcSlotGrant grant, byte[] content, ulong offset = 0, ulong rowStride = 0)
    {
        content.CopyTo(Maps[grant.SlotId].Bytes.AsSpan((int)offset));
        return new LocalRpcBufferSeal(Invocation, Lease, GenerationValue, grant.SlotId, grant.Sequence, offset, (ulong)content.Length, LocalRpcDigest.Compute(content), rowStride);
    }

    /// <summary>Grants a slot and seals it honestly, as the helper would.</summary>
    internal (LocalRpcSlotGrant Grant, LocalRpcBufferSeal Seal, byte[] Content) GrantAndSeal(uint slot, int length, ulong capacity = 0, byte seed = 1)
    {
        var grant = Session.Grant(slot, capacity == 0 ? (ulong)Maps[slot].Bytes.Length : capacity).Value!;
        var content = Pattern(length, seed);
        var seal = HonestSeal(grant, content);
        Assert.Equal(LocalRpcBrokerRefusal.None, Session.Seal(seal));
        return (grant, seal, content);
    }

    public void Dispose()
    {
        Session.Dispose();
        Registry.Dispose();
    }

    internal static byte[] Sha256(ReadOnlySpan<byte> data) => SHA256.HashData(data);
}

/// <summary>
/// A clock a test moves by hand whose timers never fire, so only the lazy expiry checks of the broker can notice that time
/// has passed (a real timer that is late looks exactly like this).
/// </summary>
internal sealed class FrozenTimerClock : TimeProvider
{
    private long _ticks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp() => Interlocked.Read(ref _ticks);

    public override DateTimeOffset GetUtcNow() => new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).AddTicks(Interlocked.Read(ref _ticks));

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) => new InertTimer();

    internal void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);

    private sealed class InertTimer : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => true;

        public void Dispose()
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
