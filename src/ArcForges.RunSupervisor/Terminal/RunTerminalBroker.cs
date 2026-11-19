// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.RunSupervisor;

/// <summary>Exclusive terminal authority and transient acknowledgments for one live owner.</summary>
internal sealed class RunTerminalBroker(string epoch, RunTerminalMode mode)
{
    private const int MaxFrameBytes = 64 * 1024;
    private const int MaxAcknowledgments = 256;
    private const int MaxObservers = 64;
    private static readonly TimeSpan s_window = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan s_nativeBudget = TimeSpan.FromSeconds(8);
    private static readonly TimeProvider s_clock = TimeProvider.System;
    private static readonly RunTerminalReply s_pending = new(RunTerminalStatus.Pending);
    private static readonly RunTerminalReply s_unavailable = new(RunTerminalStatus.AckUnavailable);

    private readonly Lock _gate = new();
    private readonly Dictionary<string, Attachment> _observers = new(StringComparer.Ordinal);
    private readonly Queue<Attachment> _retiredWriters = new();
    private readonly LinkedList<Acknowledgment> _acknowledgments = new();
    private readonly Dictionary<string, LinkedListNode<Acknowledgment>> _byCommand = new(StringComparer.Ordinal);
    // Non-sequenced Acquire needs a bounded, fail-closed rejection of forgotten exact retries. The filter
    // retains neither request data nor results. A false positive only refuses a new attachment.
    private readonly ulong[] _seen = new ulong[4096];
    private Attachment? _writer;
    private IRunWorkerSession? _session;
    private NativeOperation? _nativePending;
    private ulong _generation;
    private bool _stdinClosed;
    private bool _retired;

    internal void Bind(IRunWorkerSession session)
    {
        lock (_gate)
        {
            if (!_retired)
            {
                _session = session;
            }
        }
    }

    internal void RevokeAll()
    {
        lock (_gate)
        {
            _retired = true;
            _session = null;
            if (_writer is { } writer)
            {
                RemoveAttachment(writer);
            }

            _observers.Clear();
            while (_acknowledgments.First is { } first)
            {
                Remove(first);
            }
        }
    }

    internal void Tick()
    {
        lock (_gate)
        {
            Expire(s_clock.GetTimestamp());
        }
    }

    internal RunTerminalReply Begin(RunTerminalRequest request)
    {
        if (!Valid(request))
        {
            return new(RunTerminalStatus.InvalidArgument);
        }

        lock (_gate)
        {
            var now = s_clock.GetTimestamp();
            Expire(now);
            if (request.Action == RunTerminalAction.Revoke)
            {
                Revoke(request.Caller);
                return new(RunTerminalStatus.Ok);
            }

            if (Seen('c', request.Caller.ConnectionId))
            {
                return s_unavailable;
            }

            if (_byCommand.TryGetValue(request.CommandId, out var prior))
            {
                return Matches(prior.Value, request)
                    ? prior.Value.Reply
                    : new(RunTerminalStatus.CommandIdReused);
            }

            if (request.Action == RunTerminalAction.Acquire)
            {
                if (Seen('a', request.CommandId))
                {
                    return s_unavailable;
                }

                var result = Acquire(request, now);
                Remember(request, result, now, result.Lease?.LeaseId);
                _ = Seen('a', request.CommandId, remember: true);
                return result;
            }

            if (request.Action == RunTerminalAction.Detach && Seen('d', request.CommandId))
            {
                return s_unavailable;
            }

            var lease = request.Lease!;
            var attachment = Find(lease.LeaseId);
            if (attachment is null || !attachment.EqualsAuthority(request.Caller, lease))
            {
                return Stale(request, lease);
            }

            if (request.Action == RunTerminalAction.Detach)
            {
                RemoveAttachment(attachment);
                var detached = new RunTerminalReply(RunTerminalStatus.Ok);
                // Detach can be acknowledged briefly after release, but cannot restore the removed authority.
                Remember(request, detached, now, leaseExpiry: attachment.RenewedAt);
                _ = Seen('d', request.CommandId, remember: true);
                return detached;
            }

            if (attachment.Mode != RunTerminalLeaseMode.Writer)
            {
                return new(RunTerminalStatus.LeaseStale);
            }

            return BeginNative(request, attachment, now);
        }
    }

    internal RunTerminalReply Poll(RunTerminalPoll poll)
    {
        if (!ValidCaller(poll.Caller) || !ValidId(poll.CommandId))
        {
            return new(RunTerminalStatus.InvalidArgument);
        }

        lock (_gate)
        {
            Expire(s_clock.GetTimestamp());
            return _byCommand.TryGetValue(poll.CommandId, out var found) && found.Value.Intent.Caller == poll.Caller
                ? found.Value.Reply
                : s_unavailable;
        }
    }

    private RunTerminalReply Acquire(RunTerminalRequest request, long now)
    {
        if (_session is null)
        {
            return new(RunTerminalStatus.TerminalUnavailable);
        }

        var leaseMode = request.Mode!.Value;
        var expiresAt = s_clock.GetUtcNow() + s_window;
        if (request.ExistingLeaseId is { } existing)
        {
            var current = Find(existing);
            if (current is null || current.Caller != request.Caller || current.Mode != leaseMode)
            {
                return new(RunTerminalStatus.LeaseStale);
            }

            current.RenewedAt = now;
            current.ExpiresAt = expiresAt;
            return new(RunTerminalStatus.Ok, current.Project());
        }

        if (leaseMode == RunTerminalLeaseMode.Writer && _writer is { } writer)
        {
            if (!request.Takeover)
            {
                return new(RunTerminalStatus.Busy);
            }

            RemoveAttachment(writer);
        }
        else if (leaseMode == RunTerminalLeaseMode.Observer && _observers.Count >= MaxObservers)
        {
            return new(RunTerminalStatus.Busy);
        }

        var attachment = new Attachment(request.Caller, Guid.NewGuid().ToString("N"), epoch,
            checked(++_generation), leaseMode, now, expiresAt);
        if (leaseMode == RunTerminalLeaseMode.Writer)
        {
            _writer = attachment;
        }
        else
        {
            _observers.Add(attachment.Id, attachment);
        }

        return new(RunTerminalStatus.Ok, attachment.Project());
    }

    private RunTerminalReply BeginNative(RunTerminalRequest request, Attachment writer, long now)
    {
        var highWater = writer.Consumed(request.Action);
        if (request.Sequence <= highWater)
        {
            // A missing slot never makes an already-consumed sequence eligible for another native effect.
            var sequenceRetained = _acknowledgments.Any(ack => ack.Authority == writer.Id
                && ack.Intent.Action == request.Action && ack.Intent.Sequence == request.Sequence);
            return sequenceRetained ? new(RunTerminalStatus.CommandIdReused) : s_unavailable;
        }

        if (request.Action == RunTerminalAction.Write && request.Sequence - highWater != 1)
        {
            return new(RunTerminalStatus.InvalidArgument);
        }

        if (_session is not { } session)
        {
            return new(RunTerminalStatus.TerminalUnavailable);
        }

        if (request.CloseStdin && mode != RunTerminalMode.Pipes
            || request.Action == RunTerminalAction.Resize && mode != RunTerminalMode.Interactive)
        {
            return new(RunTerminalStatus.Unsupported);
        }

        if (request.Action == RunTerminalAction.Write && _stdinClosed)
        {
            return new(RunTerminalStatus.TerminalUnavailable);
        }

        if (_nativePending is not null)
        {
            // Keep the fence even if a timed-out observer has already received UNKNOWN.
            return new(RunTerminalStatus.Busy);
        }

        var input = request.Input?.ToArray();
        var acknowledgment = Remember(request, s_pending, now, writer.Id);
        writer.Consume(request.Action, request.Sequence);
        var budget = s_nativeBudget - s_clock.GetElapsedTime(now);
        var operation = new NativeOperation(acknowledgment, new CancellationTokenSource(budget > TimeSpan.Zero ? budget : TimeSpan.Zero));
        _nativePending = operation;
        _ = Task.Run(() => InvokeNativeAsync(session, operation, input));
        return s_pending;
    }

    private async Task InvokeNativeAsync(IRunWorkerSession session, NativeOperation operation, byte[]? input)
    {
        var acknowledgment = operation.Acknowledgment;
        var result = s_unavailable;
        try
        {
            lock (_gate)
            {
                Expire(s_clock.GetTimestamp());
                if (_writer?.Id != acknowledgment.Authority || _session != session
                    || operation.Cancellation.IsCancellationRequested)
                {
                    return;
                }
            }

            var intent = acknowledgment.Intent;
            var token = operation.Cancellation.Token;
            if (intent.Action == RunTerminalAction.Resize)
            {
                await session.ResizeTerminalAsync(intent.Rows, intent.Columns, token).ConfigureAwait(false);
                result = new(RunTerminalStatus.Ok, Rows: intent.Rows, Columns: intent.Columns);
            }
            else if (intent.CloseStdin)
            {
                await session.CloseTerminalInputAsync(token).ConfigureAwait(false);
                result = new(RunTerminalStatus.Ok, AcceptedBytes: 0);
            }
            else
            {
                var accepted = await session.WriteTerminalAsync(input!, token).ConfigureAwait(false);
                if (accepted >= 0 && accepted <= input!.Length)
                {
                    result = new(RunTerminalStatus.Ok, AcceptedBytes: accepted);
                }
            }
        }
#pragma warning disable CA1031 // Native callback exceptions may follow a partial effect and must settle the single-writer fence.
        catch (Exception)
        {
            // No exception text, native input bytes or partial byte claims leave the broker.
        }
#pragma warning restore CA1031
        finally
        {
            if (input is not null)
            {
                CryptographicOperations.ZeroMemory(input);
            }

            Task? revocation;
            lock (_gate)
            {
                if (acknowledgment.Intent.CloseStdin && result.Status == RunTerminalStatus.Ok)
                {
                    _stdinClosed = true;
                }

                if (acknowledgment.Reply.Status == RunTerminalStatus.Pending)
                {
                    acknowledgment.Reply = s_clock.GetElapsedTime(acknowledgment.Created) < s_nativeBudget
                        ? result
                        : s_unavailable;
                }

                _nativePending = null;
                revocation = operation.Revocation;
            }

            try
            {
                if (revocation is not null)
                {
                    await revocation.ConfigureAwait(false);
                }
            }
            catch (AggregateException)
            {
                // A cancellation callback cannot establish a successful terminal effect.
            }
            finally
            {
                operation.Cancellation.Dispose();
            }
        }
    }

    private void Expire(long now)
    {
        if (_writer is { } writer && s_clock.GetElapsedTime(writer.RenewedAt, now) >= s_window)
        {
            RemoveAttachment(writer);
        }

        foreach (var (_, observer) in _observers)
        {
            if (s_clock.GetElapsedTime(observer.RenewedAt, now) >= s_window)
            {
                RemoveAttachment(observer);
            }
        }

        var node = _acknowledgments.First;
        while (node is not null)
        {
            var next = node.Next;
            var ack = node.Value;
            if (s_clock.GetElapsedTime(ack.Created, now) >= s_window
                || ack.LeaseExpiry is { } lease && s_clock.GetElapsedTime(lease, now) >= s_window)
            {
                Remove(node);
            }

            node = next;
        }

        if (_nativePending is { Acknowledgment.Reply.Status: RunTerminalStatus.Pending } pending
            && s_clock.GetElapsedTime(pending.Acknowledgment.Created, now) >= s_nativeBudget)
        {
            CancelNative(pending);
        }
    }

    private void Revoke(RunTerminalCaller caller)
    {
        _ = Seen('c', caller.ConnectionId, remember: true);
        if (_writer is { } writer && writer.Caller == caller)
        {
            RemoveAttachment(writer);
        }

        foreach (var (_, observer) in _observers)
        {
            if (observer.Caller == caller)
            {
                RemoveAttachment(observer);
            }
        }

        RemoveWhere(ack => ack.Intent.Caller == caller);
    }

    private Attachment? Find(string id) => _writer?.Id == id ? _writer : _observers.GetValueOrDefault(id);

    private RunTerminalReply Stale(RunTerminalRequest request, RunTerminalLease lease)
    {
        if (request.Action is RunTerminalAction.Write or RunTerminalAction.Resize)
        {
            foreach (var retired in _retiredWriters)
            {
                if (retired.EqualsAuthority(request.Caller, lease))
                {
                    return request.Sequence <= retired.Consumed(request.Action)
                        ? s_unavailable
                        : new(RunTerminalStatus.LeaseStale);
                }
            }

            if (lease.RunEpoch == epoch && lease.Generation < _generation && Seen('r', lease.LeaseId))
            {
                return s_unavailable;
            }
        }

        return _retired ? s_unavailable : new(RunTerminalStatus.LeaseStale);
    }

    private void RemoveAttachment(Attachment attachment)
    {
        if (attachment == _writer)
        {
            _writer = null;
            if (_nativePending is { } pending && pending.Acknowledgment.Authority == attachment.Id)
            {
                CancelNative(pending);
            }

            if (attachment.Consumed(RunTerminalAction.Write) > 0 || attachment.Consumed(RunTerminalAction.Resize) > 0)
            {
                _ = Seen('r', attachment.Id, remember: true);
            }

            _retiredWriters.Enqueue(attachment);
            if (_retiredWriters.Count > 64)
            {
                _ = _retiredWriters.Dequeue();
            }
        }
        else
        {
            _ = _observers.Remove(attachment.Id);
        }

        RemoveWhere(ack => ack.Authority == attachment.Id);
    }

    private static void CancelNative(NativeOperation pending)
    {
        pending.Acknowledgment.Reply = s_unavailable;
        pending.Revocation ??= pending.Cancellation.CancelAsync();
    }

    private Acknowledgment Remember(RunTerminalRequest request, RunTerminalReply reply, long now,
        string? authority = null, long? leaseExpiry = null)
    {
        if (_acknowledgments.Count >= MaxAcknowledgments)
        {
            Remove(_acknowledgments.First!);
        }

        // 256 fixed-size digests (8 KiB total), bounded identity fields and one <=64 KiB pending
        // native buffer stay below the 1 MiB aggregate volatile acknowledgment budget.
        var ack = new Acknowledgment(IntentOf(request), request.Input is { } input ? SHA256.HashData(input) : null,
            now, authority, leaseExpiry, reply);
        _byCommand.Add(request.CommandId, _acknowledgments.AddLast(ack));
        return ack;
    }

    private void RemoveWhere(Predicate<Acknowledgment> discard)
    {
        var node = _acknowledgments.First;
        while (node is not null)
        {
            var next = node.Next;
            if (discard(node.Value))
            {
                Remove(node);
            }

            node = next;
        }
    }

    private void Remove(LinkedListNode<Acknowledgment> node)
    {
        _ = _byCommand.Remove(node.Value.Intent.CommandId);
        _acknowledgments.Remove(node);
        if (node.Value.InputDigest is { } digest)
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private bool Seen(char domain, string identity, bool remember = false)
    {
        Span<byte> digest = stackalloc byte[32];
        _ = SHA256.HashData(Encoding.UTF8.GetBytes(domain + identity), digest);
        var found = true;
        for (var index = 0; index < 4; index++)
        {
            var bit = (int)(BinaryPrimitives.ReadUInt32LittleEndian(digest[(index * 4)..]) % (_seen.Length * 64u));
            var mask = 1UL << (bit % 64);
            ref var word = ref _seen[bit / 64];
            found &= (word & mask) != 0;
            if (remember)
            {
                word |= mask;
            }
        }

        return found;
    }

    private static bool Matches(Acknowledgment ack, RunTerminalRequest request)
    {
        if (ack.Intent != IntentOf(request))
        {
            return false;
        }

        if (ack.InputDigest is not { } expected || request.Input is not { } input)
        {
            return ack.InputDigest is null && request.Input is null;
        }

        Span<byte> digest = stackalloc byte[32];
        _ = SHA256.HashData(input, digest);
        var matches = CryptographicOperations.FixedTimeEquals(expected, digest);
        CryptographicOperations.ZeroMemory(digest);
        return matches;
    }

    private static RunTerminalRequest IntentOf(RunTerminalRequest request) => request with
    {
        Input = null,
        Lease = request.Lease is { } lease
            ? lease with { ExpiresAt = default, LastInputSequence = 0, LastResizeSequence = 0 }
            : null,
    };

    private static bool Valid(RunTerminalRequest request)
    {
        if (!ValidCaller(request.Caller)
            || (request.Action == RunTerminalAction.Revoke ? request.CommandId != string.Empty : !ValidId(request.CommandId)))
        {
            return false;
        }

        if (request.Action is RunTerminalAction.Acquire or RunTerminalAction.Revoke)
        {
            if (request.Lease is not null || request.Sequence != 0 || request.Input is not null || request.CloseStdin
                || request.Rows != 0 || request.Columns != 0)
            {
                return false;
            }

            return request.Action == RunTerminalAction.Acquire
                ? request.Mode is RunTerminalLeaseMode.Writer or RunTerminalLeaseMode.Observer
                    && (request.ExistingLeaseId is null || ValidId(request.ExistingLeaseId))
                    && (!request.Takeover || request.Mode == RunTerminalLeaseMode.Writer && request.ExistingLeaseId is null)
                : request.Mode is null && request.ExistingLeaseId is null && !request.Takeover;
        }

        if (request.Mode is not null || request.ExistingLeaseId is not null || request.Takeover || !ValidLease(request.Lease))
        {
            return false;
        }

        return request.Action switch
        {
            RunTerminalAction.Write => request.Sequence != 0 && request.Rows == 0 && request.Columns == 0
                && (request.CloseStdin ? request.Input is null : request.Input is { Length: > 0 and <= MaxFrameBytes }),
            RunTerminalAction.Resize => request.Sequence != 0 && request.Input is null && !request.CloseStdin
                && request.Rows is >= 1 and <= 32767 && request.Columns is >= 1 and <= 32767,
            RunTerminalAction.Detach => request.Sequence == 0 && request.Input is null
                && !request.CloseStdin && request.Rows == 0 && request.Columns == 0,
            _ => false,
        };
    }

    private static bool ValidCaller(RunTerminalCaller? caller) =>
        caller is { ProcessId: > 0, ProcessStartTicks: > 0, ConnectionId.Length: > 0 and <= 128 };

    private static bool ValidLease(RunTerminalLease? lease) =>
        lease is { Generation: > 0, Mode: RunTerminalLeaseMode.Observer or RunTerminalLeaseMode.Writer }
        && ValidId(lease.LeaseId) && ValidId(lease.RunEpoch);

    private static bool ValidId(string? value) => value is { Length: 32 } && value.All(char.IsAsciiHexDigitLower);

    private sealed class Attachment(RunTerminalCaller caller, string id, string runEpoch, ulong generation,
        RunTerminalLeaseMode mode, long renewedAt, DateTimeOffset expiresAt)
    {
        internal RunTerminalCaller Caller { get; } = caller;
        internal string Id { get; } = id;
        internal RunTerminalLeaseMode Mode { get; } = mode;
        internal long RenewedAt { get; set; } = renewedAt;
        internal DateTimeOffset ExpiresAt { get; set; } = expiresAt;
        private ulong _input;
        private ulong _resize;

        internal RunTerminalLease Project() => new(Id, runEpoch, generation, Mode, ExpiresAt, _input, _resize);

        internal bool EqualsAuthority(RunTerminalCaller peer, RunTerminalLease lease) =>
            peer == Caller && lease.LeaseId == Id && lease.RunEpoch == runEpoch && lease.Generation == generation && lease.Mode == Mode;

        internal ulong Consumed(RunTerminalAction action) => action == RunTerminalAction.Write ? _input : _resize;

        internal void Consume(RunTerminalAction action, ulong sequence)
        {
            if (action == RunTerminalAction.Write)
            {
                _input = sequence;
            }
            else
            {
                _resize = sequence;
            }
        }
    }

    private sealed record Acknowledgment(RunTerminalRequest Intent, byte[]? InputDigest, long Created, string? Authority,
        long? LeaseExpiry, RunTerminalReply Initial)
    {
        internal RunTerminalReply Reply { get; set; } = Initial;
    }

    private sealed record NativeOperation(Acknowledgment Acknowledgment, CancellationTokenSource Cancellation)
    {
        internal Task? Revocation { get; set; }
    }
}
