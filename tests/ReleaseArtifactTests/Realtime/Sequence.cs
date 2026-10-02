// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Events.V1;
using ArcForges.Contracts.PublicApi.V1;
using Google.Protobuf;

namespace RealtimeAotProbe;

/// <summary>What the sequence tracker decided for one hint.</summary>
internal enum SequenceOutcome
{
    /// <summary>The hint is the baseline or exactly the next sequence: apply it.</summary>
    Apply,

    /// <summary>One or more sequences are missing before this hint: record, deliver, reconcile through the owner RPC.</summary>
    Gap,

    /// <summary>The hint repeats or precedes an applied sequence: discard it idempotently.</summary>
    Duplicate,

    /// <summary>A different hint claims an already applied sequence: an integrity failure.</summary>
    Conflict,
}

internal readonly record struct SequenceVerdict(SequenceOutcome Outcome, ulong Expected, ulong Actual);

/// <summary>The per-subscription sequence rules of realtime annex 03 section 3.</summary>
/// <remarks>
/// <c>seq == last + 1</c> applies, <c>seq &gt; last + 1</c> is a gap that is recorded and reconciled, and
/// <c>seq &lt;= last</c> is a duplicate that is discarded; a duplicate that differs from what was applied at
/// that sequence is a conflict (annex 10 section 5). The first hint after a start, snapshot or reset is the
/// baseline because the first Poll carries no start sequence (SB-03). Evaluation never mutates: the caller
/// accepts a hint only after delivering it, so a consumer that fails leaves the hint unapplied.
/// </remarks>
internal sealed class EventSequenceTracker
{
    internal const int ConflictWindow = 64;

    private readonly Queue<(ulong Sequence, ByteString Content)> _recent = new();

    /// <summary>The last applied sequence, or null before the baseline.</summary>
    public ulong? Last { get; private set; }

    /// <summary>The number of gaps recorded.</summary>
    public long Gaps { get; private set; }

    /// <summary>The number of duplicates discarded.</summary>
    public long Duplicates { get; private set; }

    public SequenceVerdict Evaluate(Event hint)
    {
        ArgumentNullException.ThrowIfNull(hint);
        ulong sequence = hint.Seq;
        if (Last is not ulong last)
        {
            return new SequenceVerdict(SequenceOutcome.Apply, sequence, sequence);
        }

        if (sequence > last)
        {
            ulong expected = last + 1;
            return new SequenceVerdict(sequence == expected ? SequenceOutcome.Apply : SequenceOutcome.Gap, expected, sequence);
        }

        ByteString content = hint.ToByteString();
        foreach ((ulong recentSequence, ByteString recentContent) in _recent)
        {
            if (recentSequence == sequence)
            {
                return new SequenceVerdict(recentContent.Equals(content) ? SequenceOutcome.Duplicate : SequenceOutcome.Conflict, last, sequence);
            }
        }

        return new SequenceVerdict(SequenceOutcome.Duplicate, last, sequence);
    }

    /// <summary>Record an applied or gap-delivered hint.</summary>
    public void Accept(Event hint, SequenceVerdict verdict)
    {
        ArgumentNullException.ThrowIfNull(hint);
        if (verdict.Outcome is not (SequenceOutcome.Apply or SequenceOutcome.Gap))
        {
            throw new InvalidOperationException("Only an applied or gap hint can be accepted.");
        }

        if (verdict.Outcome == SequenceOutcome.Gap)
        {
            Gaps++;
        }

        Last = hint.Seq;
        _recent.Enqueue((hint.Seq, hint.ToByteString()));
        while (_recent.Count > ConflictWindow)
        {
            _recent.Dequeue();
        }
    }

    public void RecordDuplicate() => Duplicates++;

    /// <summary>Forget the baseline after a snapshot or a reset.</summary>
    public void Reset()
    {
        Last = null;
        _recent.Clear();
    }
}

/// <summary>What the output tracker decided for one chunk.</summary>
internal enum OutputOutcome
{
    /// <summary>The chunk starts exactly at the next offset.</summary>
    Append,

    /// <summary>The chunk repeats an already received range identically.</summary>
    Duplicate,

    /// <summary>Bytes are missing before the chunk: read them through ReadOutput, never invent them.</summary>
    Gap,

    /// <summary>The chunk contradicts bytes already received at that offset: an integrity failure.</summary>
    Conflict,

    /// <summary>The chunk breaks a structural rule (owner, size, offset, binding).</summary>
    Violation,
}

internal readonly record struct OutputVerdict(OutputOutcome Outcome, ulong Expected, ulong Actual, string Detail);

/// <summary>The offset rules of the append-only output stream (annex 10 sections 2 and 5).</summary>
/// <remarks>
/// A chunk is bound to the execution owner it was requested for and, once the first chunk of an epoch is
/// accepted, to that chunk's attempt and stream identifiers; another attempt or stream arrives only through a
/// reset. The chunk hash is compared for equality only: its algorithm belongs to the Cloud producer and this
/// probe does not verify the bytes against it.
/// </remarks>
internal sealed class OutputTracker(ExecutionOwner owner, RealtimePolicy policy)
{
    internal const int ConflictWindow = 64;

    private readonly ExecutionOwner _owner = owner ?? throw new ArgumentNullException(nameof(owner));
    private readonly RealtimePolicy _policy = policy ?? throw new ArgumentNullException(nameof(policy));
    private readonly Queue<(ulong Offset, ByteString Data, string? Hash)> _recent = new();
    private ArcForges.Contracts.Foundation.V1.Id? _attempt;
    private ArcForges.Contracts.Foundation.V1.Id? _stream;
    private bool _bound;

    /// <summary>The offset the next appended chunk must start at.</summary>
    public ulong NextOffset { get; private set; }

    public long Duplicates { get; private set; }

    public long Gaps { get; private set; }

    public OutputVerdict Evaluate(OutputChunk chunk)
    {
        ArgumentNullException.ThrowIfNull(chunk);
        if (chunk.Execution is null || !chunk.Execution.Equals(_owner))
        {
            return new OutputVerdict(OutputOutcome.Violation, NextOffset, 0, "the chunk names another execution owner");
        }

        if (!chunk.HasOffset)
        {
            return new OutputVerdict(OutputOutcome.Violation, NextOffset, 0, "the chunk carries no offset");
        }

        ulong offset = chunk.Offset;
        int length = chunk.Data.Length;
        if (length > _policy.MaximumChunkBytes)
        {
            return new OutputVerdict(OutputOutcome.Violation, NextOffset, offset, "the chunk exceeds the frame data bound");
        }

        if (offset > ulong.MaxValue - (ulong)length)
        {
            return new OutputVerdict(OutputOutcome.Violation, NextOffset, offset, "the chunk range overflows the 64 bit offset");
        }

        if (_bound && (!Equals(chunk.AttemptId, _attempt) || !Equals(chunk.StreamId, _stream)))
        {
            return new OutputVerdict(OutputOutcome.Violation, NextOffset, offset, "the attempt or stream changed without a reset");
        }

        if (offset == NextOffset)
        {
            return new OutputVerdict(OutputOutcome.Append, NextOffset, offset, string.Empty);
        }

        if (offset > NextOffset)
        {
            return new OutputVerdict(OutputOutcome.Gap, NextOffset, offset, "bytes before the chunk were not received");
        }

        if (offset + (ulong)length > NextOffset)
        {
            return new OutputVerdict(OutputOutcome.Violation, NextOffset, offset, "the chunk straddles the end of the bytes already received");
        }

        foreach ((ulong recentOffset, ByteString data, string? hash) in _recent)
        {
            if (recentOffset == offset)
            {
                bool same = data.Equals(chunk.Data) && string.Equals(hash, chunk.HasChunkHash ? chunk.ChunkHash : null, StringComparison.Ordinal);
                return new OutputVerdict(same ? OutputOutcome.Duplicate : OutputOutcome.Conflict, NextOffset, offset,
                    same ? string.Empty : "different bytes or hash at an offset already received");
            }
        }

        return new OutputVerdict(OutputOutcome.Duplicate, NextOffset, offset, string.Empty);
    }

    public void Accept(OutputChunk chunk, OutputVerdict verdict)
    {
        ArgumentNullException.ThrowIfNull(chunk);
        if (verdict.Outcome != OutputOutcome.Append)
        {
            throw new InvalidOperationException("Only an appended chunk can be accepted.");
        }

        if (!_bound)
        {
            _attempt = chunk.AttemptId;
            _stream = chunk.StreamId;
            _bound = true;
        }

        NextOffset = chunk.Offset + (ulong)chunk.Data.Length;
        _recent.Enqueue((chunk.Offset, chunk.Data, chunk.HasChunkHash ? chunk.ChunkHash : null));
        while (_recent.Count > ConflictWindow)
        {
            _recent.Dequeue();
        }
    }

    public void RecordDuplicate() => Duplicates++;

    public void RecordGap() => Gaps++;

    /// <summary>Forget everything received: a reset, expiry or successor stream restarts the output.</summary>
    public void Reset()
    {
        NextOffset = 0;
        _attempt = null;
        _stream = null;
        _bound = false;
        _recent.Clear();
    }
}
