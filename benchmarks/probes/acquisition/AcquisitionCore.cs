// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;

namespace ArcForges.AcquisitionProbe;

internal readonly record struct AcquisitionSample(long Sequence, long TimestampTicks, double Value);

internal enum AcquisitionGapReason
{
    RingOverrun,
    TransportDisconnect,
    SequenceDiscontinuity,
    PartialFrame
}

internal sealed record AcquisitionGap(
    AcquisitionGapReason Reason,
    long FirstMissingSequence,
    long? EndExclusiveSequence,
    long MissingSamples,
    long ObservedTimestampTicks,
    bool IsOpen);

internal sealed class BoundedGapJournal
{
    private const int Capacity = 64;
    private readonly AcquisitionGap?[] _entries = new AcquisitionGap[Capacity];
    private int _count;

    public long SuppressedEntries { get; private set; }

    public IReadOnlyList<AcquisitionGap> Snapshot()
    {
        AcquisitionGap[] entries = new AcquisitionGap[_count];
        for (int index = 0; index < _count; index++)
        {
            entries[index] = _entries[index]!;
        }

        return entries;
    }

    public void Add(AcquisitionGap gap)
    {
        if (_count > 0)
        {
            AcquisitionGap previous = _entries[_count - 1]!;
            if (previous.Reason == gap.Reason
                && previous.EndExclusiveSequence == gap.FirstMissingSequence
                && !previous.IsOpen
                && !gap.IsOpen)
            {
                _entries[_count - 1] = previous with
                {
                    EndExclusiveSequence = gap.EndExclusiveSequence,
                    MissingSamples = checked(previous.MissingSamples + gap.MissingSamples),
                    ObservedTimestampTicks = gap.ObservedTimestampTicks
                };
                return;
            }
        }

        if (_count < Capacity)
        {
            _entries[_count++] = gap;
            return;
        }

        SuppressedEntries++;
    }

    public void CloseOpenTransportGap(long resumedAtSequence, long timestampTicks)
    {
        for (int index = _count - 1; index >= 0; index--)
        {
            AcquisitionGap gap = _entries[index]!;
            if (gap.Reason == AcquisitionGapReason.TransportDisconnect && gap.IsOpen)
            {
                long missingSamples = Math.Max(0, resumedAtSequence - gap.FirstMissingSequence);
                _entries[index] = gap with
                {
                    EndExclusiveSequence = resumedAtSequence,
                    MissingSamples = missingSamples,
                    ObservedTimestampTicks = timestampTicks,
                    IsOpen = false
                };
                return;
            }
        }
    }
}

internal sealed class SingleProducerSingleConsumerRing
{
    private sealed class Slot
    {
        public long Version;
        public AcquisitionSample Value;
    }

    private readonly Slot[] _slots;
    private long _head;
    private long _tail;

    public SingleProducerSingleConsumerRing(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);

        _slots = new Slot[capacity];
        for (int index = 0; index < capacity; index++)
        {
            _slots[index] = new Slot();
        }
    }

    public int Capacity => _slots.Length;

    public long CapacityBytes => (long)_slots.Length * (sizeof(long) + 24 + 16 + IntPtr.Size);

    public long BufferedCount => Math.Max(0, Volatile.Read(ref _head) - Volatile.Read(ref _tail));

    public bool TryWrite(AcquisitionSample sample)
    {
        long head = Volatile.Read(ref _head);
        long tail = Volatile.Read(ref _tail);
        if (head - tail >= _slots.Length)
        {
            return false;
        }

        Slot slot = _slots[(int)(head % _slots.Length)];
        Volatile.Write(ref slot.Version, checked((head * 2) + 1));
        slot.Value = sample;
        Volatile.Write(ref slot.Version, checked((head * 2) + 2));
        Volatile.Write(ref _head, head + 1);
        return true;
    }

    public bool TryRead(out AcquisitionSample sample)
    {
        long tail = Volatile.Read(ref _tail);
        long head = Volatile.Read(ref _head);
        if (tail >= head)
        {
            sample = default;
            return false;
        }

        Slot slot = _slots[(int)(tail % _slots.Length)];
        long expectedVersion = checked((tail * 2) + 2);
        long versionBefore = Volatile.Read(ref slot.Version);
        if (versionBefore != expectedVersion || (versionBefore & 1) != 0)
        {
            sample = default;
            return false;
        }

        AcquisitionSample candidate = slot.Value;
        long versionAfter = Volatile.Read(ref slot.Version);
        if (versionAfter != versionBefore)
        {
            sample = default;
            return false;
        }

        sample = candidate;
        Volatile.Write(ref _tail, tail + 1);
        return true;
    }

    public AcquisitionSample[] CopyBuffered(int maximumSamples)
    {
        if (maximumSamples <= 0)
        {
            return [];
        }

        long head = Volatile.Read(ref _head);
        long tail = Volatile.Read(ref _tail);
        long start = Math.Max(tail, head - Math.Min(maximumSamples, _slots.Length));
        List<AcquisitionSample> samples = new((int)Math.Max(0, head - start));
        for (long sequence = start; sequence < head; sequence++)
        {
            Slot slot = _slots[(int)(sequence % _slots.Length)];
            long expectedVersion = checked((sequence * 2) + 2);
            long versionBefore = Volatile.Read(ref slot.Version);
            if (versionBefore != expectedVersion || (versionBefore & 1) != 0)
            {
                continue;
            }

            AcquisitionSample candidate = slot.Value;
            long versionAfter = Volatile.Read(ref slot.Version);
            if (versionBefore == versionAfter)
            {
                samples.Add(candidate);
            }
        }

        return [.. samples];
    }
}

internal sealed class AcquisitionSession
{
    private readonly BoundedGapJournal _gaps = new();
    private long? _expectedSequence;

    public AcquisitionSession(int ringCapacity)
    {
        Ring = new SingleProducerSingleConsumerRing(ringCapacity);
    }

    public SingleProducerSingleConsumerRing Ring { get; }

    public long SamplesReceived { get; private set; }

    public long SamplesQueued { get; private set; }

    public long DroppedSamples { get; private set; }

    public long LastDropObservedTimestampTicks { get; private set; }

    public bool IsOpen { get; private set; } = true;

    public IReadOnlyList<AcquisitionGap> Gaps => _gaps.Snapshot();

    public long SuppressedGapEntries => _gaps.SuppressedEntries;

    public bool Accept(AcquisitionSample sample)
    {
        if (!IsOpen)
        {
            throw new InvalidOperationException("Cannot accept samples after the recording session is closed.");
        }

        if (_expectedSequence is long expected)
        {
            _gaps.CloseOpenTransportGap(sample.Sequence, Stopwatch.GetTimestamp());
            if (sample.Sequence > expected)
            {
                long now = Stopwatch.GetTimestamp();
                _gaps.Add(new AcquisitionGap(
                    AcquisitionGapReason.SequenceDiscontinuity,
                    expected,
                    sample.Sequence,
                    sample.Sequence - expected,
                    now,
                    false));
            }
            else if (sample.Sequence < expected)
            {
                throw new InvalidDataException($"Sample sequence regressed from {expected} to {sample.Sequence}.");
            }
        }

        _expectedSequence = checked(sample.Sequence + 1);
        SamplesReceived++;
        if (!Ring.TryWrite(sample))
        {
            long now = Stopwatch.GetTimestamp();
            DroppedSamples++;
            LastDropObservedTimestampTicks = now;
            _gaps.Add(new AcquisitionGap(
                AcquisitionGapReason.RingOverrun,
                sample.Sequence,
                checked(sample.Sequence + 1),
                1,
                now,
                false));
            return false;
        }

        SamplesQueued++;
        return true;
    }

    public void MarkTransportDisconnected()
    {
        if (!IsOpen)
        {
            return;
        }

        long firstMissing = _expectedSequence ?? 0;
        _gaps.Add(new AcquisitionGap(
            AcquisitionGapReason.TransportDisconnect,
            firstMissing,
            null,
            0,
            Stopwatch.GetTimestamp(),
            true));
    }

    public void MarkPartialFrame()
    {
        long firstMissing = _expectedSequence ?? 0;
        _gaps.Add(new AcquisitionGap(
            AcquisitionGapReason.PartialFrame,
            firstMissing,
            null,
            0,
            Stopwatch.GetTimestamp(),
            true));
    }

    public void Close()
    {
        IsOpen = false;
    }

    public IReadOnlyList<AcquisitionGap> GapSnapshot() => _gaps.Snapshot();
}

internal sealed class CaptureSink
{
    private long _samplesCommitted;
    private long _checksum;
    private long _lastSequence = -1;

    public long SamplesCommitted => Interlocked.Read(ref _samplesCommitted);

    public long Checksum => Interlocked.Read(ref _checksum);

    public long LastSequence => Interlocked.Read(ref _lastSequence);

    public bool DrainOne(SingleProducerSingleConsumerRing ring)
    {
        if (!ring.TryRead(out AcquisitionSample sample))
        {
            return false;
        }

        Interlocked.Increment(ref _samplesCommitted);
        Interlocked.Exchange(ref _lastSequence, sample.Sequence);
        long previousChecksum = Interlocked.Read(ref _checksum);
        Interlocked.Exchange(ref _checksum, unchecked((previousChecksum * 31) + sample.Sequence + BitConverter.DoubleToInt64Bits(sample.Value)));
        return true;
    }

    public void Drain(SingleProducerSingleConsumerRing ring)
    {
        while (DrainOne(ring))
        {
        }
    }
}

internal readonly record struct PlotPoint(long FirstSequence, long LastSequence, double Minimum, double Maximum);

internal static class MinMaxDownsampler
{
    public static PlotPoint[] Downsample(ReadOnlySpan<AcquisitionSample> samples, int maximumPoints)
    {
        if (maximumPoints <= 0 || samples.IsEmpty)
        {
            return [];
        }

        if (samples.Length <= maximumPoints)
        {
            PlotPoint[] exact = new PlotPoint[samples.Length];
            for (int index = 0; index < samples.Length; index++)
            {
                AcquisitionSample sample = samples[index];
                exact[index] = new PlotPoint(sample.Sequence, sample.Sequence, sample.Value, sample.Value);
            }

            return exact;
        }

        int bucketCount = Math.Max(1, maximumPoints / 2);
        PlotPoint[] output = new PlotPoint[Math.Min(maximumPoints, bucketCount * 2)];
        int outputCount = 0;
        for (int bucket = 0; bucket < bucketCount; bucket++)
        {
            int start = (int)((long)bucket * samples.Length / bucketCount);
            int end = (int)((long)(bucket + 1) * samples.Length / bucketCount);
            if (end <= start)
            {
                continue;
            }

            AcquisitionSample minimum = samples[start];
            AcquisitionSample maximum = samples[start];
            for (int index = start + 1; index < end; index++)
            {
                if (samples[index].Value < minimum.Value)
                {
                    minimum = samples[index];
                }

                if (samples[index].Value > maximum.Value)
                {
                    maximum = samples[index];
                }
            }

            if (minimum.Sequence <= maximum.Sequence)
            {
                output[outputCount++] = new PlotPoint(minimum.Sequence, maximum.Sequence, minimum.Value, maximum.Value);
            }
            else
            {
                output[outputCount++] = new PlotPoint(maximum.Sequence, minimum.Sequence, minimum.Value, maximum.Value);
            }
        }

        return outputCount == output.Length ? output : output[..outputCount];
    }
}

internal sealed class LiveAcquisitionView
{
    public bool IsPaused { get; private set; }

    public long RenderCount { get; private set; }

    public void Pause() => IsPaused = true;

    public void Resume() => IsPaused = false;

    public PlotPoint[] Render(SingleProducerSingleConsumerRing ring, int historySamples, int maximumPoints)
    {
        if (IsPaused)
        {
            return [];
        }

        RenderCount++;
        AcquisitionSample[] buffered = ring.CopyBuffered(historySamples);
        return MinMaxDownsampler.Downsample(buffered, maximumPoints);
    }
}
