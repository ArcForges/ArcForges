// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace ArcForges.AcquisitionProbe;

internal sealed record SustainedRunEvidence(
    string Scenario,
    string Transport,
    string OperatingSystem,
    string Runtime,
    long ProbeTargetSamplesPerSecond,
    double SustainedTargetSeconds,
    long SamplesReceived,
    long SamplesCommitted,
    double ElapsedSeconds,
    double SamplesPerSecond,
    int RingCapacitySamples,
    long RingCapacityBytes,
    long ReceiveBufferBytes,
    long PeakWorkingSetBytes,
    long PeakManagedHeapBytes,
    long DroppedSamples,
    long LastDropObservedTimestampTicks,
    long CaptureChecksum,
    long DownsampleMaximumMilliseconds,
    bool DownsamplerPreservedSpike,
    long PausedViewSamplesCommitted,
    long DisconnectGapFirstMissingSequence,
    bool DisconnectGapRemainedOpen,
    bool RecordingRemainedOpenAfterDisconnect,
    string Command);

internal sealed class PeakMemorySampler : IAsyncDisposable
{
    private readonly Process _process = Process.GetCurrentProcess();
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _samplingTask;
    private long _peakWorkingSetBytes;
    private long _peakManagedHeapBytes;

    public PeakMemorySampler()
    {
        _samplingTask = Task.Run(SampleLoopAsync);
    }

    public long PeakWorkingSetBytes => Interlocked.Read(ref _peakWorkingSetBytes);

    public long PeakManagedHeapBytes => Interlocked.Read(ref _peakManagedHeapBytes);

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        await _samplingTask.ConfigureAwait(false);
        _stop.Dispose();
        _process.Dispose();
    }

    private async Task SampleLoopAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                _process.Refresh();
                UpdatePeak(ref _peakWorkingSetBytes, _process.WorkingSet64);
                UpdatePeak(ref _peakManagedHeapBytes, GC.GetTotalMemory(false));
                await Task.Delay(TimeSpan.FromMilliseconds(100), _stop.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
        }
    }

    private static void UpdatePeak(ref long peak, long candidate)
    {
        long previous;
        do
        {
            previous = Interlocked.Read(ref peak);
            if (candidate <= previous)
            {
                return;
            }
        }
        while (Interlocked.CompareExchange(ref peak, candidate, previous) != previous);
    }
}

internal static class TcpLoopbackScenarios
{
    private const int FrameSize = 24;
    private const int WireReadBufferBytes = 256 * 1024;
    private const int SustainedRingCapacity = 65_536;
    private const long ProbeTargetSamplesPerSecond = 1_000_000;
    private const int SustainedProducerSamplesPerSecond = 1_200_000;
    private const int SustainedSamples = 12_000_000;
    private const double SustainedTargetSeconds = 10;
    private const int ProducerBatchSamples = 65_536;

    public static async Task<SustainedRunEvidence> RunAcceptanceAsync(CancellationToken cancellationToken)
    {
        DownsampleEvidence downsampleEvidence = VerifyDownsampling();
        AcquisitionSession session = new(SustainedRingCapacity);
        CaptureSink sink = new();
        LiveAcquisitionView view = new();
        TcpListener listener = StartListener();
        PeakMemorySampler memory = new();
        long started = Stopwatch.GetTimestamp();

        Task<ReceiveEvidence> receiveTask = ReceiveAsync(
            listener,
            session,
            sink,
            expectedSamples: SustainedSamples,
            view,
            pauseAfterSamples: null,
            drainAfterEachRead: true,
            cancellationToken);

        SendEvidence sent = await SendSamplesAsync(
            (IPEndPoint)listener.LocalEndpoint,
            firstSequence: 0,
            sampleCount: SustainedSamples,
            targetSamplesPerSecond: SustainedProducerSamplesPerSecond,
            cancellationToken).ConfigureAwait(false);

        ReceiveEvidence received = await receiveTask.ConfigureAwait(false);
        double elapsedSeconds = Stopwatch.GetElapsedTime(started).TotalSeconds;
        listener.Stop();
        await memory.DisposeAsync().ConfigureAwait(false);

        if (sent.Samples != SustainedSamples || received.Samples != SustainedSamples)
        {
            throw new InvalidOperationException($"TCP sustained run sent {sent.Samples} and received {received.Samples} of {SustainedSamples} samples.");
        }

        if (elapsedSeconds < SustainedTargetSeconds)
        {
            throw new InvalidOperationException($"Sustained TCP traffic ran for only {elapsedSeconds:F2}s; required at least {SustainedTargetSeconds:F0}s.");
        }

        double samplesPerSecond = received.Samples / elapsedSeconds;
        if (samplesPerSecond < ProbeTargetSamplesPerSecond)
        {
            throw new InvalidOperationException($"TCP throughput {samplesPerSecond:N0} samples/s is below the probe-local floor of {ProbeTargetSamplesPerSecond:N0}.");
        }

        if (received.DroppedSamples != 0 || sink.SamplesCommitted != SustainedSamples)
        {
            throw new InvalidOperationException($"Sustained capture lost data: dropped={received.DroppedSamples}, committed={sink.SamplesCommitted}.");
        }

        if (session.Gaps.Count != 0)
        {
            throw new InvalidOperationException("The sustained TCP run recorded an unexpected sequence or transport gap.");
        }

        if (received.MaximumBufferedSamples > session.Ring.Capacity)
        {
            throw new InvalidOperationException("The ring buffer exceeded its fixed capacity.");
        }

        if (view.RenderCount == 0)
        {
            throw new InvalidOperationException("The live view did not render any downsampled frames during acquisition.");
        }

        if (!downsampleEvidence.PreservedSpike)
        {
            throw new InvalidOperationException("The min/max downsampler did not preserve a narrow signal spike.");
        }

        return new SustainedRunEvidence(
            "NAT.03 TCP loopback sustained scalar acquisition",
            "TCP over OS localhost sockets",
            RuntimeInformation.OSDescription,
            RuntimeInformation.FrameworkDescription,
            ProbeTargetSamplesPerSecond,
            SustainedTargetSeconds,
            received.Samples,
            sink.SamplesCommitted,
            elapsedSeconds,
            samplesPerSecond,
            session.Ring.Capacity,
            session.Ring.CapacityBytes,
            WireReadBufferBytes,
            memory.PeakWorkingSetBytes,
            memory.PeakManagedHeapBytes,
            received.DroppedSamples,
            received.LastDropObservedTimestampTicks,
            sink.Checksum,
            downsampleEvidence.MaximumMilliseconds,
            downsampleEvidence.PreservedSpike,
            PausedViewSamplesCommitted: 0,
            DisconnectGapFirstMissingSequence: 0,
            DisconnectGapRemainedOpen: false,
            RecordingRemainedOpenAfterDisconnect: false,
            "dotnet run --project benchmarks/probes/acquisition/AcquisitionProbe.csproj -c Release -- --self-test");
    }

    public static async Task<OverrunEvidence> RunOverrunAsync(CancellationToken cancellationToken)
    {
        const int ringCapacity = 4_096;
        const int sampleCount = 12_288;
        AcquisitionSession session = new(ringCapacity);
        CaptureSink sink = new();
        TcpListener listener = StartListener();
        Task<ReceiveEvidence> receiveTask = ReceiveAsync(
            listener,
            session,
            sink,
            expectedSamples: sampleCount,
            view: null,
            pauseAfterSamples: null,
            drainAfterEachRead: false,
            cancellationToken);

        await SendSamplesAsync(
            (IPEndPoint)listener.LocalEndpoint,
            firstSequence: 0,
            sampleCount,
            targetSamplesPerSecond: 10_000_000,
            cancellationToken).ConfigureAwait(false);

        ReceiveEvidence received = await receiveTask.ConfigureAwait(false);
        sink.Drain(session.Ring);
        listener.Stop();

        long expectedDrops = sampleCount - ringCapacity;
        if (received.Samples != sampleCount || received.DroppedSamples != expectedDrops || sink.SamplesCommitted != ringCapacity)
        {
            throw new InvalidOperationException($"Induced overrun did not account for every sample: received={received.Samples}, dropped={received.DroppedSamples}, retained={sink.SamplesCommitted}.");
        }

        AcquisitionGap? gap = session.GapSnapshot().SingleOrDefault(item => item.Reason == AcquisitionGapReason.RingOverrun);
        if (gap is null || gap.MissingSamples != expectedDrops || gap.EndExclusiveSequence is null || received.LastDropObservedTimestampTicks <= 0)
        {
            throw new InvalidOperationException("The ring overrun was not retained as an exact, timestamped sequence gap.");
        }

        return new OverrunEvidence(sampleCount, expectedDrops, gap.FirstMissingSequence, gap.EndExclusiveSequence.Value, received.LastDropObservedTimestampTicks, sink.SamplesCommitted, session.Ring.CapacityBytes);
    }

    public static async Task<DisconnectEvidence> RunDisconnectAsync(CancellationToken cancellationToken)
    {
        const int expectedSamples = 10_000;
        const int transmittedSamples = 5_000;
        AcquisitionSession session = new(8_192);
        CaptureSink sink = new();
        TcpListener listener = StartListener();
        Task<ReceiveEvidence> receiveTask = ReceiveAsync(
            listener,
            session,
            sink,
            expectedSamples,
            view: null,
            pauseAfterSamples: null,
            drainAfterEachRead: true,
            cancellationToken);

        await SendSamplesAsync(
            (IPEndPoint)listener.LocalEndpoint,
            firstSequence: 0,
            sampleCount: transmittedSamples,
            targetSamplesPerSecond: 10_000_000,
            cancellationToken).ConfigureAwait(false);

        ReceiveEvidence received = await receiveTask.ConfigureAwait(false);
        listener.Stop();

        AcquisitionGap? gap = session.GapSnapshot().SingleOrDefault(item => item.Reason == AcquisitionGapReason.TransportDisconnect);
        if (received.Samples != transmittedSamples || gap is null || !gap.IsOpen || gap.FirstMissingSequence != transmittedSamples || !session.IsOpen)
        {
            throw new InvalidOperationException("An induced premature TCP disconnect did not leave an open, explicit recording gap.");
        }

        return new DisconnectEvidence(received.Samples, gap.FirstMissingSequence, gap.ObservedTimestampTicks, gap.IsOpen, session.IsOpen, sink.SamplesCommitted);
    }

    public static async Task<PauseEvidence> RunPauseAsync(CancellationToken cancellationToken)
    {
        const int sampleCount = 50_000;
        AcquisitionSession session = new(8_192);
        CaptureSink sink = new();
        LiveAcquisitionView view = new();
        TcpListener listener = StartListener();
        Task<ReceiveEvidence> receiveTask = ReceiveAsync(
            listener,
            session,
            sink,
            sampleCount,
            view,
            pauseAfterSamples: 1,
            drainAfterEachRead: true,
            cancellationToken);

        await SendSamplesAsync(
            (IPEndPoint)listener.LocalEndpoint,
            firstSequence: 0,
            sampleCount,
            targetSamplesPerSecond: 10_000_000,
            cancellationToken).ConfigureAwait(false);

        ReceiveEvidence received = await receiveTask.ConfigureAwait(false);
        listener.Stop();

        long committedWhilePaused = received.SamplesCommittedWhilePaused;
        if (!view.IsPaused || received.Samples != sampleCount || committedWhilePaused <= 0 || sink.SamplesCommitted != sampleCount)
        {
            throw new InvalidOperationException($"Pausing the view interrupted capture: paused={view.IsPaused}, received={received.Samples}, committed-while-paused={committedWhilePaused}, committed={sink.SamplesCommitted}.");
        }

        return new PauseEvidence(received.Samples, committedWhilePaused, sink.SamplesCommitted, received.RenderCallsAfterPause, view.IsPaused);
    }

    private static DownsampleEvidence VerifyDownsampling()
    {
        const int sampleCount = 65_536;
        const int spikeIndex = 31_111;
        AcquisitionSample[] samples = new AcquisitionSample[sampleCount];
        for (int index = 0; index < samples.Length; index++)
        {
            samples[index] = new AcquisitionSample(index, index, index == spikeIndex ? 1000 : 0);
        }

        Stopwatch timer = Stopwatch.StartNew();
        PlotPoint[] output = MinMaxDownsampler.Downsample(samples, maximumPoints: 1_000);
        timer.Stop();
        bool preserved = output.Any(point => point.Maximum == 1000);
        if (output.Length > 1_000)
        {
            throw new InvalidOperationException($"Downsampling returned {output.Length} points for a 1,000-point display budget.");
        }

        if (timer.ElapsedMilliseconds > 250)
        {
            throw new InvalidOperationException($"Downsampling took {timer.ElapsedMilliseconds}ms for {sampleCount:N0} samples; the 250ms probe responsiveness budget was exceeded.");
        }

        return new DownsampleEvidence(timer.ElapsedMilliseconds, preserved);
    }

    private static async Task<ReceiveEvidence> ReceiveAsync(
        TcpListener listener,
        AcquisitionSession session,
        CaptureSink sink,
        int expectedSamples,
        LiveAcquisitionView? view,
        int? pauseAfterSamples,
        bool drainAfterEachRead,
        CancellationToken cancellationToken)
    {
        using TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
        client.NoDelay = true;
        using NetworkStream stream = client.GetStream();
        byte[] buffer = new byte[WireReadBufferBytes + FrameSize];
        int carry = 0;
        long receivedCount = 0;
        long maximumBuffered = 0;
        long committedWhilePaused = 0;
        long renderCallsAfterPause = 0;

        while (receivedCount < expectedSamples)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(carry, WireReadBufferBytes), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                if (carry > 0)
                {
                    session.MarkPartialFrame();
                }

                break;
            }

            int available = carry + read;
            int completeBytes = available - (available % FrameSize);
            for (int offset = 0; offset < completeBytes; offset += FrameSize)
            {
                AcquisitionSample sample = Decode(buffer.AsSpan(offset, FrameSize));
                session.Accept(sample);
                receivedCount++;

                if (pauseAfterSamples is int pauseThreshold && receivedCount >= pauseThreshold && view is not null && !view.IsPaused)
                {
                    view.Pause();
                }

            }

            carry = available - completeBytes;
            if (carry > 0)
            {
                Buffer.BlockCopy(buffer, completeBytes, buffer, 0, carry);
            }

            maximumBuffered = Math.Max(maximumBuffered, session.Ring.BufferedCount);
            if (view is not null)
            {
                PlotPoint[] points = view.Render(session.Ring, historySamples: 4_096, maximumPoints: 512);
                if (view.IsPaused)
                {
                    renderCallsAfterPause++;
                    if (points.Length != 0)
                    {
                        throw new InvalidOperationException("A paused view rendered non-empty points.");
                    }
                }
            }

            if (drainAfterEachRead)
            {
                long before = sink.SamplesCommitted;
                sink.Drain(session.Ring);
                if (view?.IsPaused == true)
                {
                    committedWhilePaused += sink.SamplesCommitted - before;
                }
            }
        }

        if (receivedCount < expectedSamples)
        {
            session.MarkTransportDisconnected();
        }

        return new ReceiveEvidence(receivedCount, session.DroppedSamples, session.LastDropObservedTimestampTicks, maximumBuffered, committedWhilePaused, renderCallsAfterPause);
    }

    private static async Task<SendEvidence> SendSamplesAsync(
        IPEndPoint endpoint,
        long firstSequence,
        int sampleCount,
        int targetSamplesPerSecond,
        CancellationToken cancellationToken)
    {
        using TcpClient client = new() { NoDelay = true, SendBufferSize = 1_048_576 };
        await client.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken).ConfigureAwait(false);
        using NetworkStream stream = client.GetStream();
        byte[] buffer = new byte[FrameSize * ProducerBatchSamples];
        int sent = 0;
        long started = Stopwatch.GetTimestamp();

        while (sent < sampleCount)
        {
            int count = Math.Min(buffer.Length / FrameSize, sampleCount - sent);
            for (int index = 0; index < count; index++)
            {
                long sequence = firstSequence + sent + index;
                Encode(buffer.AsSpan(index * FrameSize, FrameSize), sequence, timestampTicks: sequence, value: (sequence % 100_003) / 100_003d);
            }

            int byteCount = count * FrameSize;
            await stream.WriteAsync(buffer.AsMemory(0, byteCount), cancellationToken).ConfigureAwait(false);
            sent += count;

            if (targetSamplesPerSecond > 0)
            {
                long desiredElapsedTicks = (long)((double)sent * Stopwatch.Frequency / targetSamplesPerSecond);
                await WaitUntilAsync(started + desiredElapsedTicks, cancellationToken).ConfigureAwait(false);
            }
        }

        client.Client.Shutdown(SocketShutdown.Send);
        return new SendEvidence(sent);
    }

    private static async Task WaitUntilAsync(long deadlineTicks, CancellationToken cancellationToken)
    {
        while (true)
        {
            long remaining = deadlineTicks - Stopwatch.GetTimestamp();
            if (remaining <= 0)
            {
                return;
            }

            double remainingMilliseconds = remaining * 1000d / Stopwatch.Frequency;
            if (remainingMilliseconds > 3)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(remainingMilliseconds - 1), cancellationToken).ConfigureAwait(false);
            }
            else
            {
                Thread.SpinWait(64);
            }
        }
    }

    private static TcpListener StartListener()
    {
        TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start(backlog: 1);
        return listener;
    }

    private static AcquisitionSample Decode(ReadOnlySpan<byte> frame)
    {
        long sequence = BinaryPrimitives.ReadInt64LittleEndian(frame);
        long timestampTicks = BinaryPrimitives.ReadInt64LittleEndian(frame[8..]);
        long valueBits = BinaryPrimitives.ReadInt64LittleEndian(frame[16..]);
        return new AcquisitionSample(sequence, timestampTicks, BitConverter.Int64BitsToDouble(valueBits));
    }

    private static void Encode(Span<byte> frame, long sequence, long timestampTicks, double value)
    {
        BinaryPrimitives.WriteInt64LittleEndian(frame, sequence);
        BinaryPrimitives.WriteInt64LittleEndian(frame[8..], timestampTicks);
        BinaryPrimitives.WriteInt64LittleEndian(frame[16..], BitConverter.DoubleToInt64Bits(value));
    }

    private readonly record struct ReceiveEvidence(
        long Samples,
        long DroppedSamples,
        long LastDropObservedTimestampTicks,
        long MaximumBufferedSamples,
        long SamplesCommittedWhilePaused,
        long RenderCallsAfterPause);

    private readonly record struct SendEvidence(long Samples);

    private readonly record struct DownsampleEvidence(long MaximumMilliseconds, bool PreservedSpike);
}

internal sealed record OverrunEvidence(
    long SamplesReceived,
    long SamplesDropped,
    long FirstDroppedSequence,
    long EndExclusiveDroppedSequence,
    long LastDropObservedTimestampTicks,
    long SamplesRetained,
    long RingCapacityBytes);

internal sealed record DisconnectEvidence(
    long SamplesReceived,
    long FirstMissingSequence,
    long GapObservedTimestampTicks,
    bool GapIsOpen,
    bool RecordingSessionIsOpen,
    long SamplesCommitted);

internal sealed record PauseEvidence(
    long SamplesReceived,
    long SamplesCommittedWhilePaused,
    long SamplesCommittedTotal,
    long RenderCallsAfterPause,
    bool ViewIsPaused);
