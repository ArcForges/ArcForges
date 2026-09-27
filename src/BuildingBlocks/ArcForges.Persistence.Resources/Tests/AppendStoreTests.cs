// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Foundation.V1;
using Xunit;

namespace ArcForges.Persistence.Resources.Tests;

public sealed class AppendStoreTests
{
    public static bool LocalKillEnabled => Environment.GetEnvironmentVariable("ARCFORGES_APPEND_KILL_DIAGNOSTICS") == "1"
        && Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true";
    [Fact]
    public void SegmentsSpanChunksAndRangesPreserveRawBytes()
    {
        using var fixture = new Files();
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        using (var writer = AppendStore.Create(fixture.Capture))
        {
            long a = writer.AppendChunk([1, 2, 3, 4]);
            long b = writer.AppendChunk([5, 6, 7]);
            writer.MapSegment(first, [new(a, 1, 3), new(b, 0, 2)]);
            writer.MapSegment(second, [new(a, 0, 1)]);
            writer.RecordGap(new(CaptureGapCause.BackPressure, 100, 200, null));
            writer.RecordGap(new(CaptureGapCause.Overflow, 200, 300, 5));
            writer.RecordGap(new(CaptureGapCause.Dropped, 300, 400, 1));
            writer.Seal();
            Assert.Throws<InvalidOperationException>(() => writer.AppendChunk([8]));
            Assert.Throws<InvalidOperationException>(writer.Seal);
        }
        using var view = CaptureSnapshot.Open(fixture.Capture);
        Assert.True(view.IsSealed);
        Assert.Null(view.Loss);
        Assert.Equal(5, view.SegmentLength(first));
        Assert.Equal(new byte[] { 3, 4, 5 }, view.ReadRange(first, 1, 3));
        Assert.Equal(new byte[] { 1 }, view.ReadRange(second, 0, 1));
        Assert.Empty(view.ReadRange(first, 5, 0));
        Assert.Equal(3, view.Gaps.Count);
        Assert.Null(view.Gaps[0].LostSamples);
        Assert.Throws<ArgumentOutOfRangeException>(() => view.ReadRange(first, 4, 2));
        Assert.Throws<ArgumentOutOfRangeException>(() => view.ReadRange(first, 0, AppendStore.MaximumChunkBytes + 1));
        Assert.False(File.Exists(fixture.Capture + ".loss"));
    }

    [Fact]
    public void InvalidMapsAndGapsCannotEnterTheStore()
    {
        using var fixture = new Files();
        using var writer = AppendStore.Create(fixture.Capture);
        long chunk = writer.AppendChunk([1, 2]);
        var segment = Guid.NewGuid();
        Assert.Throws<InvalidDataException>(() => writer.MapSegment(segment, [new(chunk, 1, 2)]));
        Assert.Throws<InvalidDataException>(() => writer.MapSegment(segment, [new(chunk + 1, 0, 1)]));
        Assert.Throws<InvalidDataException>(() => writer.MapSegment(segment, [new(chunk, -1, 1)]));
        Assert.Throws<ArgumentException>(() => writer.MapSegment(Guid.Empty, [new(chunk, 0, 1)]));
        writer.MapSegment(segment, [new(chunk, 0, 1)]);
        Assert.Throws<ArgumentException>(() => writer.MapSegment(segment, [new(chunk, 0, 1)]));
        Assert.Throws<ArgumentException>(() => writer.RecordGap(new(CaptureGapCause.Dropped, 5, 4, 1)));
        Assert.Throws<ArgumentException>(() => writer.RecordGap(new((CaptureGapCause)99, 1, 2, 1)));
        Assert.Throws<ArgumentException>(() => writer.RecordGap(new(CaptureGapCause.Dropped, 1, 2, -1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => writer.AppendChunk([]));
        Assert.Throws<IOException>(() => AppendStore.Create(fixture.Capture));
        Assert.Throws<IOException>(() => new FileStream(fixture.Capture, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
    }

    [Fact]
    public void RecoveryPersistsLossAndNeverMutatesOriginal()
    {
        using var fixture = new Files();
        var segment = Guid.NewGuid();
        using (var writer = AppendStore.Create(fixture.Capture))
        {
            long chunk = writer.AppendChunk([10, 20]);
            writer.MapSegment(segment, [new(chunk, 0, 2)]);
        }
        byte[] original = File.ReadAllBytes(fixture.Capture);
        File.WriteAllBytes(fixture.Capture + ".loss.pending.interrupted", [1, 2]);
        using (var recovered = CaptureSnapshot.Open(fixture.Capture))
        {
            Assert.False(recovered.IsSealed);
            Assert.NotNull(recovered.Loss);
            Assert.Equal("MissingSeal", recovered.Loss.Cause);
            Assert.Equal(EffectCertainty.Unknown, recovered.Loss.Effect);
            Assert.Null(recovered.Loss.LostSamples);
            Assert.Null(recovered.Loss.StartTimestamp);
            Assert.Null(recovered.Loss.EndTimestamp);
            Assert.Equal(original.Length, recovered.Loss.VerifiedBytes);
            Assert.Equal(new byte[] { 10, 20 }, recovered.ReadRange(segment, 0, 2));
        }
        Assert.Equal(original, File.ReadAllBytes(fixture.Capture));
        Assert.Equal(new byte[] { 1, 2 }, File.ReadAllBytes(fixture.Capture + ".loss.pending.interrupted"));
        byte[] receipt = File.ReadAllBytes(fixture.Capture + ".loss");
        using (var repeated = CaptureSnapshot.Open(fixture.Capture)) Assert.NotNull(repeated.Loss);
        Assert.Equal(receipt, File.ReadAllBytes(fixture.Capture + ".loss"));
        receipt[^1] ^= 1;
        File.WriteAllBytes(fixture.Capture + ".loss", receipt);
        Assert.Throws<InvalidDataException>(() => CaptureSnapshot.Open(fixture.Capture));
    }

    [Fact]
    public void ChecksummedInvalidManifestBecomesExplicitLoss()
    {
        using var fixture = new Files();
        using (var file = new FileStream(fixture.Capture, FileMode.CreateNew, FileAccess.Write))
        {
            AppendFrameCodec.Write(file, AppendFrameKind.Chunk, 1, [1]);
            AppendFrameCodec.Write(file, AppendFrameKind.Segment, 2, [1, 2, 3]);
            AppendFrameCodec.Write(file, AppendFrameKind.Seal, 3, []);
        }
        using var recovered = CaptureSnapshot.Open(fixture.Capture);
        Assert.False(recovered.IsSealed);
        Assert.Equal("InvalidManifest", recovered.Loss!.Cause);
        Assert.Equal(AppendFrameCodec.HeaderLength + 1, recovered.Loss.VerifiedBytes);
        Assert.Empty(recovered.Segments);
    }

    [Fact]
    public void EveryTruncatedCapturePersistsTheVerifiedBoundaryWithoutChangingEvidence()
    {
        using var fixture = new Files();
        var segment = Guid.NewGuid();
        using (var writer = AppendStore.Create(fixture.Capture))
        {
            long chunk = writer.AppendChunk([11, 22, 33]);
            writer.MapSegment(segment, [new(chunk, 0, 3)]);
            writer.Seal();
        }
        byte[] complete = File.ReadAllBytes(fixture.Capture);
        // Independent physical boundaries: chunk(64+3), manifest(64+20+16), seal(64).
        const int chunkEnd = 67;
        const int manifestEnd = 167;
        Assert.Equal(231, complete.Length);
        for (int length = 0; length < complete.Length; length++)
        {
            string interrupted = fixture.Capture + "." + length.ToString(System.Globalization.CultureInfo.InvariantCulture);
            File.WriteAllBytes(interrupted, complete.AsSpan(0, length).ToArray());
            using var recovered = CaptureSnapshot.Open(interrupted);
            Assert.False(recovered.IsSealed);
            Assert.NotNull(recovered.Loss);
            Assert.Equal(length >= manifestEnd ? manifestEnd : length >= chunkEnd ? chunkEnd : 0, recovered.Loss.VerifiedBytes);
            Assert.Equal(length, recovered.Loss.ObservedBytes);
            Assert.True(File.Exists(interrupted + ".loss"));
            Assert.Equal(complete.AsSpan(0, length).ToArray(), File.ReadAllBytes(interrupted));
            if (length >= manifestEnd) Assert.Equal(new byte[] { 11, 22, 33 }, recovered.ReadRange(segment, 0, 3));
            else Assert.Empty(recovered.Segments);
        }
    }

    [Theory(Skip = "Explicit local process-kill diagnostics only.", SkipUnless = nameof(LocalKillEnabled))]
    [InlineData(false)]
    [InlineData(true)]
    public void KilledAppendProcessLeavesVerifiedPrefixAndDurableLoss(bool midChunk)
    {
        using var fixture = new Files();
        string source = fixture.Capture + ".source";
        var segment = Guid.NewGuid();
        using (var writer = AppendStore.Create(source))
        {
            long first = writer.AppendChunk([1, 2, 3]);
            writer.MapSegment(segment, [new(first, 0, 3)]);
            writer.AppendChunk(new byte[1024]);
            writer.Seal();
        }
        using var input = File.OpenRead(source);
        var scan = AppendFrameCodec.Scan(input);
        long boundary = scan.Frames[1].EndOffset;
        long cutoff = boundary + (midChunk ? AppendFrameCodec.HeaderLength + 400 : 0);
        string ready = fixture.Capture + ".ready";
        var start = new ProcessStartInfo("dotnet") { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (string argument in new[] { Path.Combine(AppContext.BaseDirectory, "ArcForges.Persistence.Resources.Tests.dll"), "--append-kill", fixture.Capture,
            midChunk.ToString(), segment.ToString(), ready }) start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        try
        {
            var timer = Stopwatch.StartNew();
            while (!File.Exists(ready) && !process.HasExited && timer.Elapsed < TimeSpan.FromSeconds(10)) Thread.Sleep(10);
            Assert.True(File.Exists(ready), "Offline append worker did not reach its durable interruption boundary.");
            process.Kill(entireProcessTree: true);
            Assert.True(process.WaitForExit(10_000));
        }
        finally
        {
            if (!process.HasExited) { process.Kill(entireProcessTree: true); process.WaitForExit(); }
        }
        using var recovered = CaptureSnapshot.Open(fixture.Capture);
        Assert.False(recovered.IsSealed);
        Assert.Equal(boundary, recovered.Loss!.VerifiedBytes);
        Assert.Equal(cutoff, recovered.Loss.ObservedBytes);
        Assert.Equal(midChunk ? "TruncatedPayload" : "MissingSeal", recovered.Loss.Cause);
        Assert.Equal(new byte[] { 1, 2, 3 }, recovered.ReadRange(segment, 0, 3));
        Assert.True(File.Exists(fixture.Capture + ".loss"));
    }

    private sealed class Files : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "arcforges-append-" + Guid.NewGuid().ToString("N"));
        internal Files() => Directory.CreateDirectory(_root);
        internal string Capture => Path.Combine(_root, "capture.raw");
        public void Dispose() => Directory.Delete(_root, recursive: true);
    }
}


