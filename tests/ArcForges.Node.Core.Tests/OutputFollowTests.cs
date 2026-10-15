// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Platform;
using OutputIndexRecord = ArcForges.Node.Platform.OutputIndexRecord;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Output followers (04 section 4): <see cref="OutputReader.Follow"/> reads a bounded number of index records per call, so a call that
/// skips every record it read (a follower past them, or records of the stream it does not follow) returns no slices without being
/// caught up. Only the end of the index means caught up: attach, its final drain before the result frame, and WatchTaskOutput keep
/// reading until then. The two shapes: a stdout-only follower over 5,000 stderr records and then one stdout record, and an attach that
/// reconnects after 9,000 records it already received, with one more record after them.
/// </summary>
public sealed class OutputFollowTests
{
    private const int ChunkBytes = 10;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void AStdoutFollowerSkipsThousandsOfStderrRecordsAndStillReadsTheStdoutAfterThem()
    {
        using var root = new TemporaryRoot();
        var files = new AttemptFiles(root.Path, "attempt");
        Write(files, [.. Enumerable.Repeat(OutputStreamKind.Stderr, 5_000), OutputStreamKind.Stdout]);

        var cursor = new OutputCursor(0, 0, long.MaxValue);
        var first = OutputReader.Follow(files, cursor, 8 * OutputReader.ChunkBytes);
        Assert.Empty(first.Slices);
        Assert.False(first.AtEnd, "No slices from the first 4,096 records is not the end of the index.");
        Assert.Equal(4_096, first.Next.Record);

        var (slices, calls, _) = Drain(files, cursor);
        var slice = Assert.Single(slices);
        Assert.Equal(OutputStreamKind.Stdout, slice.Stream);
        Assert.Equal(Data(OutputStreamKind.Stdout, 0), slice.Data);
        Assert.Equal(2, calls);
    }

    [Fact]
    public void AReconnectAfterNineThousandRecordsGetsTheRecordAfterThem()
    {
        using var root = new TemporaryRoot();
        var files = new AttemptFiles(root.Path, "attempt");
        Write(files, [.. Enumerable.Repeat(OutputStreamKind.Stdout, 9_001)]);

        // The attach already wrote 9,000 records' bytes; it reconnects with those offsets and starts the index from record 0.
        var cursor = new OutputCursor(0, 9_000L * ChunkBytes, 0);
        var (slices, calls, end) = Drain(files, cursor);
        var slice = Assert.Single(slices);
        Assert.Equal(9_000L * ChunkBytes, slice.Offset);
        Assert.Equal(Data(OutputStreamKind.Stdout, 9_000), slice.Data);
        Assert.Equal(3, calls);
        Assert.Equal(9_001, end.Record);
    }

    [Fact(Timeout = 120_000)]
    public async Task AttachAndWatchDeliverOutputAfterThousandsOfSkippedRecordsBeforeTheResult()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var taskId = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.Cmd, "/d", "/c", "exit 0"));
        var task = await Tasks.WaitAsync(channel, taskId);
        var files = Tasks.Files(node, task.CurrentAttempt.AttemptId);

        // The finished attempt's captured output is replaced by test data of the two shapes (the node only reads it from now on).
        Write(files, [.. Enumerable.Repeat(OutputStreamKind.Stdout, 9_001), .. Enumerable.Repeat(OutputStreamKind.Stderr, 5_000), OutputStreamKind.Stdout]);

        // An attach reconnecting after 9,000 stdout records and every stderr record: the rest comes before the result frame.
        using (var attach = channel.Tasks.AttachTask(new TaskServiceAttachTaskRequest
        {
            Meta = Tasks.Meta(),
            TaskId = taskId,
            StdoutFromOffset = 9_000UL * ChunkBytes,
            StderrFromOffset = 5_000UL * ChunkBytes,
        }, cancellationToken: Ct))
        {
            var frames = new List<TaskServiceAttachTaskFrame>();
            while (await attach.ResponseStream.MoveNext(Ct))
            {
                frames.Add(attach.ResponseStream.Current);
            }

            Assert.Equal(TaskServiceAttachTaskFrame.FrameOneofCase.Result, frames[^1].FrameCase);
            var outputs = frames.Where(frame => frame.FrameCase == TaskServiceAttachTaskFrame.FrameOneofCase.Output).Select(frame => frame.Output).ToList();
            Assert.Equal([9_000UL * ChunkBytes, 9_001UL * ChunkBytes], outputs.Select(chunk => chunk.Offset));
            Assert.All(outputs, chunk => Assert.Equal(OutputStream.Stdout, chunk.Stream));
        }

        // A stdout-only watch from the end of the first 9,001 records: 5,000 stderr records, then the last stdout record.
        using var watch = channel.Tasks.WatchTaskOutput(new TaskServiceWatchTaskOutputRequest
        {
            Meta = Tasks.Meta(),
            AttemptId = task.CurrentAttempt.AttemptId,
            Stream = OutputStream.Stdout,
            FromOffset = 9_001UL * ChunkBytes,
        }, cancellationToken: Ct);
        var watched = new List<TaskServiceWatchTaskOutputFrame>();
        while (await watch.ResponseStream.MoveNext(Ct))
        {
            watched.Add(watch.ResponseStream.Current);
        }

        Assert.Equal(TaskServiceWatchTaskOutputFrame.FrameOneofCase.Result, watched[^1].FrameCase);
        var chunk = Assert.Single(watched, frame => frame.FrameCase == TaskServiceWatchTaskOutputFrame.FrameOneofCase.Output).Output;
        Assert.Equal(9_001UL * ChunkBytes, chunk.Offset);
        Assert.Equal(Data(OutputStreamKind.Stdout, 9_001), chunk.Data.ToByteArray());
    }

    private static (List<OutputSlice> Slices, int Calls, OutputCursor End) Drain(AttemptFiles files, OutputCursor cursor)
    {
        var slices = new List<OutputSlice>();
        for (var calls = 1; ; calls++)
        {
            var step = OutputReader.Follow(files, cursor, 8 * OutputReader.ChunkBytes);
            slices.AddRange(step.Slices);
            cursor = step.Next;
            if (step.AtEnd)
            {
                return (slices, calls, cursor);
            }

            Assert.True(calls < 100, "The follower did not reach the end of the index.");
        }
    }

    /// <summary>Writes one 10-byte chunk per entry to its stream's file and one index record for it.</summary>
    private static void Write(AttemptFiles files, IReadOnlyList<OutputStreamKind> streams)
    {
        Directory.CreateDirectory(files.Directory);
        using var stdout = new FileStream(files.OutputPath(OutputStreamKind.Stdout), FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        using var stderr = new FileStream(files.OutputPath(OutputStreamKind.Stderr), FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        using var index = new FileStream(files.IndexPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        var counts = new Dictionary<OutputStreamKind, int> { [OutputStreamKind.Stdout] = 0, [OutputStreamKind.Stderr] = 0 };
        var record = new byte[OutputIndexRecord.Size];
        foreach (var stream in streams)
        {
            var number = counts[stream]++;
            (stream == OutputStreamKind.Stdout ? stdout : stderr).Write(Data(stream, number));
            new OutputIndexRecord(stream, (long)number * ChunkBytes, ChunkBytes, 1_000 + number, OutputChunkMarks.None).Write(record);
            index.Write(record);
        }
    }

    private static byte[] Data(OutputStreamKind stream, int number) =>
        System.Text.Encoding.ASCII.GetBytes((stream == OutputStreamKind.Stdout ? "o" : "e") + number.ToString("D8", System.Globalization.CultureInfo.InvariantCulture) + "\n");

    private sealed class TemporaryRoot : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("arcforges-follow-").FullName;

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
