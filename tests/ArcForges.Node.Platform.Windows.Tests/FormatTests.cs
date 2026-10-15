// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Node.Platform;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>A clock the test moves (16 section 4: deterministic time); its timestamps are its own monotonic ticks.</summary>
internal sealed class ManualClock(DateTimeOffset start) : TimeProvider
{
    private long _ticks;

    public DateTimeOffset Now { get; set; } = start;

    public override DateTimeOffset GetUtcNow() => Now;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp() => Interlocked.Read(ref _ticks);

    public void Advance(TimeSpan by)
    {
        Interlocked.Add(ref _ticks, by.Ticks);
        Now += by;
    }

    /// <summary>Moves the wall clock only (a clock change), not the monotonic time.</summary>
    public void JumpWallClock(TimeSpan by) => Now += by;
}

/// <summary>
/// The stable internal contract of the helper roles (04 section 3, "Compatibility of the helper roles"): exit.json, launch.json, guard.json,
/// guard-events.jsonl and the heartbeat keep their schema-1 field names; the output index keeps its 22-byte records; and the guards'
/// takeover rule (06 section 5) judges staleness on their own monotonic clock.
/// </summary>
public sealed class FormatTests
{
    [Fact]
    public void ExitRecordsUseTheSchemaOneFieldNames()
    {
        var record = new ExitRecord
        {
            AttemptId = "01abc",
            ExitStatus = -1073741510,
            ServiceResult = "exit-code",
            RecordedAt = "2026-10-15T00:00:00.000Z",
            CpuUserMs = 12,
            CpuKernelMs = 3,
            MemPeakBytes = 4096,
            IoReadBytes = 1,
            IoWriteBytes = 2,
            LimitViolations = ["job_memory"],
            LeftoversTerminated = ["a.exe"],
        };
        using var document = JsonDocument.Parse(record.ToJson());
        var names = document.RootElement.EnumerateObject().Select(property => property.Name).ToList();
        Assert.Equal(
            ["schema", "attempt_id", "exit_code_kind", "exit_status", "service_result", "recorded_at", "cpu_user_ms", "cpu_kernel_ms", "mem_peak_bytes",
                "io_read_bytes", "io_write_bytes", "oom_kills", "limit_violations", "leftovers_terminated"],
            names);
        Assert.Equal(1, document.RootElement.GetProperty("schema").GetInt32());
        var back = ExitRecord.Parse(record.ToJson());
        Assert.Equal(record.ExitStatus, back.ExitStatus);
        Assert.Equal(["job_memory"], back.LimitViolations);
    }

    [Fact]
    public void ReadersIgnoreAbsentAndTornFiles()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-formats-").FullName;
        try
        {
            Assert.Null(ExitRecord.TryRead(Path.Combine(root, "exit.json")));
            File.WriteAllText(Path.Combine(root, "exit.json"), "{\"schema\":1,\"attempt");
            Assert.Null(ExitRecord.TryRead(Path.Combine(root, "exit.json")));
            HelperFiles.WriteAtomically(Path.Combine(root, "exit.json"), new ExitRecord { AttemptId = "x", ExitStatus = 7 }.ToJson());
            Assert.Equal(7, ExitRecord.TryRead(Path.Combine(root, "exit.json"))!.ExitStatus);

            var events = Path.Combine(root, "guard-events.jsonl");
            new GuardEvent { AttemptId = "x", Event = GuardEventKinds.Takeover }.Append(events);
            new GuardEvent { AttemptId = "x", Event = GuardEventKinds.Terminate, Reason = "OUTPUT_LIMIT", OutputBytes = 10, LimitBytes = 5 }.Append(events);
            File.AppendAllText(events, "{\"schema\":1,\"event\":\"ter");
            var read = GuardEvent.ReadAll(events);
            Assert.Equal([GuardEventKinds.Takeover, GuardEventKinds.Terminate], read.Select(item => item.Event));
            Assert.Equal("OUTPUT_LIMIT", read[1].Reason);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void IndexRecordsAre22BytesAndATornTailIsIgnored()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-index-").FullName;
        try
        {
            var path = Path.Combine(root, "index.bin");
            var buffer = new byte[OutputIndexRecord.Size];
            using (var stream = File.Create(path))
            {
                new OutputIndexRecord(OutputStreamKind.Stdout, 0, 10, 123, OutputChunkMarks.None).Write(buffer);
                stream.Write(buffer);
                new OutputIndexRecord(OutputStreamKind.Stderr, 0, 4, 124, OutputChunkMarks.ApproximateTime).Write(buffer);
                stream.Write(buffer);
                stream.Write(buffer.AsSpan(0, 7));
            }

            var records = OutputIndexFile.Read(path, 0, out var complete);
            Assert.Equal(2 * OutputIndexRecord.Size, complete);
            Assert.Equal(2, records.Count);
            Assert.Equal(OutputStreamKind.Stderr, records[1].Stream);
            Assert.Equal(OutputChunkMarks.ApproximateTime, records[1].Marks);
            Assert.Single(OutputIndexFile.Read(path, 1, out _));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void AGuardTakesOverWhenTheHeartbeatStopsChangingOnItsOwnMonotonicClock()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-heartbeat-").FullName;
        try
        {
            var path = Path.Combine(root, "node-heartbeat");
            var clock = new ManualClock(DateTimeOffset.UnixEpoch.AddYears(56));
            new NodeHeartbeat { Instance = "a", Seq = 1 }.Write(path);
            var watch = new HeartbeatWatch(path, TimeSpan.FromSeconds(5), clock);
            Assert.False(watch.Stale);

            // Renewals keep it fresh; a wall-clock jump changes nothing.
            for (var second = 2; second <= 6; second++)
            {
                clock.Advance(TimeSpan.FromSeconds(1));
                new NodeHeartbeat { Instance = "a", Seq = second }.Write(path);
                Assert.True(watch.Poll());
                Assert.False(watch.Stale);
            }

            clock.JumpWallClock(TimeSpan.FromHours(3));
            Assert.False(watch.Stale);

            // The node stops: the same (instance, seq) for the takeover time.
            clock.Advance(TimeSpan.FromSeconds(4.9));
            Assert.False(watch.Poll());
            Assert.False(watch.Stale);
            clock.Advance(TimeSpan.FromMilliseconds(100));
            Assert.True(watch.Stale);

            // A restarted node renews with a new instance: the guard stands down.
            new NodeHeartbeat { Instance = "b", Seq = 1 }.Write(path);
            Assert.True(watch.Poll());
            Assert.False(watch.Stale);
            Assert.Equal("b", watch.Last!.Instance);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void AGuardWithoutAnyHeartbeatCountsFromItsStart()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-heartbeat-").FullName;
        try
        {
            var clock = new ManualClock(DateTimeOffset.UnixEpoch);
            var watch = new HeartbeatWatch(Path.Combine(root, "node-heartbeat"), TimeSpan.FromSeconds(2), clock);
            Assert.False(watch.Poll());
            clock.Advance(TimeSpan.FromSeconds(2));
            Assert.True(watch.Stale);
            Assert.False(watch.SawRenewal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
