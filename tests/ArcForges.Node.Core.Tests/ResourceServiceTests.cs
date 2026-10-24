// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Store;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Sample storage and downsampling with a real store (03 section 1; R-RES-001), and ResourceService against a real node in the test
/// process (node-component layer): the snapshot from the real samplers, WatchResources, ListProcesses and GetSamples with their
/// validation. Each test has its own data root and endpoint.
/// </summary>
public sealed class ResourceServiceTests
{
    private const long Second = 1_000_000;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void FinishedAttemptsAndOldMachineSamplesAreDownsampledAndOldOnesDropped()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-samples-").FullName;
        try
        {
            var clock = new SampleClock(new DateTimeOffset(2026, 10, 23, 12, 0, 0, TimeSpan.Zero));
            using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = root, BootIdentity = "boot", Clock = clock });
            var node = store.Metadata.NodeId.ToArray();
            var now = StoreTime.ToMicroseconds(clock.GetUtcNow());
            byte[] finished = [], running = [];
            store.Write(transaction =>
            {
                finished = Attempt(transaction, node, now - (60 * Second), finishedAt: now - (30 * Second));
                running = Attempt(transaction, node, now - (60 * Second), finishedAt: null);
                var rows = new List<SampleRow>();
                for (var second = 0; second < 20; second++)
                {
                    // 1 s attempt samples: the CPU rate alternates, memory rises to a peak and falls, the counters only grow.
                    var at = now - (60 * Second) + (second * Second);
                    rows.Add(new SampleRow(SampleScope.Attempt, finished, at, 1000, second % 2 == 0 ? 1_000 : 3_000, second * 100, (long)Math.Min(second, 12) * 1000,
                        (long)Math.Min(second, 12) * 1000, 2, second * 10, second * 20));
                    rows.Add(new SampleRow(SampleScope.Attempt, running, at, 1000, 500, second * 50, 4096, 4096, 1, 0, 0));
                }

                // Machine samples at 5 s: two minutes older than 24 h, one row older than 30 days, one recent minute.
                var old = ((now - (25 * 3600 * Second)) / (60 * Second)) * 60 * Second;
                for (var index = 0; index < 24; index++)
                {
                    rows.Add(new SampleRow(SampleScope.Machine, node, old + (index * 5 * Second), 5000, index < 12 ? 1_000 : 2_000, index, 1_000 + index, 1_000 + index,
                        100, index, index));
                }

                rows.Add(new SampleRow(SampleScope.Machine, node, now - (31L * 24 * 3600 * Second), 5000, 1, 1, 1, 1, 1, 1, 1));
                for (var index = 0; index < 12; index++)
                {
                    rows.Add(new SampleRow(SampleScope.Managed, node, now - (60 * Second) + (index * 5 * Second), 5000, 7, 7, 7, 7, 7, 7, 7));
                }

                ResourceSamples.Insert(transaction, rows);
            });

            var removed = store.Write(ResourceSamples.Housekeep);

            var attempt = store.Read(reader => ResourceSamples.Read(reader, SampleScope.Attempt, finished, 0, long.MaxValue, 1_000));
            Assert.Equal(10_000, attempt.ResolutionMs);
            Assert.Equal(2, attempt.Samples.Count);
            Assert.All(attempt.Samples, sample => Assert.Equal(2_000u, sample.Usage.CpuMillicores));
            Assert.Equal(12_000ul, attempt.Samples.Max(sample => sample.Usage.MemPeakBytes));
            Assert.Equal(1_900ul, attempt.Samples.Max(sample => sample.Usage.CpuTimeMs));
            Assert.Equal(380ul, attempt.Samples.Max(sample => sample.Usage.IoWriteBytes));

            // A running attempt keeps its 1 s samples; the recent managed minute keeps its 5 s samples.
            var live = store.Read(reader => ResourceSamples.Read(reader, SampleScope.Attempt, running, 0, long.MaxValue, 1_000));
            Assert.Equal((20, 1_000L), (live.Samples.Count, live.ResolutionMs));
            Assert.Equal(12, store.Read(reader => ResourceSamples.Read(reader, SampleScope.Managed, node, 0, long.MaxValue, 1_000)).Samples.Count);

            // Older than 24 h: two 1-minute rows (mean CPU, maxima); older than 30 days: gone.
            var machine = store.Read(reader => ResourceSamples.Read(reader, SampleScope.Machine, node, 0, long.MaxValue, 1_000));
            Assert.Equal(60_000, machine.ResolutionMs);
            Assert.Equal([1_000u, 2_000u], machine.Samples.Select(sample => sample.Usage.CpuMillicores));
            Assert.Equal([1_011ul, 1_023ul], machine.Samples.Select(sample => sample.Usage.MemBytes));
            Assert.Equal(1 + (20 - 2) + (24 - 2), removed);

            // A second pass changes nothing.
            Assert.Equal(0, store.Write(ResourceSamples.Housekeep));

            // Reading at most N points merges into N buckets or fewer, with the bucket width as the resolution.
            var merged = store.Read(reader => ResourceSamples.Read(reader, SampleScope.Attempt, running, 0, long.MaxValue, 10));
            Assert.Equal(10, merged.Samples.Count);
            Assert.Equal(2_000, merged.ResolutionMs);
            Assert.All(merged.Samples, sample => Assert.Equal(500u, sample.Usage.CpuMillicores));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    // isolation=exclusive: the snapshot is the live machine's (LiveMachine), and its pressure level is Normal only on a machine that no
    // other test loads.
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task TheSnapshotProcessesAndSamplesComeFromTheRealSamplers()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().WithLiveMachine().StartAsync();
        await using var channel = await node.ChannelAsync();

        // The first evaluation runs within a second of the start; machine samples are stored every 5 s.
        ResourceSnapshot snapshot = new();
        await WaitAsync(async () =>
        {
            snapshot = (await channel.Resources.GetResourceSnapshotAsync(new ResourceServiceGetResourceSnapshotRequest { Meta = new RequestMeta() },
                deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: Ct)).Value.Snapshot;
            return snapshot.HasBudgetCpuMillicores;
        }, "the first evaluation");
        Assert.Equal((uint)(Environment.ProcessorCount * 1000), snapshot.CapacityCpuMillicores);
        Assert.Equal(snapshot.CapacityCpuMillicores - snapshot.ReserveCpuMillicores - snapshot.UnmanagedCpuMillicores,
            Math.Max(1000, snapshot.BudgetCpuMillicores));
        Assert.Equal(snapshot.CapacityMemBytes - snapshot.ReserveMemBytes - snapshot.UnmanagedMemBytes, snapshot.BudgetMemBytes);
        Assert.InRange(snapshot.AvailableMemBytes, 1ul, snapshot.CapacityMemBytes);
        Assert.Equal(PressureLevel.Normal, snapshot.Pressure);
        Assert.Equal(OperatingSystem.IsLinux(), snapshot.PressureDetail.Available);
        Assert.Contains(snapshot.Volumes, volume => volume.ManagedRoots.Contains(node.DataRoot) && volume.FreeBytes > 0);
        Assert.NotNull(snapshot.Capabilities);
        Assert.True(snapshot.NodeSelf.CpuTimeMs > 0);

        // The node's own process (this test process) is NODE_SELF; nothing outside an attempt container is managed.
        var processes = (await channel.Resources.ListProcessesAsync(new ResourceServiceListProcessesRequest { Meta = new RequestMeta(), Filter = new ProcessFilter { TopN = 500 } },
            deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: Ct)).Value.Processes;
        Assert.Contains(processes, process => process.Process.Pid == (uint)Environment.ProcessId && process.Label == ProcessLabel.NodeSelf);
        Assert.DoesNotContain(processes, process => process.Label == ProcessLabel.Managed && process.TaskId is null);
        Assert.Equal(processes.Count, processes.Select(process => process.Process.Pid).Distinct().Count());
        var nodeOnly = (await channel.Resources.ListProcessesAsync(new ResourceServiceListProcessesRequest
        {
            Meta = new RequestMeta(),
            Filter = new ProcessFilter { Labels = { ProcessLabel.NodeSelf } },
        }, deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: Ct)).Value.Processes;
        Assert.All(nodeOnly, process => Assert.Equal(ProcessLabel.NodeSelf, process.Label));
        Assert.Empty((await channel.Resources.ListProcessesAsync(new ResourceServiceListProcessesRequest
        {
            Meta = new RequestMeta(),
            Filter = new ProcessFilter { SessionId = new Id { Value = ByteString.CopyFrom(new byte[16]) } },
        }, deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: Ct)).Value.Processes);

        ResourceServiceGetSamplesValue samples = new();
        await WaitAsync(async () =>
        {
            samples = (await channel.Resources.GetSamplesAsync(new ResourceServiceGetSamplesRequest { Meta = new RequestMeta(), Scope = SampleScope.Machine },
                deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct)).Value;
            return samples.Samples.Count >= 2;
        }, "two machine samples");
        Assert.Equal(5_000ul, samples.ResolutionMs);
        Assert.All(samples.Samples, sample => Assert.InRange(sample.Usage.MemBytes, 1ul, snapshot.CapacityMemBytes));
        Assert.True((await channel.Resources.GetSamplesAsync(new ResourceServiceGetSamplesRequest { Meta = new RequestMeta(), Scope = SampleScope.Managed },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct)).Value.Samples.Count >= 1);
    }

    [Fact(Timeout = 60_000)]
    public async Task InvalidRequestsAreRefusedWithTypedErrors()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        async Task<ArcError> Samples(ResourceServiceGetSamplesRequest request) =>
            (await channel.Resources.GetSamplesAsync(request, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct)).Error;

        Assert.Equal(("invalid_argument", ErrorCategory.Validation), Code(await Samples(new ResourceServiceGetSamplesRequest())));
        Assert.Equal(("invalid_argument", ErrorCategory.Validation), Code(await Samples(new ResourceServiceGetSamplesRequest { Scope = SampleScope.Attempt })));
        Assert.Equal(("invalid_argument", ErrorCategory.Validation), Code(await Samples(new ResourceServiceGetSamplesRequest
        {
            Scope = SampleScope.Machine,
            AttemptId = new Id { Value = ByteString.CopyFrom(new byte[16]) },
        })));
        Assert.Equal(("invalid_argument", ErrorCategory.Validation), Code(await Samples(new ResourceServiceGetSamplesRequest { Scope = SampleScope.Machine, MaxPoints = 5 })));
        var now = DateTimeOffset.UtcNow;
        Assert.Equal(("invalid_argument", ErrorCategory.Validation), Code(await Samples(new ResourceServiceGetSamplesRequest
        {
            Scope = SampleScope.Machine,
            Range = new TimeRangeUtc { From = ProtoTime.ToInstant(now.AddDays(-31)), Until = ProtoTime.ToInstant(now) },
        })));
        Assert.Equal(("invalid_argument", ErrorCategory.Validation), Code(await Samples(new ResourceServiceGetSamplesRequest
        {
            Scope = SampleScope.Machine,
            Range = new TimeRangeUtc { From = ProtoTime.ToInstant(now), Until = ProtoTime.ToInstant(now.AddHours(-1)) },
        })));
        Assert.Equal(("not_found", ErrorCategory.State), Code(await Samples(new ResourceServiceGetSamplesRequest
        {
            Scope = SampleScope.Attempt,
            AttemptId = new Id { Value = ByteString.CopyFrom(new byte[16]) },
        })));

        var processes = await channel.Resources.ListProcessesAsync(new ResourceServiceListProcessesRequest { Filter = new ProcessFilter { TopN = 501 } },
            deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: Ct);
        Assert.Equal(("invalid_argument", ErrorCategory.Validation), Code(processes.Error));
        processes = await channel.Resources.ListProcessesAsync(new ResourceServiceListProcessesRequest { Filter = new ProcessFilter { Labels = { (ProcessLabel)42 } } },
            deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: Ct);
        Assert.Equal(("invalid_argument", ErrorCategory.Validation), Code(processes.Error));

        using var watch = channel.Resources.WatchResources(new ResourceServiceWatchResourcesRequest { IntervalMs = 500 }, cancellationToken: Ct);
        Assert.True(await watch.ResponseStream.MoveNext(Ct));
        Assert.Equal(("invalid_argument", ErrorCategory.Validation), Code(watch.ResponseStream.Current.Error));
    }

    [Fact(Timeout = 60_000)]
    public async Task WatchResourcesStreamsASnapshotPerInterval()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        using var watch = channel.Resources.WatchResources(new ResourceServiceWatchResourcesRequest { IntervalMs = 1_000 }, cancellationToken: cancel.Token);
        var started = DateTime.UtcNow;
        var frames = new List<ResourceServiceWatchResourcesFrame>();
        while (frames.Count < 3 && await watch.ResponseStream.MoveNext(cancel.Token))
        {
            frames.Add(watch.ResponseStream.Current);
        }

        var elapsed = DateTime.UtcNow - started;
        Assert.All(frames, frame => Assert.Equal(ResourceServiceWatchResourcesFrame.FrameOneofCase.Snapshot, frame.FrameCase));
        Assert.Equal([1ul, 2ul, 3ul], frames.Select(frame => frame.Position.Sequence));
        Assert.InRange(elapsed, TimeSpan.FromSeconds(1.5), TimeSpan.FromSeconds(20));
        await cancel.CancelAsync();
    }

    private static (string Code, ErrorCategory Category) Code(ArcError? error) => (error?.Code ?? "none", error?.Category ?? ErrorCategory.Unspecified);

    private static byte[] Attempt(StoreTransaction transaction, byte[] node, long createdAt, long? finishedAt)
    {
        var taskId = StoreIds.NewUuid7(transaction.Clock);
        transaction.Execute(
            """
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, env_digest, spec_digest, owner, owner_origin, pool,
                              priority, effective_priority, side_effect, side_effect_source, command_fingerprint, command_digest, created_at, rev)
            VALUES ($id, 1, 1, 'test', 'test', $spec, NULL, zeroblob(32), $owner, 1, 'default', 3, 3, 4, 1, 'test', zeroblob(32), $now, 0);
            """,
            ("$id", taskId), ("$spec", new TaskSpec { Title = "test" }.ToByteArray()), ("$owner", new ActorRef { Origin = Origin.Human }.ToByteArray()),
            ("$now", createdAt));
        var attemptId = StoreIds.NewUuid7(transaction.Clock);
        transaction.Execute(
            """
            INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, request_cpu_millicores, request_mem_expected_bytes,
                                 request_mem_ceiling_bytes, request_source, accounted_mem_bytes, created_at, finished_at, termination_reason, rev)
            VALUES ($id, $task, 1, 1, $state, $node, 1000, 1024, 2048, 5, 1024, $created, $finished, $reason, 0);
            """,
            ("$id", attemptId), ("$task", taskId), ("$state", finishedAt is null ? 4 : 9), ("$node", node), ("$created", createdAt), ("$finished", finishedAt),
            ("$reason", finishedAt is null ? null : 1));
        return attemptId;
    }

    private static async Task WaitAsync(Func<Task<bool>> condition, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!await condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                Assert.Fail($"Timed out waiting for {what}.");
            }

            await Task.Delay(200, Ct);
        }
    }

    private sealed class SampleClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
