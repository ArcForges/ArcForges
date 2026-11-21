// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

/// <summary>Exchanges stored process identities with a simulated platform during legacy Stop recovery.</summary>
public sealed class EscapedTerminationTests
{
    private const string CurrentBoot = "windows:4e7af21b-2fb7-4e3f-b82e-d40ffdefa9f0:200";
    private const string EarlierBoot = "windows:4e7af21b-2fb7-4e3f-b82e-d40ffdefa9f0:100";

    [Fact(Timeout = 120_000)]
    public async Task ARecoveredStopUsesRecordedProcessBirthAndLeavesNaturalExitAlone()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var (stoppedTask, stoppedAttempt) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Stopping);
        var (exitedTask, exitedAttempt) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Running);
        WriteExit(node, stoppedAttempt);
        WriteExit(node, exitedAttempt);

        const int exactPid = 101;
        const int reusedPid = 102;
        const int naturalPid = 103;
        var recordedBirth = DateTimeOffset.UnixEpoch.AddDays(1);
        var laterBirth = recordedBirth.AddSeconds(30);

        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = BootIdentity.Read(), Clock = node.Clock });
        store.Write(transaction =>
        {
            Assert.Equal(1, transaction.Execute("UPDATE attempt SET termination_reason = $reason WHERE attempt_id = $id;",
                ("$reason", (int)TerminationReason.Cancelled), ("$id", stoppedAttempt.Value.ToByteArray())));
            RecordProcess(transaction, stoppedAttempt, exactPid, recordedBirth, "matched-fixture");
            RecordProcess(transaction, stoppedAttempt, reusedPid, recordedBirth, "stale-fixture");
            RecordProcess(transaction, exitedAttempt, naturalPid, laterBirth, "natural-fixture");
        }, CommitDurability.Full);

        using var platform = new ObservedTerminationPlatform(new Dictionary<int, DateTimeOffset>
        {
            [exactPid] = recordedBirth,
            [reusedPid] = laterBirth,
            [naturalPid] = laterBirth,
        });
        using var log = new NodeLog(Path.Combine(node.DataRoot, "logs", "node"), LogLevel.Info, node.Clock);
        using var heartbeat = new NodeHeartbeatWriter(node.DataRoot, log, node.Clock);
        var journal = EventJournal.Open(store);
        await using var processor = new CommandProcessor(store, journal, new StreamHub());
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = node.Clock,
            DataRoot = node.DataRoot,
            Platform = platform,
            Heartbeat = heartbeat,
        });
        await execution.RecoverAsync(new RecoveryReport(true, false, null, store.Opening), processor, ct);
        execution.Start();

        ManagedTask? Read(Id taskId) => store.Read(reader => TaskRecords.GetTask(reader, taskId.Value.Span, full: false));

        await Tasks.WaitForAsync(() => Read(stoppedTask)?.State == TaskState.Cancelled && Read(exitedTask)?.State == TaskState.Succeeded,
            Tasks.Bound, "both retained attempts to finish");
        var stopped = Assert.IsType<ManagedTask>(Read(stoppedTask)).CurrentAttempt;
        var exited = Assert.IsType<ManagedTask>(Read(exitedTask)).CurrentAttempt;
        Assert.Equal(stoppedAttempt, stopped.AttemptId);
        Assert.Equal(exitedAttempt, exited.AttemptId);
        Assert.True(stopped.NodeGap);
        Assert.True(exited.NodeGap);
        Assert.Equal(TerminationReason.Cancelled, stopped.Result.TerminationReason);
        Assert.Equal(TerminationReason.Exited, exited.Result.TerminationReason);
        Assert.Contains("matched-fixture (101)", stopped.Result.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("stale-fixture", stopped.Result.Detail, StringComparison.Ordinal);
        Assert.Equal([(exactPid, recordedBirth, ProcessTermination.Terminated), (reusedPid, recordedBirth, ProcessTermination.Gone)],
            platform.Observations.OrderBy(item => item.Pid).ToArray());
    }

    [Theory(Timeout = 60_000)]
    [InlineData(CurrentBoot, true)]
    [InlineData(EarlierBoot, true)]
    [InlineData("windows:unknown:100", true)]
    [InlineData(null, true)]
    [InlineData(CurrentBoot, false)]
    public async Task ExplicitTerminationRequiresTheRecordedProcessesOriginalLocalBoot(string? recordedBoot, bool localExecutor)
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var (_, attempt) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished);
        var attemptId = attempt.Value.ToByteArray();
        const int pid = 104;
        const string image = "retained-process-fixture";
        var birth = DateTimeOffset.UnixEpoch.AddDays(1);
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = CurrentBoot, Clock = node.Clock });
        var executor = localExecutor ? store.Metadata.NodeId.ToArray() : CommandIds.New().Value.ToByteArray();
        store.Write(transaction =>
        {
            Assert.Equal(1, transaction.Execute("UPDATE attempt SET boot_identity = $boot, executor_node_id = $executor WHERE attempt_id = $id;",
                ("$boot", recordedBoot), ("$executor", executor), ("$id", attemptId)));
            RecordProcess(transaction, attempt, pid, birth, image);
        }, CommitDurability.Full);

        using var platform = new ObservedTerminationPlatform(new Dictionary<int, DateTimeOffset> { [pid] = birth });
        using var log = new NodeLog(Path.Combine(node.DataRoot, "logs", "node"), LogLevel.Info, node.Clock);
        using var heartbeat = new NodeHeartbeatWriter(node.DataRoot, log, node.Clock);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = node.Clock,
            DataRoot = node.DataRoot,
            Platform = platform,
            Heartbeat = heartbeat,
        });
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(node.ConfigPath, node.DataRoot, log), node.DataRoot, "offline-termination-fixture", node.Clock,
            new RecoveryReport(true, false, null, store.Opening), new CapabilityReport())
        { Execution = execution };
        await runtime.TransitionAsync(NodeLifecycleState.Recovering, "fixture").WaitAsync(ct);
        await runtime.TransitionAsync(NodeLifecycleState.Ready, "fixture").WaitAsync(ct);

        var handler = new ResourceServiceHandler(runtime, new ClientSessions());
        var human = new Caller(Origin.Human, ClientKind.Cli, null);
        var request = new ResourceServiceTerminateProcessRequest
        {
            Meta = Tasks.Meta(),
            Process = new() { Pid = pid, StartTime = ProtoTime.ToInstant(birth) },
        };
        var result = await handler.TerminateProcess(request, human).WaitAsync(ct);
        if (localExecutor && recordedBoot == CurrentBoot)
        {
            Assert.Null(result.Error);
            Assert.Equal(request.Meta.CommandId, result.Value.Receipt.CommandId);
            Assert.Equal(EffectCertainty.Happened, result.Value.Receipt.Effect);
            Assert.Equal((pid, birth, ProcessTermination.Terminated), Assert.Single(platform.Observations));

            // An exact historical success remains replayable after the recorded boot can no longer authorize an effect.
            store.Write(transaction => transaction.Execute("UPDATE attempt SET boot_identity = $boot WHERE attempt_id = $id;",
                ("$boot", EarlierBoot), ("$id", attemptId)), CommitDurability.Full);
            recordedBoot = EarlierBoot;
            Assert.Equal(result, await handler.TerminateProcess(request.Clone(), human).WaitAsync(ct));
            var changed = request.Clone();
            changed.Reason = "a different request under the same command ID";
            var refused = await handler.TerminateProcess(changed, human).WaitAsync(ct);
            Assert.Equal(("not_found", EffectCertainty.DidNotHappen), (refused.Error?.Code, refused.Error?.Effect));
            Assert.Equal((pid, birth, ProcessTermination.Terminated), Assert.Single(platform.Observations));
        }
        else
        {
            Assert.Equal(("not_found", EffectCertainty.DidNotHappen), (result.Error?.Code, result.Error?.Effect));
            Assert.Null(result.Value);
            Assert.Empty(platform.Observations);
            Assert.Null(store.Read(reader => reader.Scalar("SELECT 1 FROM command_dedup WHERE command_id = $id;",
                ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        }

        store.Read(reader =>
        {
            using var command = reader.CreateCommand("""
                SELECT owner.boot_identity, owner.executor_node_id, process.pid, process.start_at, process.executable, process.label
                FROM process_record AS process JOIN attempt AS owner ON owner.attempt_id = process.attempt_id
                WHERE process.attempt_id = $id;
                """);
            command.Parameters.AddWithValue("$id", attemptId);
            using var rows = command.ExecuteReader();
            Assert.True(rows.Read());
            Assert.Equal(recordedBoot, rows.IsDBNull(0) ? null : rows.GetString(0));
            Assert.Equal(executor, (byte[])rows.GetValue(1));
            Assert.Equal((pid, StoreTime.ToMicroseconds(birth), image, (int)ProcessLabel.Escaped),
                (rows.GetInt32(2), rows.GetInt64(3), rows.GetString(4), rows.GetInt32(5)));
            Assert.False(rows.Read());
            return 0;
        });
    }

    private static void WriteExit(InProcessNode node, Id attempt)
    {
        var files = Tasks.Files(node, attempt);
        Directory.CreateDirectory(files.Directory);
        HelperFiles.WriteAtomically(files.ExitPath, new ExitRecord
        {
            AttemptId = IdText.Format(attempt),
            RecordedAt = node.Clock.GetUtcNow().ToString("O", CultureInfo.InvariantCulture),
        }.ToJson());
    }

    private static void RecordProcess(StoreTransaction transaction, Id attempt, int pid, DateTimeOffset birth, string image) =>
        transaction.Execute("""
            INSERT INTO process_record (attempt_id, pid, start_at, parent_pid, executable, arguments_redacted, first_seen, last_seen, mem_peak_bytes, label)
            VALUES ($attempt, $pid, $start, 0, $image, NULL, $now, $now, 0, $label);
            """, ("$attempt", attempt.Value.ToByteArray()), ("$pid", pid), ("$start", StoreTime.ToMicroseconds(birth)), ("$image", image),
            ("$now", transaction.NowMicroseconds), ("$label", (int)ProcessLabel.Escaped));

    private sealed class ObservedTerminationPlatform(IReadOnlyDictionary<int, DateTimeOffset> observed) : IExecutionPlatform
    {
        public ConcurrentQueue<(int Pid, DateTimeOffset Birth, ProcessTermination Outcome)> Observations { get; } = new();
        public string Name => "retained-identity-fixture";
        public MachineCapacity Capacity => new(4, 1L << 30);
        public CapabilityReport Evaluate() => new();
        public IAttemptHandle? Reopen(string nodeName, AttemptFiles files, RootProcess? root, bool stopping) => null;
        public bool AcknowledgeRecorded(string nodeName, string attemptName) => false;
        public void Start(string nodeName, RootLimits limits, string helperExecutable) => throw new NotSupportedException();
        public void UpdateRootLimits(RootLimits limits) => throw new NotSupportedException();
        public void Dispose() { }

        public ProcessTermination TerminateProcess(int pid, DateTimeOffset start)
        {
            var outcome = observed.TryGetValue(pid, out var actual) && actual == start ? ProcessTermination.Terminated : ProcessTermination.Gone;
            Observations.Enqueue((pid, start, outcome));
            return outcome;
        }
    }
}
