// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

/// <summary>Exchanges stored process identities with a simulated platform during legacy Stop recovery.</summary>
public sealed class EscapedTerminationTests
{
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
        using var keys = new NodeDataKeyRing(store, node.Secrets.Selection);
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
            Secrets = new TaskSecrets(store, keys),
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
