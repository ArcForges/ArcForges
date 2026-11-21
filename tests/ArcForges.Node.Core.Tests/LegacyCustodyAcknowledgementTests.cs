// SPDX-License-Identifier: AGPL-3.0-only
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

public sealed class LegacyCustodyAcknowledgementTests
{
    private const string Machine = "19cfb15c-89b9-48b0-9db3-9b261837901d";
    private const string WindowsCurrent = "windows:" + Machine + ":200";
    private const string EarlierWindowsBoot = "windows:" + Machine + ":100";
    private const string LinuxCurrent = "linux:19cfb15c-89b9-48b0-9db3-9b261837901d";

    [Fact(Timeout = 30_000)]
    public async Task RecoveryAcknowledgesOnlyMatchingCommittedLocalExitsAndKnowsTheEarlierWindowsBoot()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = InProcessNode.Create();
        node.Clock = new FixtureClock();
        var recordedExit = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var recordedSignal = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var differentCoreStatus = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var differentReceipt = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var differentStatus = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var lateKnown = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var lostUnknown = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var foreignExecutor = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var earlierBootExit = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var (earlierBootTask, earlierBootAttempt) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Running);
        var (currentTask, currentAttempt) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Running);
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = WindowsCurrent, Clock = node.Clock });
        store.Write(transaction =>
        {
            transaction.Execute("UPDATE attempt SET boot_identity = $boot;", ("$boot", WindowsCurrent));
            transaction.Execute("UPDATE attempt SET executor_node_id = $other WHERE attempt_id = $id;",
                ("$other", CommandIds.New().Value.ToByteArray()), ("$id", foreignExecutor.Value.ToByteArray()));
            // A previous store open has already recorded the current boot in store_meta.
            transaction.Execute("UPDATE attempt SET boot_identity = $original WHERE attempt_id IN ($exit, $live);",
                ("$original", EarlierWindowsBoot), ("$exit", earlierBootExit.Value.ToByteArray()), ("$live", earlierBootAttempt.Value.ToByteArray()));
            transaction.Execute("UPDATE attempt SET exit_code = NULL, signal = 9, core_dumped = 1 WHERE attempt_id IN ($signal, $mismatch);",
                ("$signal", recordedSignal.Value.ToByteArray()), ("$mismatch", differentCoreStatus.Value.ToByteArray()));
            transaction.Execute("UPDATE attempt SET termination_reason = $lost, effect = $unknown WHERE attempt_id = $id;",
                ("$lost", (int)TerminationReason.Lost), ("$unknown", (int)EffectCertainty.Unknown), ("$id", lostUnknown.Value.ToByteArray()));
        }, CommitDurability.Full);

        WriteExit(node, recordedExit, recordedExit);
        WriteExit(node, recordedSignal, recordedSignal, status: 9, kind: "dumped");
        WriteExit(node, differentCoreStatus, differentCoreStatus, status: 9, kind: "killed");
        WriteExit(node, differentReceipt, recordedExit);
        WriteExit(node, differentStatus, differentStatus, status: 9);
        WriteExit(node, lateKnown, lateKnown, at: node.Clock.GetUtcNow().AddMinutes(1));
        WriteExit(node, lostUnknown, lostUnknown);
        WriteExit(node, foreignExecutor, foreignExecutor);
        WriteExit(node, earlierBootExit, earlierBootExit);
        WriteExit(node, currentAttempt, currentAttempt);
        var noAttemptRow = CommandIds.New();
        WriteExit(node, noAttemptRow, noAttemptRow);

        using var platform = new RecordingPlatform();
        await WithSupervisorAsync(node, store, platform, async (execution, processor, heartbeat) =>
        {
            await execution.RecoverAsync(new RecoveryReport(true, false, null, store.Opening), processor, ct);
            Assert.Equal(new[] { IdText.Format(recordedExit), IdText.Format(recordedSignal) }.Order(StringComparer.Ordinal),
                platform.Acknowledged.Order(StringComparer.Ordinal));
            Assert.Equal([IdText.Format(currentAttempt)], platform.Queried);
            var prior = store.Read(reader => TaskRecords.GetTask(reader, earlierBootTask.Value.Span, full: true));
            Assert.NotNull(prior);
            Assert.Equal((TaskState.Lost, "boot_changed", earlierBootAttempt),
                (prior.State, prior.StateReason, prior.CurrentAttempt.AttemptId));
            Assert.Equal(EffectCertainty.Unknown, prior.CurrentAttempt.Result.Effect);
            Assert.Equal(TaskState.Running, store.Read(reader => TaskRecords.GetTask(reader, currentTask.Value.Span, full: false)?.State));
            Assert.True(heartbeat.RecoveryDone);
        });
    }

    [Theory(Timeout = 30_000)]
    [InlineData(WindowsCurrent, null)]
    [InlineData(WindowsCurrent, "")]
    [InlineData(WindowsCurrent, "fixture-original-boot")]
    [InlineData(WindowsCurrent, "windows:unknown:100")]
    [InlineData(WindowsCurrent, "windows:" + Machine + ":9223372036854775807")]
    [InlineData(WindowsCurrent, "windows:c8f75b9b-07c3-4965-abbf-93a8447372cd:100")]
    [InlineData(LinuxCurrent, "linux:c8f75b9b-07c3-4965-abbf-93a8447372cd")]
    public async Task ACurrentHostLookupCannotSettleAnUnauthenticatedOriginalBoot(string currentBoot, string? recordedBoot)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = InProcessNode.Create();
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Running);
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = currentBoot, Clock = node.Clock });
        store.Write(transaction => transaction.Execute("UPDATE attempt SET boot_identity = $boot WHERE attempt_id = $id;",
            ("$boot", recordedBoot), ("$id", attemptId.Value.ToByteArray())), CommitDurability.Full);
        using var platform = new RecordingPlatform(confirmedMissing: true);
        ManagedTask? ReadTask() => store.Read(reader => TaskRecords.GetTask(reader, taskId.Value.Span, full: true));
        var original = ReadTask();
        Assert.NotNull(original);
        await WithSupervisorAsync(node, store, platform, async (execution, processor, heartbeat) =>
        {
            await Assert.ThrowsAsync<LegacyCustodyUnavailableException>(() =>
                execution.RecoverAsync(new RecoveryReport(true, true, null, store.Opening), processor, ct));
            Assert.Equal(original, ReadTask());
            Assert.Equal([IdText.Format(attemptId)], platform.Queried);
            Assert.Empty(platform.Acknowledged);
            Assert.False(heartbeat.RecoveryDone);
        });
    }

    [Theory(Timeout = 30_000)]
    [InlineData(AttemptKind.Remote, WindowsCurrent)]
    [InlineData(AttemptKind.Local, EarlierWindowsBoot)]
    [InlineData(AttemptKind.Adopted, WindowsCurrent)]
    [InlineData(AttemptKind.Adopted, EarlierWindowsBoot)]
    public async Task RecoveryLeavesForeignLiveAttemptsUntouched(AttemptKind kind, string recordedBoot)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = InProcessNode.Create();
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Running);
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = WindowsCurrent, Clock = node.Clock });
        store.Write(transaction => transaction.Execute("""
            UPDATE attempt SET executor_node_id = $other, boot_identity = $boot, kind = $kind, container_name = $container
            WHERE attempt_id = $id;
            """, ("$other", CommandIds.New().Value.ToByteArray()), ("$boot", recordedBoot), ("$kind", (int)kind),
            ("$container", IdText.Format(attemptId)), ("$id", attemptId.Value.ToByteArray())), CommitDurability.Full);
        using var platform = new RecordingPlatform();
        ManagedTask? ReadTask() => store.Read(reader => TaskRecords.GetTask(reader, taskId.Value.Span, full: true));
        var original = ReadTask();
        Assert.NotNull(original);
        await WithSupervisorAsync(node, store, platform, async (execution, processor, heartbeat) =>
        {
            await execution.RecoverAsync(new RecoveryReport(true, true, null, store.Opening), processor, ct);
            Assert.Equal(original, ReadTask());
            Assert.Empty(platform.Queried);
            Assert.Empty(platform.Acknowledged);
            Assert.Empty(execution.RunningAttempts);
            Assert.Empty(execution.Adoptions.Tracked);
            Assert.True(heartbeat.RecoveryDone);
        });
    }

    private static async Task WithSupervisorAsync(InProcessNode node, NodeStore store, RecordingPlatform platform,
        Func<ExecutionSupervisor, CommandProcessor, NodeHeartbeatWriter, Task> verify)
    {
        using var log = new NodeLog(Path.Combine(node.DataRoot, "logs", "node"), LogLevel.Info, node.Clock);
        using var heartbeat = new NodeHeartbeatWriter(node.DataRoot, log, node.Clock);
        await using var processor = new CommandProcessor(store, EventJournal.Open(store), new StreamHub());
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
        await verify(execution, processor, heartbeat);
    }

    private static void WriteExit(InProcessNode node, Id directoryId, Id receiptId, int status = 0, string kind = "exited", DateTimeOffset? at = null)
    {
        var files = new AttemptFiles(node.DataRoot, IdText.Format(directoryId));
        Directory.CreateDirectory(files.Directory);
        HelperFiles.WriteAtomically(files.ExitPath, new ExitRecord
        {
            AttemptId = IdText.Format(receiptId),
            ExitStatus = status,
            ExitCodeKind = kind,
            RecordedAt = (at ?? node.Clock.GetUtcNow()).ToString("O", CultureInfo.InvariantCulture),
        }.ToJson());
    }

    private sealed class FixtureClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    }

    private sealed class RecordingPlatform(bool confirmedMissing = false) : IExecutionPlatform
    {
        public List<string> Queried { get; } = [];
        public List<string> Acknowledged { get; } = [];
        public string Name => "legacy-custody-ack-fixture";
        public MachineCapacity Capacity => new(4, 1L << 30);
        public CapabilityReport Evaluate() => new();
        public void Start(string nodeName, RootLimits limits, string helperExecutable) => throw new NotSupportedException();
        public void UpdateRootLimits(RootLimits limits) { }
        public void Dispose() { }

        public IAttemptHandle? Reopen(string nodeName, AttemptFiles files, RootProcess? root, bool stopping)
        {
            Queried.Add(files.AttemptName);
            return confirmedMissing ? null : throw new LegacyCustodyUnavailableException("The precise fixture scope cannot be queried.");
        }

        public IAdoptedContainer? ReopenAdopted(string containerName)
        {
            Queried.Add(containerName);
            return confirmedMissing ? null : throw new LegacyCustodyUnavailableException("The precise fixture adoption scope cannot be queried.");
        }

        public bool AcknowledgeRecorded(string nodeName, string attemptName)
        {
            Acknowledged.Add(attemptName);
            return true;
        }
    }
}
