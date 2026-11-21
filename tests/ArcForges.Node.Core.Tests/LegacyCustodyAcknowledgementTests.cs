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
    [Fact(Timeout = 30_000)]
    public async Task RecoveryAcknowledgesOnlyTheExactFinishedLocalAttemptAndKeepsEarlierBootEvidence()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = InProcessNode.Create();
        var recordedExit = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var differentReceipt = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var foreignExecutor = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var earlierBootExit = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished).AttemptId;
        var (earlierBootTask, earlierBootAttempt) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Running);
        var (currentTask, currentAttempt) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Running);
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = BootIdentity.Read(), Clock = node.Clock });
        store.Write(transaction =>
        {
            transaction.Execute("UPDATE attempt SET executor_node_id = $other WHERE attempt_id = $id;",
                ("$other", CommandIds.New().Value.ToByteArray()), ("$id", foreignExecutor.Value.ToByteArray()));
            // A previous store open has already recorded the current boot in store_meta.
            transaction.Execute("UPDATE attempt SET boot_identity = 'fixture-original-boot' WHERE attempt_id IN ($exit, $live);",
                ("$exit", earlierBootExit.Value.ToByteArray()), ("$live", earlierBootAttempt.Value.ToByteArray()));
        }, CommitDurability.Full);

        WriteExit(node, recordedExit, recordedExit);
        WriteExit(node, differentReceipt, recordedExit);
        WriteExit(node, foreignExecutor, foreignExecutor);
        WriteExit(node, earlierBootExit, earlierBootExit);
        WriteExit(node, currentAttempt, currentAttempt);
        var noAttemptRow = CommandIds.New();
        WriteExit(node, noAttemptRow, noAttemptRow);

        using var log = new NodeLog(Path.Combine(node.DataRoot, "logs", "node"), LogLevel.Info, node.Clock);
        using var heartbeat = new NodeHeartbeatWriter(node.DataRoot, log, node.Clock);
        using var keys = new NodeDataKeyRing(store, node.Secrets.Selection);
        using var platform = new RecordingPlatform();
        await using var processor = new CommandProcessor(store, EventJournal.Open(store), new StreamHub());
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
        Assert.Equal([IdText.Format(recordedExit)], platform.Acknowledged);
        Assert.Equal([IdText.Format(currentAttempt)], platform.Queried);
        var prior = store.Read(reader => TaskRecords.GetTask(reader, earlierBootTask.Value.Span, full: true));
        Assert.NotNull(prior);
        Assert.Equal((TaskState.Lost, "boot_changed", earlierBootAttempt),
            (prior.State, prior.StateReason, prior.CurrentAttempt.AttemptId));
        Assert.Equal(EffectCertainty.Unknown, prior.CurrentAttempt.Result.Effect);
        Assert.Equal(TaskState.Running, store.Read(reader => TaskRecords.GetTask(reader, currentTask.Value.Span, full: false)?.State));
        Assert.True(heartbeat.RecoveryDone);
    }

    private static void WriteExit(InProcessNode node, Id directoryId, Id receiptId)
    {
        var files = new AttemptFiles(node.DataRoot, IdText.Format(directoryId));
        Directory.CreateDirectory(files.Directory);
        HelperFiles.WriteAtomically(files.ExitPath, new ExitRecord
        {
            AttemptId = IdText.Format(receiptId),
            RecordedAt = node.Clock.GetUtcNow().ToString("O", CultureInfo.InvariantCulture),
        }.ToJson());
    }

    private sealed class RecordingPlatform : IExecutionPlatform
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
            throw new LegacyCustodyUnavailableException("The precise fixture scope cannot be queried.");
        }

        public bool AcknowledgeRecorded(string nodeName, string attemptName)
        {
            Acknowledged.Add(attemptName);
            return true;
        }
    }
}
