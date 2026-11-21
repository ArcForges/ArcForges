// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed partial class LaunchFaultTests
{
    // The original native launch-clock and blocked started.json checks reproduce from
    // eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a. Current V2 recovery owns its exact resource
    // readback and prepared-owner/Stop evidence in RecoveryMxcRunServiceTests and RecoveryPreparedMxcRunServiceTests.

    [Theory(Timeout = 30_000)]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ARecoveredLegacyRootKeepsItsOriginalClockAndEnforcesItsRecordedLimit(bool cpu, bool startedInGap)
    {
        var ct = TestContext.Current.CancellationToken;
        await UseRecoveredAttemptAsync(AttemptState.Starting, startedInGap, spec =>
        {
            if (cpu)
                spec.CpuTimeLimitMs = 1_500;
            else
                spec.TimeoutMs = 2_000;
        }, async fixture =>
        {
            var handle = fixture.Handle;
            if (!startedInGap)
            {
                // A reported container member and elapsed time before the original root do not start its clock.
                fixture.Clock.Advance(TimeSpan.FromSeconds(3));
                await handle.ObservePassesAsync();
                Assert.Equal(AttemptState.Starting, fixture.ReadAttempt().State);
                Assert.Null(fixture.ReadAttempt().StartedAt);
                Assert.Null(fixture.ReadAttempt().RootPid);
                Assert.Equal(0, handle.Terminations);
                handle.ReportOriginalRoot();
            }

            var start = Assert.IsType<RecordedStart>(handle.OriginalStart);
            await Tasks.WaitForAsync(() => fixture.ReadAttempt().StartedAt is not null,
                TimeSpan.FromSeconds(5), "the original root clock to be recorded");
            var original = fixture.ReadAttempt();
            Assert.True(fixture.ReadTask().CurrentAttempt.NodeGap);
            Assert.Equal(start.Process.Pid, original.RootPid);
            Assert.Equal(StoreTime.ToMicroseconds(start.Process.StartTime), original.RootStart);
            Assert.Equal(StoreTime.ToMicroseconds(start.ResumedAt), original.StartedAt);

            if (cpu)
            {
                await handle.ObservePassesAsync();
                Assert.Equal(0, handle.Terminations);
                handle.ReportCpuLimitReached();
                fixture.Clock.Advance(TimeSpan.FromSeconds(1));
            }
            else if (!startedInGap)
            {
                fixture.Clock.Advance(TimeSpan.FromMilliseconds(1_900));
                await handle.ObservePassesAsync();
                Assert.Equal(0, handle.Terminations);
                fixture.Clock.Advance(TimeSpan.FromMilliseconds(100));
            }

            var reason = cpu ? TerminationReason.CpuTimeExceeded : TerminationReason.TimedOut;
            await handle.WaitForTerminationsAsync(1);
            var stopping = fixture.ReadAttempt();
            Assert.Equal(AttemptState.Stopping, stopping.State);
            Assert.Equal(reason, stopping.Reason);
            Assert.False(handle.Acknowledged.IsCompleted);

            handle.ReportOriginalExit();
            await handle.Acknowledged.WaitAsync(TimeSpan.FromSeconds(5), ct);
            fixture.AssertFinished(TaskState.Failed, reason);
            if (cpu)
                Assert.Equal(1_500ul, fixture.ReadTask().CurrentAttempt.Usage.CpuTimeMs);
        }, ct);
    }

    private static async Task UseRecoveredAttemptAsync(AttemptState storedState, bool startedInGap,
        Action<TaskSpec>? configure, Func<RecoveredAttemptCheck, Task> check, CancellationToken cancellationToken)
    {
        await using var node = InProcessNode.Create();
        var clock = new RecoveredLimitClock();
        node.Clock = clock;
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(node, storedState);
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = BootIdentity.Read(), Clock = clock });
        var attemptName = IdText.Format(attemptId);
        var files = new AttemptFiles(node.DataRoot, attemptName);
        Directory.CreateDirectory(files.Directory);
        store.Write(transaction =>
        {
            var spec = TaskRecords.GetRow(transaction, taskId.Value.Span)!.Spec;
            spec.Resources = new ResourceSpec { CancelGraceMs = 0 };
            configure?.Invoke(spec);
            var bytes = spec.ToByteArray();
            transaction.Execute("UPDATE task SET spec=$spec, spec_digest=$digest WHERE task_id=$id;",
                ("$spec", bytes), ("$digest", SHA256.HashData(bytes)), ("$id", taskId.Value.ToByteArray()));
            transaction.Execute("UPDATE attempt SET started_at=NULL, termination_reason=$reason WHERE attempt_id=$id;",
                ("$reason", storedState == AttemptState.Stopping ? (int)TerminationReason.Cancelled : null),
                ("$id", attemptId.Value.ToByteArray()));
        }, CommitDurability.Full);

        using var handle = new RecoveredLimitHandle(IdText.Format(store.Metadata.NodeId.Span), files, clock, storedState);
        if (startedInGap)
        {
            handle.ReportOriginalRoot();
            clock.Advance(TimeSpan.FromSeconds(3));
        }

        using var log = new NodeLog(Path.Combine(node.DataRoot, "logs", "node"), LogLevel.Info, clock);
        using var heartbeat = new NodeHeartbeatWriter(node.DataRoot, log, clock);
        using var keys = new NodeDataKeyRing(store, node.Secrets.Selection);
        await using var processor = new CommandProcessor(store, EventJournal.Open(store), new StreamHub());
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = clock,
            DataRoot = node.DataRoot,
            Platform = handle,
            Secrets = new TaskSecrets(store, keys),
            Heartbeat = heartbeat,
        });
        await execution.RecoverAsync(new RecoveryReport(true, false, null, store.Opening), processor, cancellationToken);
        Assert.Equal(1, handle.Reopens);
        Assert.Same(handle, execution.Running(attemptName)?.Handle);
        execution.Start();
        await check(new RecoveredAttemptCheck(store, taskId, attemptId, handle, clock));
    }

    private sealed record RecoveredAttemptCheck(NodeStore Store, Id TaskId, Id AttemptId, RecoveredLimitHandle Handle, RecoveredLimitClock Clock)
    {
        public AttemptRow ReadAttempt() => Store.Read(reader => TaskRecords.GetAttemptRow(reader, AttemptId.Value.Span))!;

        public ManagedTask ReadTask() => Store.Read(reader => TaskRecords.GetTask(reader, TaskId.Value.Span, full: false))!;

        public void AssertFinished(TaskState state, TerminationReason reason)
        {
            var task = ReadTask();
            var attempt = task.CurrentAttempt;
            Assert.Equal(AttemptId, attempt.AttemptId);
            Assert.Equal(AttemptState.Finished, attempt.State);
            Assert.Equal(reason, attempt.Result.TerminationReason);
            Assert.Equal(EffectCertainty.Happened, attempt.Result.Effect);
            Assert.True(attempt.NodeGap);
            Assert.Equal(state, task.State);
            Assert.Equal(1L, Store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
        }
    }

    private sealed class RecoveredLimitClock : TimeProvider
    {
        private long _timestamp;
        public override long TimestampFrequency => TimeProvider.System.TimestampFrequency;
        public override long GetTimestamp() => Interlocked.Read(ref _timestamp);
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddDays(1) + GetElapsedTime(0, GetTimestamp());
        public void Advance(TimeSpan elapsed) => Interlocked.Add(ref _timestamp, (long)(elapsed.TotalSeconds * TimestampFrequency));
    }

    private sealed record RecordedStart(RootProcess Process, DateTimeOffset ResumedAt);

    // The only platform substitute: no process is launched and the real retained-attempt supervisor consumes these observations.
    private sealed class RecoveredLimitHandle(string nodeName, AttemptFiles files, TimeProvider clock, AttemptState state)
        : IExecutionPlatform, IAttemptHandle
    {
        private readonly TaskCompletionSource<RootProcess?> _pendingStart = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _acknowledged = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private RecordedStart? _originalStart;
        private int _refreshes;
        private int _terminations;
        private long _cpuUserMs = 999;

        public int Reopens { get; private set; }
        public int Terminations => Volatile.Read(ref _terminations);
        public Task Acknowledged => _acknowledged.Task;
        public RecordedStart? OriginalStart => Volatile.Read(ref _originalStart);
        public string Name => "retained-limit-fixture";
        public MachineCapacity Capacity => new(4, 1L << 30);
        public string ContainerName => "retained-fixture";
        public RootProcess? Root => OriginalStart?.Process;
        public DateTimeOffset? StartedAt => OriginalStart?.ResumedAt;
        public Task<RootProcess?> Started => state == AttemptState.Stopping ? _pendingStart.Task : Task.FromResult(Root);
        public Stream? StdinWriter => null;
        public bool RootRunning => Terminations == 0;
        public bool MemoryLimitHit => false;
        public event Action? Changed;
        public event Action<int>? LaunchProcessEntered;

        public IAttemptHandle Reopen(string node, AttemptFiles originalFiles, RootProcess? persistedRoot, bool stopping)
        {
            Assert.Equal(nodeName, node);
            Assert.Equal(files.AttemptName, originalFiles.AttemptName);
            Assert.Null(persistedRoot);
            Assert.Equal(state == AttemptState.Stopping, stopping);
            Reopens++;
            return this;
        }

        public void ReportOriginalRoot()
        {
            var resumed = clock.GetUtcNow();
            var root = new RootProcess(int.MaxValue, resumed.AddMilliseconds(-100));
            Volatile.Write(ref _originalStart, new(root, resumed));
            _pendingStart.TrySetResult(root);
            Changed?.Invoke();
        }

        public void ReportLaterMember() => LaunchProcessEntered?.Invoke(int.MaxValue - 1);

        public void ReportCpuLimitReached()
        {
            Interlocked.Exchange(ref _cpuUserMs, 1_000);
            Changed?.Invoke();
        }

        public void ReportOriginalExit()
        {
            HelperFiles.WriteAtomically(files.ExitPath, new ExitRecord
            {
                AttemptId = files.AttemptName,
                ExitStatus = 137,
                ServiceResult = "exit-code",
                RecordedAt = clock.GetUtcNow().ToString("O", CultureInfo.InvariantCulture),
                CpuUserMs = Interlocked.Read(ref _cpuUserMs),
                CpuKernelMs = 500,
            }.ToJson());
            Changed?.Invoke();
        }

        public Task ObservePassesAsync()
        {
            var target = Volatile.Read(ref _refreshes) + 2;
            Changed?.Invoke();
            return Tasks.WaitForAsync(() => Volatile.Read(ref _refreshes) >= target, TimeSpan.FromSeconds(5),
                "the recovered attempt to observe the fixture state");
        }

        public Task WaitForTerminationsAsync(int count) =>
            Tasks.WaitForAsync(() => Terminations >= count, TimeSpan.FromSeconds(5), "the original handle to receive termination");

        public void Refresh() => Interlocked.Increment(ref _refreshes);
        public CapabilityReport Evaluate() => new();
        public void UpdateRootLimits(RootLimits limits) { }
        public bool AcknowledgeRecorded(string node, string attempt) => false;
        public ExitRecord? TryReadExit() => ExitRecord.TryRead(files.ExitPath);
        public LaunchRecord? TryReadLaunchFailure() => null;
        public IReadOnlyList<ContainerProcess> Processes() => [];
        public ContainerAccounting Accounting() => new(Interlocked.Read(ref _cpuUserMs), 500, 0, 0, 0, RootRunning ? 1 : 0, []);
        public IReadOnlyList<EscapedProcess> ScanEscaped() => [];
        public void Acknowledge() => _acknowledged.TrySetResult();
        public void Dispose() { }
        public void Start(string node, RootLimits limits, string helperExecutable) => throw new NotSupportedException();
        public void Terminate() => Interlocked.Increment(ref _terminations);
        public GracefulOutcome RequestGracefulStop() => new(false, 0, "synthetic scope waits for force");
    }
}
