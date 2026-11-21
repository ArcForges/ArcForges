// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Recovery and controls for owned legacy attempts, using a real store and execution supervisor.
/// The original Windows execution cases remain at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a,
/// including FIFO admission, native output overshoot, commit and priority classes, and launch/end step order.
/// <see cref="LaunchFaultTests"/> covers queued cancel and limits on retained roots.
/// <see cref="RecoveredLegacyTaskControlsTests"/> covers priority and pause/resume on retained handles.
/// </summary>
public sealed class TaskControlTests
{
    private static readonly Caller Human = new(Origin.Human, ClientKind.Cli, null);
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 30_000)]
    public async Task CancellingARecoveredAttemptRecordsGracefulThenForcedStopAndAccountsTheExit()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRetainedAttemptAsync(async fixture =>
        {
            var (tasks, execution, store, holder, clock, taskId, attemptId) = fixture;
            var recovered = await fixture.ReadAsync();
            Assert.Equal((TaskState.Running, attemptId, true), (recovered.State, recovered.CurrentAttempt.AttemptId, recovered.CurrentAttempt.NodeGap));
            Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM timeline_segment WHERE category = 'node_gap';")));

            var request = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = taskId, Reason = "migration test", GraceMs = 1000 };
            var cancel = await tasks.CancelTask(Human, request, Ct);
            Assert.Null(cancel.Error);
            Assert.Equal((TaskState.Running, EffectCertainty.Happened, request.Meta.CommandId),
                (cancel.Value.State, cancel.Value.Receipt.Effect, cancel.Value.Receipt.CommandId));
            var stopping = await fixture.ReadAsync();
            Assert.Equal(AttemptState.Stopping, stopping.CurrentAttempt.State);
            var running = Assert.IsType<RunningAttempt>(execution.Running(IdText.Format(attemptId)));
            await Assert.IsAssignableFrom<Task>(running.GracefulPhase).WaitAsync(Ct);
            Assert.Equal(1, holder.GracefulStops);
            Assert.Equal(0, holder.Terminations);

            clock.Advance(TimeSpan.FromSeconds(1));
            execution.Start();
            await holder.Acknowledged.WaitAsync(Ct);
            var finished = await fixture.ReadAsync();
            Assert.Equal((TaskState.Cancelled, TerminationReason.Cancelled, EffectCertainty.Happened),
                (finished.State, finished.CurrentAttempt.Result.TerminationReason, finished.CurrentAttempt.Result.Effect));
            Assert.Equal(1, holder.Terminations);
            Assert.Equal(RetainedHolder.ForcedExitCode, finished.CurrentAttempt.Result.ExitCode);
            Assert.Equal((ulong)RetainedHolder.PeakMemory, finished.CurrentAttempt.Usage.MemPeakBytes);
            Assert.Equal(cancel, await tasks.CancelTask(Human, request, Ct));
            var again = await tasks.CancelTask(Human, new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, Ct);
            Assert.Null(again.Error);
            Assert.Equal(TaskState.Cancelled, again.Value.State);
            Assert.Equal(1, holder.Terminations);
        });
    }

    [Fact(Timeout = 30_000)]
    public async Task RecoveredKillWithNodeAttemptIsStoppedAndRecordedOnShutdown()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRetainedAttemptAsync(async fixture =>
        {
            await fixture.Execution.StopAsync();
            Assert.True(fixture.Holder.Acknowledged.IsCompletedSuccessfully);
            var task = await fixture.ReadAsync();
            Assert.Equal((TaskState.Cancelled, TerminationReason.NodeShutdown, EffectCertainty.Happened),
                (task.State, task.CurrentAttempt.Result.TerminationReason, task.CurrentAttempt.Result.Effect));
            Assert.Equal(1, fixture.Holder.Terminations);
            Assert.Equal(0, fixture.Holder.GracefulStops);
        }, prepare: (transaction, taskId, _) =>
        {
            var spec = TaskRecords.GetRow(transaction, taskId.Value.Span)!.Spec;
            spec.Resources.KillWithNode = true;
            var bytes = spec.ToByteArray();
            transaction.Execute("UPDATE task SET spec = $spec, spec_digest = $digest WHERE task_id = $id;",
                ("$spec", bytes), ("$digest", SHA256.HashData(bytes)), ("$id", taskId.Value.ToByteArray()));
        });
    }

    [Theory(Timeout = 30_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DurableExitOrFailedLaunchRecordedWhileNodeStoppedIsRecoveredOnce(bool launchFailed)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRetainedAttemptAsync(async fixture =>
        {
            fixture.Execution.Start();
            await fixture.Holder.Acknowledged.WaitAsync(Ct);
            var task = await fixture.ReadAsync();
            var attempt = task.CurrentAttempt;
            Assert.True(attempt.NodeGap);
            Assert.Equal(AttemptState.Finished, attempt.State);
            Assert.Equal(1L, fixture.Store.Read(reader => reader.Scalar("SELECT count(*) FROM timeline_segment WHERE category = 'node_gap';")));
            if (launchFailed)
            {
                Assert.Equal((TaskState.Failed, TerminationReason.SpawnFailed, EffectCertainty.DidNotHappen),
                    (task.State, attempt.Result.TerminationReason, attempt.Result.Effect));
                Assert.Contains("retained-setup", attempt.Result.Detail, StringComparison.Ordinal);
            }
            else
            {
                Assert.Equal((TaskState.Succeeded, TerminationReason.Exited, EffectCertainty.Happened),
                    (task.State, attempt.Result.TerminationReason, attempt.Result.Effect));
                Assert.Equal((ulong)RetainedHolder.PeakMemory, attempt.Usage.MemPeakBytes);
            }

            Assert.Equal(0, fixture.Holder.Terminations);
        }, phase: launchFailed ? AttemptState.Starting : AttemptState.Running, holderAvailable: false, prepare: (transaction, taskId, holder) =>
        {
            if (launchFailed)
            {
                transaction.Execute("UPDATE task SET started_at = NULL WHERE task_id = $id;", ("$id", taskId.Value.ToByteArray()));
                transaction.Execute("UPDATE attempt SET started_at = NULL WHERE task_id = $id;", ("$id", taskId.Value.ToByteArray()));
                HelperFiles.WriteAtomically(holder.Files.LaunchPath, new LaunchRecord
                {
                    AttemptId = holder.Files.AttemptName, Step = "retained-setup", Error = "fixture failure", ExitCode = 9,
                }.ToJson());
            }

            holder.ReportExit(launchFailed ? 9 : 0);
        });
    }

    [Theory(Timeout = 30_000)]
    [InlineData(true, "boot_changed")]
    [InlineData(false, "container_missing")]
    public async Task AnUnconfirmedRecoveredAttemptIsLostAndFreshRetryDoesNotStartWork(bool earlierBoot, string reason)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRetainedAttemptAsync(async fixture =>
        {
            var lost = await fixture.ReadAsync();
            var result = lost.CurrentAttempt.Result;
            Assert.Equal((TaskState.Lost, reason, TerminationReason.Lost, EffectCertainty.Unknown),
                (lost.State, lost.StateReason, result.TerminationReason, result.Effect));
            Assert.StartsWith(reason + ":", result.Detail, StringComparison.Ordinal);
            if (earlierBoot)
                Assert.Contains("boot_id_old=previous-boot", result.Detail, StringComparison.Ordinal);

            Assert.Equal(earlierBoot ? 0 : 1, fixture.Holder.Reopens);
            var retry = await fixture.Tasks.RetryTask(Human,
                new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = fixture.TaskId }, Ct);
            Assert.Null(retry.Value);
            Assert.Equal((ErrorCategory.Execution, "operation_failed", "legacy_task_outcome_unavailable", EffectCertainty.Unknown, RetryMode.Never),
                (retry.Error.Category, retry.Error.Code, retry.Error.Details.State.Reason, retry.Error.Effect, retry.Error.Retry.Mode));
            Assert.Equal(TaskState.Lost, (await fixture.ReadAsync()).State);
            Assert.Empty(fixture.Execution.RunningAttempts);
            Assert.Equal(0, fixture.Holder.Terminations);
        }, holderAvailable: false, earlierBoot: earlierBoot);
    }

    [Fact(Timeout = 30_000)]
    public async Task ReleasingARetainedTaskBindingIsIdempotentAndKeepsTheAttemptRunning()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRetainedAttemptAsync(async fixture =>
        {
            var callerKey = new CallerKey(int.MaxValue - 1, fixture.Clock.GetUtcNow().Ticks);
            fixture.Execution.CallerConnected(callerKey);
            fixture.Execution.Submitted(fixture.TaskId.Value.Span, callerKey);
            Assert.Equal(callerKey, fixture.Execution.BindingOf(fixture.TaskId.Value.Span));

            var first = new TaskServiceReleaseCallerBindingRequest { Meta = Tasks.Meta(), TaskId = fixture.TaskId };
            var response = await fixture.Tasks.ReleaseCallerBinding(Human, first, Ct);
            Assert.Null(response.Error);
            Assert.Equal((TaskState.Running, EffectCertainty.Happened, first.Meta.CommandId),
                (response.Value.State, response.Value.Receipt.Effect, response.Value.Receipt.CommandId));
            Assert.Null(fixture.Execution.BindingOf(fixture.TaskId.Value.Span));
            var released = fixture.Store.Read(reader => TaskRecords.GetRow(reader, fixture.TaskId.Value.Span))!;
            Assert.NotNull(released.CallerReleasedAt);

            fixture.Execution.CallerDisconnected(callerKey);
            fixture.Clock.Advance(TimeSpan.FromSeconds(1));
            var second = new TaskServiceReleaseCallerBindingRequest { Meta = Tasks.Meta(), TaskId = fixture.TaskId };
            var repeated = await fixture.Tasks.ReleaseCallerBinding(Human, second, Ct);
            Assert.Null(repeated.Error);
            Assert.Equal((TaskState.Running, EffectCertainty.Happened, second.Meta.CommandId),
                (repeated.Value.State, repeated.Value.Receipt.Effect, repeated.Value.Receipt.CommandId));
            var persisted = fixture.Store.Read(reader => TaskRecords.GetRow(reader, fixture.TaskId.Value.Span))!;
            Assert.Equal(released.CallerReleasedAt, persisted.CallerReleasedAt);
            Assert.Equal(TaskState.Running, (await fixture.ReadAsync()).State);
            Assert.Equal(0, fixture.Holder.Terminations);
        });
    }

    [Theory(Timeout = 30_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RetainedOutputOverTheLimitHonorsTerminateOrNotify(bool notify)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        const int limit = 1 << 20;
        const int outputLength = limit + 1;
        await WithRetainedAttemptAsync(async fixture =>
        {
            fixture.Execution.Start();
            if (notify)
            {
                IReadOnlyList<Finding> Findings() => fixture.Store.Read(reader => ExecutionFindings.OpenFor(reader, "attempt", fixture.AttemptId.Value.Span));
                await Tasks.WaitForAsync(() => Findings().Count > 0, TimeSpan.FromSeconds(5), "the retained attempt quota finding");
                Assert.Equal(TaskState.Running, (await fixture.ReadAsync()).State);
                Assert.Equal(0, fixture.Holder.Terminations);
                fixture.Holder.ReportExit(0);
                await fixture.Holder.Acknowledged.WaitAsync(Ct);
                Assert.Equal(TaskState.Succeeded, (await fixture.ReadAsync()).State);
                var finding = Assert.Single(Findings());
                Assert.Equal(FindingKind.QuotaExceeded, finding.Kind);
                Assert.Contains(finding.Evidence, item => item.Name == "detected_by" && item.Value == "NODE");
            }
            else
            {
                await fixture.Holder.Acknowledged.WaitAsync(Ct);
                var task = await fixture.ReadAsync();
                Assert.Equal((TaskState.Failed, TerminationReason.OutputLimit, EffectCertainty.Happened, "NODE"),
                    (task.State, task.CurrentAttempt.Result.TerminationReason, task.CurrentAttempt.Result.Effect, task.CurrentAttempt.LimitEnforcedBy));
                Assert.Equal(1, fixture.Holder.Terminations);
                Assert.Equal(0, fixture.Holder.GracefulStops);
            }

            var output = await fixture.Tasks.ReadTaskOutput(Human, new TaskServiceReadTaskOutputRequest
            {
                Meta = Tasks.Meta(), AttemptId = fixture.AttemptId, Stream = OutputStream.Stdout, FromOffset = 0, MaxBytes = outputLength,
            }, Ct);
            Assert.Null(output.Error);
            Assert.Equal(outputLength, output.Value.Data.Length);
        }, prepare: (transaction, _, holder) =>
        {
            Tasks.SeedPolicy(transaction, policy =>
            {
                policy.Storage.MaxAttemptOutputBytes = limit;
                policy.Storage.DiskLimitAction = notify ? DiskLimitAction.Notify : DiskLimitAction.Terminate;
            });
            File.WriteAllBytes(holder.Files.StdoutPath, new byte[outputLength]);
        });
    }

    private static async Task WithRetainedAttemptAsync(Func<RetainedAttempt, Task> verify, AttemptState phase = AttemptState.Running,
        bool holderAvailable = true, bool earlierBoot = false, Action<StoreTransaction, Id, RetainedHolder>? prepare = null)
    {
        await using var fixture = InProcessNode.Create();
        var clock = new FixtureClock();
        fixture.Clock = clock;
        var root = phase == AttemptState.Starting ? null : new RootProcess(int.MaxValue, clock.GetUtcNow());
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(fixture, phase, root: root);
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = BootIdentity.Read(), Clock = clock });
        var files = Tasks.Files(fixture, attemptId);
        Directory.CreateDirectory(files.Directory);
        using var holder = new RetainedHolder(IdText.Format(store.Metadata.NodeId.Span), files, clock, root, holderAvailable);
        store.Write(transaction =>
        {
            if (earlierBoot)
            {
                transaction.Execute("UPDATE attempt SET boot_identity = 'previous-boot' WHERE attempt_id = $id;",
                    ("$id", attemptId.Value.ToByteArray()));
            }

            prepare?.Invoke(transaction, taskId, holder);
        }, CommitDurability.Full);

        using var log = new NodeLog(Path.Combine(fixture.DataRoot, "logs", "node"), LogLevel.Info, clock);
        using var heartbeat = new NodeHeartbeatWriter(fixture.DataRoot, log, clock);
        using var keys = new NodeDataKeyRing(store, fixture.Secrets.Selection);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store, Processor = processor, Log = log, Clock = clock, DataRoot = fixture.DataRoot,
            Platform = holder, Secrets = new TaskSecrets(store, keys), Heartbeat = heartbeat,
        });
        var recovery = new RecoveryReport(true, earlierBoot, null, store.Opening);
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(fixture.ConfigPath, fixture.DataRoot, log), fixture.DataRoot, "offline-fixture", clock,
            recovery, new CapabilityReport()) { Execution = execution };
        await runtime.TransitionAsync(NodeLifecycleState.Recovering, "fixture").WaitAsync(Ct);
        await execution.RecoverAsync(recovery, processor, Ct);
        await runtime.TransitionAsync(NodeLifecycleState.Ready, "fixture").WaitAsync(Ct);

        await verify(new RetainedAttempt(new TaskServiceHandler(runtime, new ClientSessions()), execution, store, holder, clock, taskId, attemptId));
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
    }

    private sealed record RetainedAttempt(TaskServiceHandler Tasks, ExecutionSupervisor Execution, NodeStore Store, RetainedHolder Holder,
        FixtureClock Clock, Id TaskId, Id AttemptId)
    {
        public async Task<ManagedTask> ReadAsync()
        {
            var result = await Tasks.GetTask(Human, new TaskServiceGetTaskRequest { TaskId = TaskId }, Ct);
            Assert.Null(result.Error);
            Assert.Equal(AttemptId, result.Value.Task.CurrentAttempt.AttemptId);
            return result.Value.Task;
        }
    }

    private sealed class FixtureClock : TimeProvider
    {
        private long _timestamp;
        public override long TimestampFrequency => TimeProvider.System.TimestampFrequency;
        public override long GetTimestamp() => Interlocked.Read(ref _timestamp);
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddDays(1) + GetElapsedTime(0, GetTimestamp());
        public void Advance(TimeSpan elapsed) => Interlocked.Add(ref _timestamp, (long)(elapsed.TotalSeconds * TimestampFrequency));
    }

    private sealed class RetainedHolder(string nodeName, AttemptFiles files, FixtureClock clock, RootProcess? root, bool available)
        : IExecutionPlatform, IAttemptHandle
    {
        public const int ForcedExitCode = 17;
        public const long PeakMemory = 64L << 20;
        private readonly TaskCompletionSource _acknowledged = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _gracefulStops;
        private int _terminations;
        private int _exited;

        public AttemptFiles Files => files;
        public int Reopens { get; private set; }
        public int GracefulStops => Volatile.Read(ref _gracefulStops);
        public int Terminations => Volatile.Read(ref _terminations);
        public Task Acknowledged => _acknowledged.Task;
        public string Name => "retained-control-fixture";
        public MachineCapacity Capacity => new(4, 1L << 30);
        public string ContainerName => "retained-holder-fixture";
        public RootProcess? Root => root;
        public Task<RootProcess?> Started => Task.FromResult(Root);
        public bool RootRunning => Volatile.Read(ref _exited) == 0;
        public bool MemoryLimitHit => false;
        public Stream? StdinWriter => null;
        public bool UsageNeedsProcessTable => false;
        public event Action? Changed;

        public IAttemptHandle? Reopen(string node, AttemptFiles retainedFiles, RootProcess? retainedRoot, bool stopping)
        {
            Assert.Equal(nodeName, node);
            Assert.Equal(files.AttemptName, retainedFiles.AttemptName);
            Assert.Equal(root, retainedRoot);
            Assert.False(stopping);
            Reopens++;
            return available ? this : null;
        }

        public GracefulOutcome RequestGracefulStop()
        {
            Interlocked.Increment(ref _gracefulStops);
            return new(true, 0, null);
        }

        public void Terminate()
        {
            Interlocked.Increment(ref _terminations);
            ReportExit(ForcedExitCode);
        }

        public void ReportExit(int exitCode)
        {
            HelperFiles.WriteAtomically(files.ExitPath, new ExitRecord
            {
                AttemptId = files.AttemptName, ExitStatus = exitCode,
                RecordedAt = clock.GetUtcNow().ToString("O", CultureInfo.InvariantCulture),
                MemPeakBytes = PeakMemory,
            }.ToJson());
            Volatile.Write(ref _exited, 1);
            Changed?.Invoke();
        }

        public CapabilityReport Evaluate() => new();
        public bool AcknowledgeRecorded(string node, string attempt)
        {
            Assert.Equal(nodeName, node);
            Assert.Equal(files.AttemptName, attempt);
            Acknowledge();
            return true;
        }

        public void UpdateRootLimits(RootLimits limits) { }
        public ExitRecord? TryReadExit() => ExitRecord.TryRead(files.ExitPath);
        public LaunchRecord? TryReadLaunchFailure() => LaunchRecord.TryRead(files.LaunchPath);
        public IReadOnlyList<ContainerProcess> Processes() => [];
        public ContainerAccounting Accounting() => new(0, 0, PeakMemory, 0, 0, RootRunning ? 1 : 0, []);
        public IReadOnlyList<EscapedProcess> ScanEscaped() => [];
        public void Acknowledge() => _acknowledged.TrySetResult();
        public void Dispose() { }
        public void Start(string node, RootLimits limits, string helperExecutable) =>
            throw new InvalidOperationException("The retained control fixture must not start a process.");
    }
}
