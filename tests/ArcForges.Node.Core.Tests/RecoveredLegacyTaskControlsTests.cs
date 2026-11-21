// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real recovery, command handling and SQLite with only the retained platform handle simulated.</summary>
public sealed class RecoveredLegacyTaskControlsTests
{
    private static readonly Caller Human = new(Origin.Human, ClientKind.Cli, null);
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 30_000)]
    public async Task RunningTaskPriorityUpdatesTheReopenedHandleAndRejectsAPoolChange()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredTaskAsync(AttemptState.Running, null, async fixture =>
        {
            var set = await fixture.Tasks.SetTaskPriority(Human, new TaskServiceSetTaskPriorityRequest
            {
                Meta = InProcessNode.Command(),
                TaskId = fixture.TaskId,
                Priority = Priority.Low,
            }, Ct);
            Assert.Null(set.Error);
            Assert.Equal(EffectCertainty.Happened, set.Value.Receipt.Effect);
            await fixture.DrainAsync();

            var retained = await fixture.ReadAsync();
            Assert.Equal((Priority.Low, TaskState.Running), (retained.EffectivePriority, retained.State));
            Assert.Equal([("cpu-weight", 3L)], fixture.Platform.Calls);
            Assert.Equal(3L, fixture.Store.Read(reader => reader.Scalar(
                "SELECT cpu_weight FROM attempt WHERE attempt_id = $id;", ("$id", fixture.AttemptId.Value.ToByteArray()))));

            var pool = await fixture.Tasks.SetTaskPriority(Human, new TaskServiceSetTaskPriorityRequest
            {
                Meta = InProcessNode.Command(),
                TaskId = fixture.TaskId,
                Pool = "background",
            }, Ct);
            Assert.Equal("invalid_argument", pool.Error?.Code);
            await fixture.DrainAsync();
            Assert.Equal([("cpu-weight", 3L)], fixture.Platform.Calls);
        });
    }

    [Fact(Timeout = 30_000)]
    public async Task UnavailableAttemptCustodyKeepsTheAttemptForExactReopen()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredTaskAsync(AttemptState.Running, null, async fixture =>
        {
            var recovered = await fixture.ReadAsync();
            Assert.Equal(TaskState.Running, recovered.State);
            Assert.Equal(fixture.TaskId, recovered.TaskId);
            Assert.Same(fixture.Platform, fixture.Execution.Running(IdText.Format(fixture.AttemptId))?.Handle);
            Assert.Empty(fixture.Platform.Calls);
        }, initiallyUnavailable: true);
    }

    [Fact(Timeout = 30_000)]
    public async Task SameAttemptDurableExitCanSettleWhenNativeCustodyCannotBeQueried()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredTaskAsync(AttemptState.Running, null, async fixture =>
        {
            Assert.Null(fixture.Execution.Running(IdText.Format(fixture.AttemptId))?.Handle);
            fixture.Execution.Start();
            var waited = await fixture.Tasks.WaitTask(Human, new TaskServiceWaitTaskRequest
            {
                TaskId = fixture.TaskId,
                Target = WaitTarget.Terminal,
                WaitMs = 10_000,
            }, Ct);
            Assert.Null(waited.Error);
            Assert.True(waited.Value.Reached);
            var settled = await fixture.ReadAsync();
            Assert.Equal(TaskState.Failed, settled.State);
            Assert.Equal(AttemptState.Finished, settled.CurrentAttempt.State);
            Assert.Equal(9, settled.CurrentAttempt.Result.ExitCode);
            Assert.Equal(EffectCertainty.Happened, settled.CurrentAttempt.Result.Effect);
            Assert.Empty(fixture.Platform.Calls);
        }, initiallyUnavailable: true, useRetainedExit: true);
    }

    [Theory(Timeout = 30_000)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task UnavailableLateStartWatchLeavesStopDueAndRetryForcesOnce(int unavailableObservations)
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await WithRecoveredTaskAsync(AttemptState.Starting, null, async fixture =>
        {
            var name = IdText.Format(fixture.AttemptId);
            var attempt = Assert.IsType<RunningAttempt>(fixture.Execution.Running(name));
            fixture.Platform.UnavailableLateWatchObservations = unavailableObservations;

            await fixture.Execution.StopAsync(name, TerminationReason.Cancelled, null, graceful: false).WaitAsync(ct);
            var pending = await fixture.ReadAsync();
            Assert.Equal(AttemptState.Stopping, pending.CurrentAttempt.State);
            Assert.Null(pending.CurrentAttempt.Result);
            Assert.False(attempt.Forced);
            Assert.False(attempt.Finalizing);
            Assert.False(attempt.TerminationOwed);
            Assert.False(attempt.LaunchProcessesWatched);
            Assert.Equal(fixture.Clock.GetTimestamp(), attempt.GraceDeadline);
            Assert.Equal(1, fixture.Platform.LateWatchCalls);
            Assert.Equal(0, fixture.Platform.LaunchSubscribers);
            Assert.Equal(0, fixture.Platform.ForceCalls);

            fixture.Execution.Start();
            await fixture.Platform.ForcedReached.Task.WaitAsync(TimeSpan.FromSeconds(5), ct);
            await fixture.Execution.StopAsync(name, TerminationReason.Cancelled, null, graceful: false).WaitAsync(ct);
            lock (attempt)
            {
                Assert.True(attempt.Forced);
                Assert.True(attempt.TerminationOwed);
                Assert.True(attempt.LaunchProcessesWatched);
                Assert.False(attempt.Finalizing);
                Assert.Equal(unavailableObservations + 1, fixture.Platform.LateWatchCalls);
                Assert.Equal(1, fixture.Platform.LaunchSubscribers);
                Assert.Equal(1, fixture.Platform.ForceCalls);
            }
        }, rootPending: true);
    }

    [Fact(Timeout = 30_000)]
    public async Task ExplicitPauseAndResumePersistStateAndControlTheReopenedHandle()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredTaskAsync(AttemptState.Running, null, async fixture =>
        {
            var pause = await fixture.Tasks.PauseTask(Human, new TaskServicePauseTaskRequest
            {
                Meta = InProcessNode.Command(),
                TaskId = fixture.TaskId,
            }, Ct);
            Assert.Null(pause.Error);
            Assert.Equal(EffectCertainty.Happened, pause.Value.Receipt.Effect);
            await fixture.DrainAsync();
            var paused = await fixture.ReadAsync();
            Assert.Equal((TaskState.Paused, AttemptState.Paused), (paused.State, paused.CurrentAttempt.State));
            Assert.Equal([("freeze", 0L)], fixture.Platform.Calls);

            await WaitThroughNormalPressureAsync(fixture);
            Assert.Equal(TaskState.Paused, (await fixture.ReadAsync()).State);
            Assert.Equal([("freeze", 0L)], fixture.Platform.Calls);

            var resume = await fixture.Tasks.ResumeTask(Human, new TaskServiceResumeTaskRequest
            {
                Meta = InProcessNode.Command(),
                TaskId = fixture.TaskId,
            }, Ct);
            Assert.Null(resume.Error);
            Assert.Equal(EffectCertainty.Happened, resume.Value.Receipt.Effect);
            await fixture.DrainAsync();
            var running = await fixture.ReadAsync();
            Assert.Equal((TaskState.Running, AttemptState.Running), (running.State, running.CurrentAttempt.State));
            Assert.Equal([("freeze", 0L), ("thaw", 0L)], fixture.Platform.Calls);
        });
    }

    [Fact(Timeout = 30_000)]
    public async Task RecoveredPressureFreezeThawsOnlyAfterThirtyNormalSecondsAndRestoresMemoryHigh()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredTaskAsync(AttemptState.Paused, ExecutionSupervisor.PressureFrozen + ": retained pressure", async fixture =>
        {
            Assert.Equal(TaskState.Paused, (await fixture.ReadAsync()).State);
            await WaitThroughNormalPressureAsync(fixture);
            var running = await fixture.ReadAsync();
            Assert.Equal((TaskState.Running, AttemptState.Running), (running.State, running.CurrentAttempt.State));
            Assert.Equal([("memory-high", 64L * 1024 * 1024), ("thaw", 0L)], fixture.Platform.Calls);
        });
    }

    private static async Task WaitThroughNormalPressureAsync(RecoveredControlFixture fixture)
    {
        var response = (IPressureResponse)fixture.Execution;
        var state = new ResourceState
        {
            At = fixture.Clock.GetUtcNow(),
            CapacityCpu = 4000,
            CapacityMemory = 1L << 30,
            ReserveCpu = 1000,
            ReserveMemory = 64L << 20,
            BudgetCpu = 3000,
            BudgetMemory = 512L << 20,
        };
        var priorCalls = fixture.Platform.Calls.Count;
        response.Respond(PressureLevel.Normal, PressureLevel.Pressure, state);
        fixture.Clock.Advance(TimeSpan.FromSeconds(29));
        response.Respond(PressureLevel.Normal, PressureLevel.Normal, state with { At = fixture.Clock.GetUtcNow() });
        await fixture.DrainAsync();
        Assert.Equal(priorCalls, fixture.Platform.Calls.Count);
        fixture.Clock.Advance(TimeSpan.FromSeconds(1));
        response.Respond(PressureLevel.Normal, PressureLevel.Normal, state with { At = fixture.Clock.GetUtcNow() });
        await fixture.DrainAsync();
    }

    private static async Task WithRecoveredTaskAsync(AttemptState phase, string? reason, Func<RecoveredControlFixture, Task> verify,
        bool initiallyUnavailable = false, bool useRetainedExit = false, bool rootPending = false)
    {
        await using var node = InProcessNode.Create();
        var clock = new ControlledClock();
        node.Clock = clock;
        var root = rootPending ? null : new RootProcess(int.MaxValue, clock.GetUtcNow());
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(node, phase, root: root, stateReason: reason);
        var name = IdText.Format(attemptId);
        var files = new AttemptFiles(node.DataRoot, name);
        Directory.CreateDirectory(files.Directory);

        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = BootIdentity.Read(), Clock = clock });
        using var platform = new ReopenedPlatform(IdText.Format(store.Metadata.NodeId.Span), name, root, phase == AttemptState.Paused);
        using var log = new NodeLog(Path.Combine(node.DataRoot, "logs", "node"), LogLevel.Info, clock);
        using var heartbeat = new NodeHeartbeatWriter(node.DataRoot, log, clock);
        using var keys = new NodeDataKeyRing(store, node.Secrets.Selection);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        var recovery = new RecoveryReport(true, false, null, store.Opening);
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = clock,
            DataRoot = node.DataRoot,
            Platform = platform,
            Secrets = new TaskSecrets(store, keys),
            Heartbeat = heartbeat,
        });
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(node.ConfigPath, node.DataRoot, log), node.DataRoot, "offline-fixture", clock,
            recovery, new CapabilityReport())
        { Execution = execution };
        await runtime.TransitionAsync(NodeLifecycleState.Recovering, "fixture").WaitAsync(Ct);
        if (initiallyUnavailable)
        {
            var nativeError = new LegacyCustodyUnavailableException("The user manager is unavailable.");
            platform.ReopenError = nativeError;
            // Even a valid record for a different attempt cannot replace this attempt's native ownership proof.
            var unrelatedExit = new ExitRecord { AttemptId = IdText.Format(taskId), RecordedAt = clock.GetUtcNow().ToString("O", System.Globalization.CultureInfo.InvariantCulture) };
            HelperFiles.WriteAtomically(files.ExitPath, unrelatedExit.ToJson());
            ManagedTask? ReadTask() => store.Read(reader => TaskRecords.GetTask(reader, taskId.Value.Span, full: true));
            var original = ReadTask();
            Assert.NotNull(original);
            var recoverCursor = journal.LatestPosition;
            var error = await Assert.ThrowsAsync<LegacyCustodyUnavailableException>(() => execution.RecoverAsync(recovery, processor, Ct));
            Assert.Same(nativeError, error.InnerException);
            Assert.Equal(original, ReadTask());
            Assert.Equal(recoverCursor, journal.LatestPosition);
            Assert.False(heartbeat.RecoveryDone);
            Assert.Empty(execution.RunningAttempts);
            Assert.Empty(platform.Calls);
            if (useRetainedExit)
            {
                unrelatedExit.AttemptId = files.AttemptName;
                unrelatedExit.ExitStatus = 9;
                unrelatedExit.ServiceResult = "exit-code";
                HelperFiles.WriteAtomically(files.ExitPath, unrelatedExit.ToJson());
            }
            else
            {
                File.Delete(files.ExitPath);
                platform.ReopenError = null;
            }
        }

        await execution.RecoverAsync(recovery, processor, Ct);
        await runtime.TransitionAsync(NodeLifecycleState.Ready, "fixture").WaitAsync(Ct);
        Assert.Equal(initiallyUnavailable ? 2 : 1, platform.ReopenCalls);

        var handler = new TaskServiceHandler(runtime, new ClientSessions());
        await verify(new RecoveredControlFixture(store, processor, execution, handler, taskId, attemptId, platform, clock));
    }

    private sealed record RecoveredControlFixture(NodeStore Store, CommandProcessor Processor, ExecutionSupervisor Execution,
        TaskServiceHandler Tasks, Id TaskId, Id AttemptId, ReopenedPlatform Platform, ControlledClock Clock)
    {
        public async Task<ManagedTask> ReadAsync()
        {
            var result = await Tasks.GetTask(Human, new TaskServiceGetTaskRequest { TaskId = TaskId }, Ct);
            Assert.Null(result.Error);
            var task = result.Value.Task;
            Assert.Equal(AttemptId, task.CurrentAttempt.AttemptId);
            Assert.True(task.CurrentAttempt.NodeGap);
            Assert.Equal(1u, task.AttemptCount);
            return task;
        }

        public async Task DrainAsync()
        {
            await Execution.PlatformCalls.DrainAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(0, Execution.PlatformCalls.Pending);
            await Processor.ExecuteAsync(context => 0).WaitAsync(Ct);
        }
    }

    private sealed class ControlledClock : TimeProvider
    {
        private long _ticks;

        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddDays(1).AddTicks(GetTimestamp());
        public override long GetTimestamp() => Interlocked.Read(ref _ticks);
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public void Advance(TimeSpan elapsed) => Interlocked.Add(ref _ticks, elapsed.Ticks);
    }

    private sealed class ReopenedPlatform(string nodeName, string attemptName, RootProcess? root, bool frozen) : IExecutionPlatform, IAttemptHandle
    {
        private bool _frozen = frozen;
        private int _lateWatchCalls;
        private int _forceCalls;
        private Action<int>? _launchEntered;
        public List<(string Operation, long Value)> Calls { get; } = [];
        public int ReopenCalls { get; private set; }
        public Exception? ReopenError { get; set; }
        public int UnavailableLateWatchObservations { get; set; }
        public int LateWatchCalls => Volatile.Read(ref _lateWatchCalls);
        public int ForceCalls => Volatile.Read(ref _forceCalls);
        public int LaunchSubscribers => _launchEntered?.GetInvocationList().Length ?? 0;
        public TaskCompletionSource ForcedReached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string Name => "reopened-fixture";
        public MachineCapacity Capacity => new(4, 1L << 30);
        public string ContainerName => "retained-fixture";
        public RootProcess? Root => root;
        public Task<RootProcess?> Started => Task.FromResult(Root);
        public Stream? StdinWriter => null;
        public bool RootRunning => root is not null;
        public bool MemoryLimitHit => false;
        public bool CanPause => true;
        public event Action? Changed { add { } remove { } }
        public event Action<int>? LaunchProcessEntered
        {
            add => _launchEntered += value;
            remove => _launchEntered -= value;
        }

        public bool WatchLaunch()
        {
            if (UnavailableLateWatchObservations == 0)
            {
                return false;
            }

            Assert.Null(Root);
            if (Interlocked.Increment(ref _lateWatchCalls) <= UnavailableLateWatchObservations)
            {
                throw new LegacyCustodyUnavailableException("The pending-start observation is unavailable.");
            }

            return true;
        }

        public IAttemptHandle Reopen(string node, AttemptFiles files, RootProcess? persistedRoot, bool stopping)
        {
            Assert.Equal(nodeName, node);
            Assert.Equal(attemptName, files.AttemptName);
            Assert.Equal(root, persistedRoot);
            Assert.False(stopping);
            ReopenCalls++;
            if (ReopenError is { } error)
            {
                throw error;
            }

            return this;
        }

        public void Freeze()
        {
            Assert.False(_frozen);
            _frozen = true;
            Calls.Add(("freeze", 0));
        }

        public void Thaw()
        {
            Assert.True(_frozen);
            _frozen = false;
            Calls.Add(("thaw", 0));
        }

        public void SetCpuWeight(int weight) => Calls.Add(("cpu-weight", weight));
        public void SetMemoryHigh(long bytes) => Calls.Add(("memory-high", bytes));
        public CapabilityReport Evaluate() => new();
        public void UpdateRootLimits(RootLimits limits) { }
        public bool AcknowledgeRecorded(string node, string attempt) => false;
        public ExitRecord? TryReadExit() => null;
        public LaunchRecord? TryReadLaunchFailure() => null;
        public IReadOnlyList<ContainerProcess> Processes() => [];
        public ContainerAccounting Accounting() => new(0, 0, 0, 0, 0, 0, []);
        public IReadOnlyList<EscapedProcess> ScanEscaped() => [];
        public void Acknowledge() { }
        public void Dispose() { }

        public void Start(string node, RootLimits limits, string helperExecutable) => throw new NotSupportedException();
        public void Terminate()
        {
            if (UnavailableLateWatchObservations == 0)
            {
                throw new NotSupportedException();
            }

            Interlocked.Increment(ref _forceCalls);
            ForcedReached.TrySetResult();
        }
        public GracefulOutcome RequestGracefulStop() => throw new NotSupportedException();
    }
}
