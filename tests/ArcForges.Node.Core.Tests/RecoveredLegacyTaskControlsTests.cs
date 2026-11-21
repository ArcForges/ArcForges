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

    private static async Task WithRecoveredTaskAsync(AttemptState phase, string? reason, Func<RecoveredControlFixture, Task> verify)
    {
        await using var node = InProcessNode.Create();
        var clock = new ControlledClock();
        node.Clock = clock;
        var root = new RootProcess(int.MaxValue, clock.GetUtcNow());
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
            recovery, new CapabilityReport()) { Execution = execution };
        await runtime.TransitionAsync(NodeLifecycleState.Recovering, "fixture").WaitAsync(Ct);
        await execution.RecoverAsync(recovery, processor, Ct);
        await runtime.TransitionAsync(NodeLifecycleState.Ready, "fixture").WaitAsync(Ct);
        Assert.Equal(1, platform.ReopenCalls);

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

    private sealed class ReopenedPlatform(string nodeName, string attemptName, RootProcess root, bool frozen) : IExecutionPlatform, IAttemptHandle
    {
        private bool _frozen = frozen;
        public List<(string Operation, long Value)> Calls { get; } = [];
        public int ReopenCalls { get; private set; }
        public string Name => "reopened-fixture";
        public StringComparer EnvironmentNames => StringComparer.Ordinal;
        public MachineCapacity Capacity => new(4, 1L << 30);
        public string ContainerName => "retained-fixture";
        public RootProcess? Root => root;
        public Task<RootProcess?> Started => Task.FromResult(Root);
        public Stream? StdinWriter => null;
        public bool RootRunning => true;
        public bool MemoryLimitHit => false;
        public bool CanPause => true;
        public event Action? Changed { add { } remove { } }

        public IAttemptHandle Reopen(string node, AttemptFiles files, RootProcess? persistedRoot, bool stopping)
        {
            Assert.Equal(nodeName, node);
            Assert.Equal(attemptName, files.AttemptName);
            Assert.Equal(root, persistedRoot);
            Assert.False(stopping);
            ReopenCalls++;
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
        public PreparedCommand Prepare(CommandRequest request) => throw new NotSupportedException();
        public IAttemptHandle Launch(AttemptLaunch launch) => throw new NotSupportedException();
        public void Terminate() => throw new NotSupportedException();
        public GracefulOutcome RequestGracefulStop() => throw new NotSupportedException();
    }
}
