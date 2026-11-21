// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>V1 adopted Task custody and lifecycle using retained SQLite records and a scripted platform container.</summary>
/// <remarks>
/// The fresh native adoption and Linux cross-user/outside-subtree integration sources remain at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
/// The retained Windows and Linux platform AdoptionTests still exercise their native container primitives.
/// </remarks>
public sealed class AdoptionLifecycleTests
{
    private const string ContainerName = "retained-adoption-fixture";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly Caller Human = new(Origin.Human, ClientKind.Cli, null);

    [Fact(Timeout = 60_000)]
    public async Task AnAdoptedProcessThatEndsByItselfEndsItsTaskLostWithoutAnExitStatus()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredAdoptionAsync(containerAvailable: true, async fixture =>
        {
            var task = await fixture.ReadAsync();
            Assert.Equal((TaskState.Running, TaskKind.Adopted), (task.State, task.Spec.Kind));
            var (processes, error) = ResourceViews.Processes(fixture.Runtime, new ProcessFilter { Labels = { ProcessLabel.Adopted } });
            Assert.Null(error);
            var process = Assert.Single(processes!);
            Assert.Equal((uint)fixture.Platform.Root.Pid, process.Process.Pid);
            Assert.Equal(fixture.TaskId, process.TaskId);

            var ended = await fixture.CompleteAsync();
            Assert.Equal((TaskState.Lost, Adoptions.NoExitStatus), (ended.State, ended.StateReason));
            AssertAdoptedResult(ended, TerminationReason.Lost, EffectCertainty.Unknown);
            Assert.Equal(0, fixture.Platform.TerminateCalls);
            AssertAdoptedChanges(PersistedTaskEvents(fixture.Store), fixture.TaskId, cancelled: false);
        });
    }

    [Theory(Timeout = 60_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ARemoteCallerCannotCancelARecordedAdoption(bool accountSession)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredAdoptionAsync(containerAvailable: true, async fixture =>
        {
            var adopted = await fixture.ReadAsync();
            Assert.Equal((TaskState.Running, TaskKind.Adopted, AttemptKind.Adopted), (adopted.State, adopted.Spec.Kind, adopted.CurrentAttempt.Kind));
            var caller = accountSession ? RoutedCalls.Session() : fixture.RelayedScript();
            var denied = await fixture.RouteCancelAsync(caller);
            Assert.Equal((RoutedOutcome.RefusedByPolicy, "permission_denied", PermissionMatrix.ProcessTerminate, EffectCertainty.DidNotHappen),
                (denied.Outcome, denied.Error?.Code, denied.Error?.Details.State.State, denied.Error?.Effect));
            Assert.Equal(0, fixture.Platform.TerminateCalls);
            Assert.Single(fixture.Platform.OwnedProcesses());
            Assert.Equal(TaskState.Running, (await fixture.ReadAsync()).State);
            Assert.Equal(0L, fixture.Store.Read(reader => reader.Scalar("SELECT count(*) FROM approval;")));
            Assert.Contains(fixture.Store.Read(reader => AuditLog.Recent(reader)), entry =>
                entry.Operation == PermissionMatrix.ProcessTerminate + " TaskService.CancelTask" && entry.Decision == PermissionDecision.Deny
                && entry.Actor.Origin == Origin.Remote && caller.Equals(entry.Actor.CenterCaller));
        });
    }

    [Fact(Timeout = 60_000)]
    public async Task AnApprovedRoutedCancelCannotReachARecoveredAdoptedProcess()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredAdoptionAsync(containerAvailable: true, async fixture =>
        {
            var before = await fixture.ReadAsync();
            Assert.Equal((TaskState.Running, TaskKind.Adopted), (before.State, before.Spec.Kind));
            await fixture.Approvals.ResumeAsync().WaitAsync(Ct);
            var approval = fixture.Store.Read(reader => Approvals.Get(reader, fixture.PriorApproval!));
            Assert.NotNull(approval);
            Assert.Equal(ApprovalState.Failed, approval.State);
            var refusal = TaskServiceCancelTaskResponse.Parser.ParseFrom(approval.Outcome);
            Assert.Equal(("permission_denied", EffectCertainty.DidNotHappen), (refusal.Error.Code, refusal.Error.Effect));
            Assert.Contains(PermissionMatrix.ProcessTerminate + " is denied for REMOTE callers", refusal.Error.Details.State.Reason, StringComparison.Ordinal);
            Assert.Contains(fixture.Store.Read(reader => AuditLog.Recent(reader)), entry =>
                entry.Operation == PermissionMatrix.ProcessTerminate + " TaskService.CancelTask" && entry.Decision == PermissionDecision.Deny
                && entry.Actor.Origin == Origin.Remote);
            Assert.Equal(0, fixture.Platform.TerminateCalls);
            Assert.Single(fixture.Platform.OwnedProcesses());
            Assert.Equal(TaskState.Running, (await fixture.ReadAsync()).State);
        }, captureRoutedCancel: true);
    }

    [Fact(Timeout = 60_000)]
    public async Task AnAdoptionContainerTheNodeCannotReopenAfterARestartIsLost()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredAdoptionAsync(containerAvailable: false, async fixture =>
        {
            var ended = await fixture.ReadAsync();
            Assert.Equal(TaskState.Lost, ended.State);
            Assert.StartsWith(Adoptions.ContainerMissing + ":", ended.StateReason, StringComparison.Ordinal);
            AssertAdoptedResult(ended, TerminationReason.Lost, EffectCertainty.Unknown);
            var journal = fixture.Runtime.Journal;
            Assert.Equal(CursorStatus.OtherGeneration, fixture.Store.Read(reader => journal.Check(reader, fixture.PriorCursor, journal.Latest)));
            var events = PersistedTaskEvents(fixture.Store);
            Assert.Equal(2, events.Select(item => item.Generation).Distinct().Count());
            AssertAdoptedChanges(events, fixture.TaskId, cancelled: false);
            Assert.Equal(0, fixture.Platform.TerminateCalls);
        });
    }

    [Theory(Timeout = 60_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnavailableAdoptionCustodyLeavesTheOriginalAttemptForLaterCancellation(bool missingScopeIdentity)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredAdoptionAsync(containerAvailable: true, async fixture =>
        {
            var before = await fixture.ReadAsync();
            Assert.Equal(TaskState.Running, before.State);
            Assert.Equal(fixture.TaskId, before.TaskId);
            var cancel = await fixture.Tasks.CancelTask(Human,
                new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = fixture.TaskId }, Ct);
            Assert.Null(cancel.Error);
            Assert.Equal(1, fixture.Platform.TerminateCalls);
            Assert.Equal(TaskState.Cancelled, (await fixture.CompleteAsync()).State);
        }, initiallyUnavailable: true, missingScopeIdentity: missingScopeIdentity);
    }

    [Fact(Timeout = 60_000)]
    public async Task UnreadableAdoptionMembershipCanBeReadAgainBeforeRecordingAnEnd()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredAdoptionAsync(containerAvailable: true, async fixture =>
        {
            var before = await fixture.ReadAsync();
            fixture.Platform.SetMembershipUnavailable(true);
            fixture.Execution.Adoptions.Wake();
            await fixture.Platform.MembershipReadFailed.WaitAsync(TimeSpan.FromSeconds(5), Ct);
            fixture.Platform.SetMembershipUnavailable(false);
            fixture.Execution.Adoptions.Start();
            await fixture.Platform.MembershipReadSucceeded.WaitAsync(TimeSpan.FromSeconds(5), Ct);
            Assert.Equal(before, await fixture.ReadAsync());
            Assert.Single(fixture.Execution.Adoptions.Tracked);
            Assert.False(fixture.Platform.Released.IsCompleted);
            Assert.Equal(0, fixture.Platform.TerminateCalls);

            var ended = await fixture.CompleteAsync();
            Assert.Equal(TaskState.Lost, ended.State);
            AssertAdoptedResult(ended, TerminationReason.Lost, EffectCertainty.Unknown);
        });
    }

    [Fact(Timeout = 60_000)]
    public async Task CancellingAnAdoptionJournalsStoppingBeforeItsFinalResult()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await WithRecoveredAdoptionAsync(containerAvailable: true, async fixture =>
        {
            var request = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = fixture.TaskId, Reason = "adoption model" };
            var first = await fixture.Tasks.CancelTask(Human, request, Ct);
            Assert.Null(first.Error);
            Assert.Equal(first, await fixture.Tasks.CancelTask(Human, request, Ct));
            Assert.Equal(1, fixture.Platform.TerminateCalls);
            Assert.Equal(AttemptState.Stopping, (await fixture.ReadAsync()).CurrentAttempt.State);
            Assert.Single(fixture.Platform.OwnedProcesses());

            var ended = await fixture.CompleteAsync();
            Assert.Equal(TaskState.Cancelled, ended.State);
            AssertAdoptedResult(ended, TerminationReason.Cancelled, EffectCertainty.Happened);
            var duplicate = request.Clone();
            duplicate.Meta = Tasks.Meta();
            Assert.Null((await fixture.Tasks.CancelTask(Human, duplicate, Ct)).Error);
            Assert.Equal(1, fixture.Platform.TerminateCalls);
            AssertAdoptedChanges(PersistedTaskEvents(fixture.Store), fixture.TaskId, cancelled: true);
        });
    }

    private static async Task WithRecoveredAdoptionAsync(bool containerAvailable, Func<AdoptionFixture, Task> verify,
        bool captureRoutedCancel = false, bool initiallyUnavailable = false, bool missingScopeIdentity = false)
    {
        await using var node = InProcessNode.Create();
        var root = new RootProcess(int.MaxValue, node.Clock.GetUtcNow());
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Running, root: root, stateReason: "adopted");
        NodeStore Open() => NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = BootIdentity.Read(), Clock = node.Clock });

        EventCursor cursor;
        byte[]? priorApproval;
        using (var original = Open())
        {
            var oldJournal = EventJournal.Open(original);
            await using var oldProcessor = new CommandProcessor(original, oldJournal, new StreamHub());
            priorApproval = await oldProcessor.ExecuteAsync(command =>
                SeedHistory(command, taskId, attemptId, captureRoutedCancel), CommitDurability.Full).WaitAsync(Ct);
            cursor = oldJournal.LatestPosition;
        }

        using var store = Open();
        using var platform = new RecoveredPlatform(root, containerAvailable);
        using var log = new NodeLog(Path.Combine(node.DataRoot, "logs", "node"), LogLevel.Info, node.Clock);
        using var heartbeat = new NodeHeartbeatWriter(node.DataRoot, log, node.Clock);
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
            Clock = node.Clock,
            DataRoot = node.DataRoot,
            Platform = platform,
            Sampler = platform,
            Secrets = new TaskSecrets(store, keys),
            Heartbeat = heartbeat,
        });
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(node.ConfigPath, node.DataRoot, log), node.DataRoot, "offline-adoption-fixture", node.Clock,
            recovery, new CapabilityReport())
        { Execution = execution };
        var sessions = new ClientSessions();
        var executors = new ApprovalExecutors();
        var tasks = new TaskServiceHandler(runtime, sessions, executors);
        var approvals = new ApprovalServiceHandler(runtime, sessions, executors);
        using var dispatcher = new RoutedDispatcher(runtime);
        dispatcher.Bind(tasks, new WorkspaceServiceHandler(runtime), new FileServiceHandler(runtime));
        await runtime.TransitionAsync(NodeLifecycleState.Recovering, "fixture").WaitAsync(Ct);
        if (initiallyUnavailable)
        {
            var nativeError = new System.ComponentModel.Win32Exception(5);
            platform.ReopenError = nativeError;
            Task<int> SetRecordedScope(string? scope) => processor.ExecuteAsync(context =>
                context.Transaction.Execute("UPDATE attempt SET container_name = $scope WHERE attempt_id = $id;",
                    ("$scope", scope), ("$id", attemptId.Value.ToByteArray())), CommitDurability.Full);
            if (missingScopeIdentity)
            {
                await SetRecordedScope(null).WaitAsync(Ct);
            }

            ManagedTask? ReadTask() => store.Read(reader => TaskRecords.GetTask(reader, taskId.Value.Span, full: true));
            var original = ReadTask();
            Assert.NotNull(original);
            var recoverCursor = journal.LatestPosition;
            var error = await Assert.ThrowsAsync<LegacyCustodyUnavailableException>(() => execution.RecoverAsync(recovery, processor, Ct));
            Assert.Same(missingScopeIdentity ? null : nativeError, error.InnerException);
            Assert.Equal(original, ReadTask());
            Assert.Equal(recoverCursor, journal.LatestPosition);
            Assert.False(heartbeat.RecoveryDone);
            Assert.Empty(execution.Adoptions.Tracked);
            Assert.Equal(0, platform.TerminateCalls);
            if (missingScopeIdentity)
            {
                Assert.Equal(0, platform.ReopenCalls);
                await SetRecordedScope(ContainerName).WaitAsync(Ct);
            }

            platform.ReopenError = null;
        }

        await execution.RecoverAsync(recovery, processor, Ct).WaitAsync(Ct);
        await runtime.TransitionAsync(NodeLifecycleState.Ready, "fixture").WaitAsync(Ct);
        Assert.Equal(initiallyUnavailable && !missingScopeIdentity ? 2 : 1, platform.ReopenCalls);
        Assert.Equal(containerAvailable ? 1 : 0, execution.Adoptions.Tracked.Count);
        await verify(new AdoptionFixture(store, runtime, execution, tasks, approvals, dispatcher, taskId, platform, cursor, priorApproval));
    }

    private static byte[]? SeedHistory(CommandContext command, Id task, Id attempt, bool captureRoutedCancel)
    {
        var tx = command.Transaction;
        var id = task.Value.ToByteArray();
        var attemptId = attempt.Value.ToByteArray();
        var spec = new TaskSpec
        {
            Kind = TaskKind.Adopted,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "retained-adopted-image" } } },
        }.ToByteArray();
        tx.Execute("UPDATE task SET kind = $kind, spec = $spec, spec_digest = $digest WHERE task_id = $id;",
            ("$kind", (int)TaskKind.Adopted), ("$spec", spec), ("$digest", SHA256.HashData(spec)), ("$id", id));
        tx.Execute("UPDATE attempt SET kind = $kind, container_name = $container WHERE attempt_id = $id;",
            ("$kind", (int)AttemptKind.Adopted), ("$container", ContainerName), ("$id", attemptId));
        command.Emit(EventTopic.Tasks, new NodeEvent { Task = new TaskChanged { Task = TaskRecords.GetTask(tx, id, full: false) } });
        command.Emit(EventTopic.Tasks, new NodeEvent { Attempt = new AttemptChanged { Attempt = TaskRecords.GetAttempt(tx, attemptId) } });
        if (!captureRoutedCancel)
        {
            return null;
        }

        // A prior other-owner approval for this ID was captured before the gate could observe the target as ADOPTED.
        var request = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = task };
        var (approval, created, error) = Approvals.Raise(command, new ApprovalCapture
        {
            Operation = "TaskService.CancelTask",
            MatrixOperation = PermissionMatrix.TaskCancelOthers,
            Summary = "historical other-owner cancel",
            Risk = RiskClass.Medium,
            Requester = new ActorRef { Origin = Origin.Remote, CenterCaller = RoutedCalls.Session(), RemoteCommandId = request.Meta.CommandId },
            TargetKind = "task",
            TargetId = id,
            CommandId = request.Meta.CommandId.Value.ToByteArray(),
            Request = request.ToByteArray(),
            RequestDigest = PayloadDigest.Compute(request),
        }, Approvals.DefaultTtl);
        Assert.True(created);
        Assert.Null(error);
        Assert.NotNull(approval);
        return Approvals.Decide(command, approval.Id, approve: true, Human.Actor, null).Id;
    }

    private sealed record AdoptionFixture(NodeStore Store, NodeRuntime Runtime, ExecutionSupervisor Execution, TaskServiceHandler Tasks,
        ApprovalServiceHandler Approvals, RoutedDispatcher Dispatcher, Id TaskId, RecoveredPlatform Platform, EventCursor PriorCursor, byte[]? PriorApproval)
    {
        public async Task<ManagedTask> ReadAsync()
        {
            var read = await Tasks.GetTask(Human, new TaskServiceGetTaskRequest { Meta = AdoptionLifecycleTests.Meta(), TaskId = TaskId, Detail = TaskDetail.Full }, Ct);
            Assert.Null(read.Error);
            return read.Value.Task;
        }

        public async Task<ManagedTask> CompleteAsync()
        {
            Platform.End();
            Execution.Adoptions.Start();
            Execution.Adoptions.Wake();
            var waited = await Tasks.WaitTask(Human, new TaskServiceWaitTaskRequest
            {
                Meta = AdoptionLifecycleTests.Meta(),
                TaskId = TaskId,
                Target = WaitTarget.Terminal,
                WaitMs = 10_000,
            }, Ct);
            Assert.Null(waited.Error);
            Assert.True(waited.Value.Reached);
            await Platform.Released.WaitAsync(Ct);
            return await ReadAsync();
        }

        public CenterCaller RelayedScript() => new()
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = RoutedCalls.Account.Clone(),
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(Runtime.NodeId.Span) },
            LocalOrigin = Origin.Script,
            LocalSessionId = CommandIds.New(),
        };

        public async Task<RoutedAnswer> RouteCancelAsync(CenterCaller caller)
        {
            var request = new TaskServiceCancelTaskRequest { Meta = AdoptionLifecycleTests.Meta(), TaskId = TaskId };
            var raw = request.ToByteString();
            var now = Runtime.Clock.GetUtcNow();
            var header = new CallHeader
            {
                CallId = CommandIds.New(),
                Caller = caller,
                Method = RoutedMethod.CancelNodeTask,
                CommandId = request.Meta.CommandId,
                AccountId = caller.AccountId,
                TargetNodeId = new Id { Value = ByteString.CopyFrom(Runtime.NodeId.Span) },
                IssuedAt = ProtoTime.ToInstant(now.AddSeconds(-1)),
                ExpiresAt = ProtoTime.ToInstant(now.AddSeconds(35)),
                Deadline = ProtoTime.ToInstant(now.AddSeconds(10)),
                RequestSha256 = ByteString.CopyFrom(SHA256.HashData(raw.Span)),
                RequestSize = (uint)raw.Length,
            };
            var answer = await Dispatcher.DispatchAsync(new VerifiedCall(header, raw, 0), new RoutedCalls.TestLink(), Ct);
            return Assert.IsType<RoutedAnswer>(answer);
        }
    }

    private static RequestMeta Meta() => Tasks.Meta();

    private sealed class RecoveredPlatform(RootProcess root, bool canReopen) : IExecutionPlatform, IResourceSampler
    {
        private int _present = canReopen ? 1 : 0;
        private int _membershipUnavailable;
        private readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _membershipReadFailed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _membershipReadSucceeded = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string Name => "retained-adoption-fixture";
        public MachineCapacity Capacity => new(4, 1L << 30);
        public RootProcess Root => root;
        public Task Released => _released.Task;
        public Task MembershipReadFailed => _membershipReadFailed.Task;
        public Task MembershipReadSucceeded => _membershipReadSucceeded.Task;
        public int ReopenCalls { get; private set; }
        public int TerminateCalls { get; private set; }
        public Exception? ReopenError { get; set; }

        public IAdoptedContainer? ReopenAdopted(string containerName)
        {
            Assert.Equal(ContainerName, containerName);
            ReopenCalls++;
            if (ReopenError is { } error)
            {
                throw error;
            }

            return canReopen ? new RecoveredContainer(this) : null;
        }

        public IReadOnlyList<int> OwnedProcesses() => Volatile.Read(ref _present) == 1 ? [root.Pid] : [];
        public void SetMembershipUnavailable(bool unavailable) => Volatile.Write(ref _membershipUnavailable, unavailable ? 1 : 0);
        public IReadOnlyList<ProcessSample> Processes() => Volatile.Read(ref _present) == 1 ? [new(root.Pid, 0, root.StartTime, "retained-adopted-image")] : [];
        public MachineSample Machine() => throw new NotSupportedException();
        public void End() => Volatile.Write(ref _present, 0);
        public void Dispose() { }
        public CapabilityReport Evaluate() => new();
        public bool AcknowledgeRecorded(string nodeName, string attemptName) => false;
        public void UpdateRootLimits(RootLimits limits) { }
        public IAttemptHandle? Reopen(string nodeName, AttemptFiles files, RootProcess? root, bool stopping) => throw new NotSupportedException();
        public void Start(string nodeName, RootLimits limits, string helperExecutable) => throw new NotSupportedException();
        public ProcessTermination TerminateProcess(int pid, DateTimeOffset start) => throw new NotSupportedException();

        private sealed class RecoveredContainer(RecoveredPlatform owner) : IAdoptedContainer
        {
            string IAdoptedContainer.ContainerName => AdoptionLifecycleTests.ContainerName;
            public IReadOnlyList<int> Processes()
            {
                if (Volatile.Read(ref owner._membershipUnavailable) == 1)
                {
                    owner._membershipReadFailed.TrySetResult();
                    throw new LegacyCustodyUnavailableException("The adopted scope's membership is unavailable.");
                }

                owner._membershipReadSucceeded.TrySetResult();
                return owner.OwnedProcesses();
            }
            public void Terminate() => owner.TerminateCalls++;
            public void Dispose() => owner._released.TrySetResult();
        }
    }

    private static List<NodeEvent> PersistedTaskEvents(NodeStore store) => store.Read(reader =>
    {
        using var command = reader.CreateCommand("SELECT payload FROM event_journal WHERE topic = $topic ORDER BY seq;");
        command.Parameters.AddWithValue("$topic", (int)EventTopic.Tasks);
        using var rows = command.ExecuteReader();
        var events = new List<NodeEvent>();
        while (rows.Read())
        {
            events.Add(NodeEvent.Parser.ParseFrom((byte[])rows.GetValue(0)));
        }

        return events;
    });

    private static void AssertAdoptedResult(ManagedTask task, TerminationReason reason, EffectCertainty effect)
    {
        Assert.Equal(1U, task.AttemptCount);
        Assert.Equal(AttemptKind.Adopted, task.CurrentAttempt.Kind);
        Assert.Equal(AttemptState.Finished, task.CurrentAttempt.State);
        Assert.Equal((reason, effect), (task.CurrentAttempt.Result.TerminationReason, task.CurrentAttempt.Result.Effect));
        Assert.False(task.CurrentAttempt.Result.HasExitCode);
    }

    private static void AssertAdoptedChanges(List<NodeEvent> events, Id id, bool cancelled)
    {
        TaskLifecycleModelTests.AssertStateMachines(events);
        var tasks = events.Where(item => item.Task?.Task.TaskId.Equals(id) == true).Select(item => item.Task).ToArray();
        Assert.NotEmpty(tasks);
        Assert.Equal(TaskState.Running, tasks[0].Task.State);
        Assert.False(tasks[0].HasPreviousState);
        var changes = events.Where(item => item.Attempt?.Attempt.TaskId.Equals(id) == true).Select(item => item.Attempt).ToArray();
        Assert.NotEmpty(changes);
        Assert.Equal(AttemptState.Running, changes[0].Attempt.State);
        Assert.False(changes[0].HasPreviousState);
        Assert.DoesNotContain(changes, change => change.Attempt.State == AttemptState.Finalizing);
        Assert.Equal(AttemptState.Finished, changes[^1].Attempt.State);
        Assert.Equal(cancelled ? AttemptState.Stopping : AttemptState.Running, changes[^1].PreviousState);
        if (cancelled)
        {
            var stopping = Assert.Single(changes, change => change.Attempt.State == AttemptState.Stopping);
            Assert.Equal(AttemptState.Running, stopping.PreviousState);
            Assert.Null(stopping.Attempt.Result);
        }
        else
        {
            Assert.DoesNotContain(changes, change => change.Attempt.State == AttemptState.Stopping);
        }
    }
}
