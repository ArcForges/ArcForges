// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

public sealed class RetainedQueueServiceTests
{
    private const string RetiredAdmission = "legacy_admission_retired";

    [Fact(Timeout = 60_000)]
    public async Task LegacyQueueShowsRetainedTasksWithoutAnAdmissionForecast()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "retained-queue-fixture", Clock = fixture.Clock });
        using var log = new NodeLog(Path.Combine(fixture.DataRoot, "logs", "node"), LogLevel.Info, fixture.Clock);
        using var heartbeat = new NodeHeartbeatWriter(fixture.DataRoot, log, fixture.Clock);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = fixture.Clock,
            DataRoot = fixture.DataRoot,
            Heartbeat = heartbeat,
        });
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(fixture.ConfigPath, fixture.DataRoot, log), fixture.DataRoot, "offline-queue-fixture", fixture.Clock,
            new RecoveryReport(false, false, null, store.Opening), new CapabilityReport())
        { Execution = execution };
        var sessions = new ClientSessions();
        var service = new QueueServiceHandler(runtime, sessions);
        var tasks = new TaskServiceHandler(runtime, sessions);
        var caller = new Caller(Origin.Human, ClientKind.Cli, null);
        var owner = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli };
        var demand = new ResourceDemand { CpuMillicores = 250, MemExpectedBytes = 64UL << 20 };
        var (queued, dependency, retry, cancelled) = store.Write(transaction =>
        {
            var earlier = Seed(transaction, owner, TaskState.Queued, "default", 3_000_000, demand);
            var dependent = Seed(transaction, owner, TaskState.WaitingDependency, "default", 2_000_000);
            var deferred = Seed(transaction, owner, TaskState.RetryWait, "interactive", 1_000_000);
            var closed = Seed(transaction, owner, TaskState.Cancelled, "interactive", 4_000_000);
            transaction.Execute("INSERT INTO task_dependency (task_id, depends_on_task_id, condition) VALUES ($task, $on, $condition);",
                ("$task", dependent.Value.ToByteArray()), ("$on", earlier.Value.ToByteArray()), ("$condition", (int)DependencyCondition.Succeeded));
            return (earlier, dependent, deferred, closed);
        }, CommitDurability.Full);

        var queue = await service.GetQueue(new QueueServiceGetQueueRequest { Meta = Tasks.Meta() }, null!);
        Assert.True(NodeShapes.IsValid(queue));
        Assert.Null(queue.Error);
        Assert.Equal([queued, dependency, retry], queue.Value.Entries.Select(entry => entry.TaskId));
        Assert.All(queue.Value.Entries, entry =>
        {
            Assert.Equal(owner, entry.Owner);
            Assert.Equal(Priority.High, entry.EffectivePriority);
            Assert.Equal(RetiredAdmission, entry.Queue.BlockingReason);
            Assert.False(entry.Queue.HasPosition);
            Assert.Null(entry.Queue.Eta);
            Assert.True(entry.Queue.WaitedMs >= 1000);
            Assert.False(entry.HasReservedForLarge);
        });
        Assert.Equal(demand, queue.Value.Entries[0].Request);
        Assert.Null(queue.Value.Entries[1].Request);
        Assert.Null(queue.Value.Entries[2].Request);

        var interactive = await service.GetQueue(new QueueServiceGetQueueRequest { Meta = Tasks.Meta(), Pool = "interactive" }, null!);
        Assert.Null(interactive.Error);
        Assert.Equal(retry, Assert.Single(interactive.Value.Entries).TaskId);
        var unknownPool = await service.GetQueue(new QueueServiceGetQueueRequest { Meta = Tasks.Meta(), Pool = "absent" }, null!);
        Assert.Equal("not_found", unknownPool.Error.Code);
        var pools = await service.ListPools(new QueueServiceListPoolsRequest { Meta = Tasks.Meta() }, null!);
        Assert.Null(pools.Error);
        Assert.Equal(queue.Value.Pools, pools.Value.Pools);
        Assert.Equal(2u, pools.Value.Pools.Single(pool => pool.Name == "default").Queued);
        Assert.Equal(1u, pools.Value.Pools.Single(pool => pool.Name == "interactive").Queued);

        foreach (var (id, state) in (ValueTuple<Id, TaskState>[])[(queued, TaskState.Queued), (dependency, TaskState.WaitingDependency), (retry, TaskState.RetryWait)])
        {
            var response = await service.ExplainTask(new QueueServiceExplainTaskRequest { Meta = Tasks.Meta(), TaskId = id }, null!);
            Assert.True(NodeShapes.IsValid(response));
            Assert.Null(response.Error);
            var details = response.Value.Explanation;
            Assert.Equal((id, state, RetiredAdmission), (details.TaskId, details.State, details.BlockingReason));
            Assert.Contains("will not start or retry", details.Text, StringComparison.Ordinal);
            Assert.False(details.HasPosition);
            Assert.False(details.HasFeasibility);
            Assert.Null(details.Eta);
            Assert.Null(details.AgesAt);
            var got = await tasks.GetTask(caller, new TaskServiceGetTaskRequest { Meta = Tasks.Meta(), TaskId = id, Detail = TaskDetail.Full },
                TestContext.Current.CancellationToken);
            Assert.Null(got.Error);
            var task = got.Value.Task;
            Assert.Equal(state, task.State);
            var projected = queue.Value.Entries.Single(entry => entry.TaskId.Equals(id));
            Assert.Equal(projected.Queue.BlockingReason, task.Queue.BlockingReason);
            Assert.False(task.Queue.HasPosition);
            Assert.Null(task.Queue.Eta);
            Assert.True(task.Queue.WaitedMs >= projected.Queue.WaitedMs);
            Assert.Equal(projected.Request, task.Spec.Resources?.Hint);
            if (id.Equals(dependency))
            {
                Assert.Equal(queued, Assert.Single(details.WaitingOnTasks));
            }
            else
            {
                Assert.Empty(details.WaitingOnTasks);
            }
        }

        var terminal = await service.ExplainTask(new QueueServiceExplainTaskRequest { Meta = Tasks.Meta(), TaskId = cancelled }, null!);
        Assert.Null(terminal.Error);
        Assert.Equal(TaskState.Cancelled, terminal.Value.Explanation.State);
        Assert.False(terminal.Value.Explanation.HasBlockingReason);
        Assert.Null(execution.Platform);
        Assert.Empty(execution.RunningAttempts);
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        Assert.Equal(4L, store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE rev = 0;")));
    }

    private static Id Seed(StoreTransaction transaction, ActorRef owner, TaskState state, string pool, long ageMicroseconds, ResourceDemand? demand = null)
    {
        var id = LegacyTaskHistoryFixture.SeedQueued(transaction, owner, Priority.High);
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "fixture-never-starts" } } },
            Resources = demand is null ? null : new ResourceSpec { Hint = demand },
        }.ToByteArray();
        transaction.Execute("UPDATE task SET state = $state, pool = $pool, created_at = $at, queued_at = $at, spec = $spec, spec_digest = $digest WHERE task_id = $id;",
            ("$state", (int)state), ("$pool", pool), ("$at", transaction.NowMicroseconds - ageMicroseconds),
            ("$spec", spec), ("$digest", SHA256.HashData(spec)), ("$id", id.Value.ToByteArray()));
        return id;
    }
}
