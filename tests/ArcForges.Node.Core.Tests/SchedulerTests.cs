// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

/// <summary>The controls that still apply to the draining legacy runtime and its persisted queue.</summary>
/// <remarks>
/// The original native admission and scheduling tests remain at 8496f155213d0c215396d1093f866f39b4678f43.
/// V2 admission, CPU sharing, pressure and recovery have independent installed tests in MxcRunServiceTests.
/// </remarks>
public sealed class SchedulerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task TheRootLimitsFollowTheMeasuredBudgetOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await RootLimitsAsync();
    }

    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task TheRootLimitsFollowTheMeasuredBudgetOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux transient units.");
        Sched.RequirePlatform();
        await RootLimitsAsync();
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task PauseIsUnsupportedForARetainedTaskOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        var taskId = new Id();
        await using var node = await InProcessNode.Create(seed: transaction =>
            taskId = LegacyTaskHistoryFixture.SeedQueued(transaction, new ActorRef { Origin = Origin.Human })).StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var pause = await channel.Tasks.PauseTaskAsync(new TaskServicePauseTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.Equal("pause_unsupported", pause.Error?.Code);
        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, taskId)).State);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt WHERE task_id = $id;", ("$id", taskId.Value.ToByteArray()))));
    }

    [Fact]
    public void APressureFreezeIsKnownFromTheStateReasonAPauseTaskIsNot()
    {
        Assert.True(ExecutionSupervisor.IsPressureFrozen(ExecutionSupervisor.PressureFrozen + ": frozen at memory pressure (available; 1 of 2 bytes available)"));
        Assert.False(ExecutionSupervisor.IsPressureFrozen("paused by PauseTask"));
        Assert.False(ExecutionSupervisor.IsPressureFrozen("pressure_frozen_elsewhere"));
        Assert.False(ExecutionSupervisor.IsPressureFrozen(null));
    }

    [Fact(Timeout = 120_000)]
    public async Task SetTaskPriorityResetsTheRetainedWaitingTasksAgingTimestamp()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var taskId = new Id();
        var earlier = StoreTime.ToMicroseconds(DateTimeOffset.UtcNow.AddMinutes(-25));
        await using var node = await InProcessNode.Create(seed: transaction =>
            taskId = LegacyTaskHistoryFixture.SeedQueued(transaction, new ActorRef { Origin = Origin.Human },
                Priority.Background, Priority.Normal, earlier)).StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        Assert.Equal(Priority.Normal, (await Tasks.GetAsync(channel, taskId)).EffectivePriority);

        var changed = await channel.Tasks.SetTaskPriorityAsync(new TaskServiceSetTaskPriorityRequest
        {
            Meta = Tasks.Meta(),
            TaskId = taskId,
            Priority = Priority.Low,
        }, cancellationToken: Ct);
        Assert.Null(changed.Error);
        var retained = await Tasks.GetAsync(channel, taskId);
        Assert.Equal(TaskState.Queued, retained.State);
        Assert.Equal(Priority.Low, retained.EffectivePriority);
        Assert.Equal(0u, retained.AttemptCount);
        node.Runtime.Store.Read(reader =>
        {
            var id = ("$id", taskId.Value.ToByteArray());
            Assert.Equal(earlier, reader.Scalar("SELECT queued_at FROM task WHERE task_id = $id;", id));
            Assert.Equal((long)Priority.Low, reader.Scalar("SELECT priority FROM task WHERE task_id = $id;", id));
            Assert.True(Assert.IsType<long>(reader.Scalar("SELECT aged_at FROM task WHERE task_id = $id;", id)) > earlier);
            return 0;
        });
    }

    /// <summary>03 section 5.1: the root limits follow the measured budget; the operating system's root carries what the node applied.</summary>
    private static async Task RootLimitsAsync()
    {
        // The live machine (exclusive): the root limits follow the budget measured from it.
        await using var node = await InProcessNode.Create().WithLiveMachine().StartAsync();
        var execution = node.Runtime.Execution!;
        await Tasks.WaitForAsync(() => execution.AppliedRootLimits is not null, TimeSpan.FromSeconds(30), "root limits from the measured budget");
        await execution.PlatformCalls.DrainAsync(TimeSpan.FromSeconds(10));
        var applied = execution.AppliedRootLimits!;
        var settings = execution.Settings;
        var startup = settings.RootLimits(settings.BudgetCpu, settings.MaxShareMemory);
        TestContext.Current.TestOutputHelper?.WriteLine($"applied CPU rate {applied.CpuRate} (startup {startup.CpuRate}); memory high {applied.NotificationBytes}");
        Assert.True(applied.CpuRate <= startup.CpuRate, "The measured budget is at most C - R.");
        if (OperatingSystem.IsWindows())
        {
            using var root = ArcForges.Node.Platform.Windows.JobObject.Open(ArcForges.Node.Platform.Windows.WindowsExecutionPlatform.JobName(IdText.Format(node.Runtime.NodeId.Span), "root"))!;
            Assert.Equal((uint)applied.CpuRate, root.CpuRateControl().Value);
        }
        else
        {
            var slice = "/sys/fs/cgroup" + ArcForges.Tests.SystemdTestEnvironment.Property(node.Slice, "ControlGroup");
            Assert.Equal((applied.CpuRate * Environment.ProcessorCount * 10).ToString(CultureInfo.InvariantCulture) + " 100000", File.ReadAllText(Path.Combine(slice, "cpu.max")).Trim());
            var page = Environment.SystemPageSize;
            Assert.Equal((applied.NotificationBytes - (applied.NotificationBytes % page)).ToString(CultureInfo.InvariantCulture), File.ReadAllText(Path.Combine(slice, "memory.high")).Trim());
        }
    }
}
