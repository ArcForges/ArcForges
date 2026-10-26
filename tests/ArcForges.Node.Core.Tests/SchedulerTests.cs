// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// The scheduler with a real node, real platforms and real processes (AF-SCHED-01; 03 sections 4, 5 and 7; 04 section 8; AD-0006 section
/// 4): dependencies with SUCCEEDED, FINISHED and READY (output regex, TCP port, file) and the readiness timeout; concurrency keys (writers,
/// readers, ancestors, purposes, tools, the workspace key) with ExplainTask naming the key and its holder, held across a node restart;
/// SERIAL workspaces, <c>access = EXCLUSIVE</c> and the early release of a service's workspace key; parallelism DISABLED per scope;
/// automatic retries per class and source (caller, policy rule, agent with and without <c>accept_agent_assertions</c>) and after a node
/// loss; memory admission without overcommit; <c>exceeds_capacity</c> with TASK_INFEASIBLE and no reservation; the CPU grant clamped to
/// <c>B_cpu</c> with the tool-level setting; the large-task reservation and its lapse; pause and resume; pressure actions; the root limits
/// following the measured budget; fairness between two sessions; and the queue start after a release. Each test runs on the OS its env
/// trait names (the <c>hold</c> workload records its start, readiness and end) and skips with a reason elsewhere.
/// </summary>
public sealed class SchedulerTests
{
    private const long MiB = 1024L * 1024;
    private static readonly RetrySpec FastRetry = new() { InitialBackoffMs = 200, MaxBackoffMs = 400 };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    // ---------------------------------------------------------------------------------------------------------- dependencies

    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    public async Task DependentsStartOnlyAfterTheirConditionOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(DependenciesAsync);
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "linux-real")]
    public async Task DependentsStartOnlyAfterTheirConditionOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(DependenciesAsync);
    }

    [Fact(Timeout = 240_000)]
    [Trait("env", "windows-real")]
    public async Task DependentsOfAServiceStartOnlyOnceItIsReadyOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(ReadinessAsync);
    }

    [Fact(Timeout = 240_000)]
    [Trait("env", "linux-real")]
    public async Task DependentsOfAServiceStartOnlyOnceItIsReadyOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(ReadinessAsync);
    }

    // ---------------------------------------------------------------------------------------------------------- keys

    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    public async Task KeysSerializeConflictingTasksAndExplainTheirHoldersOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(KeysAsync);
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "linux-real")]
    public async Task KeysSerializeConflictingTasksAndExplainTheirHoldersOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(KeysAsync);
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    public async Task KeysStayHeldAcrossANodeRestartOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(KeysAcrossRestartAsync);
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "linux-real")]
    public async Task KeysStayHeldAcrossANodeRestartOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(KeysAcrossRestartAsync);
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    public async Task SerialWorkspacesExclusiveAccessAndReadyServicesOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(WorkspacesAsync);
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "linux-real")]
    public async Task SerialWorkspacesExclusiveAccessAndReadyServicesOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(WorkspacesAsync);
    }

    // ---------------------------------------------------------------------------------------------------------- parallelism

    [Fact(Timeout = 240_000)]
    [Trait("env", "windows-real")]
    public async Task ParallelismDisabledPerScopeRunsOneAtATimeOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(ParallelismAsync);
    }

    [Fact(Timeout = 240_000)]
    [Trait("env", "linux-real")]
    public async Task ParallelismDisabledPerScopeRunsOneAtATimeOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(ParallelismAsync);
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [Trait("env", "windows-real")]
    public async Task TwoSessionsShareAdmissionsEquallyOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(FairnessAsync);
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [Trait("env", "linux-real")]
    public async Task TwoSessionsShareAdmissionsEquallyOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(FairnessAsync);
    }

    // ---------------------------------------------------------------------------------------------------------- retries

    [Fact(Timeout = 240_000)]
    [Trait("env", "windows-real")]
    public async Task RetriesFollowTheClassAndItsSourceOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(RetriesAsync);
    }

    [Fact(Timeout = 240_000)]
    [Trait("env", "linux-real")]
    public async Task RetriesFollowTheClassAndItsSourceOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(RetriesAsync);
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    public async Task AfterANodeLossOnlyAnAssertedTaskIsRetriedOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(NodeLossAsync);
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "linux-real")]
    public async Task AfterANodeLossOnlyAnAssertedTaskIsRetriedOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(NodeLossAsync);
    }

    // ---------------------------------------------------------------------------------------------------------- budgets

    // isolation=exclusive: the hints are fractions of the measured B_mem, which other tests' processes would move.
    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task MemoryIsNeverOvercommittedAtAdmissionOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(MemoryAsync);
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task MemoryIsNeverOvercommittedAtAdmissionOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(MemoryAsync);
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    public async Task AnInfeasibleTaskRaisesAFindingAndNeverBlocksFeasibleWorkOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(InfeasibleAsync);
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "linux-real")]
    public async Task AnInfeasibleTaskRaisesAFindingAndNeverBlocksFeasibleWorkOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(InfeasibleAsync);
    }

    // isolation=exclusive: the grant is the measured B_cpu of an idle node.
    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task ACpuEstimateAboveTheBudgetStartsWithTheClampedGrantOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(CpuClampAsync);
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task ACpuEstimateAboveTheBudgetStartsWithTheClampedGrantOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(CpuClampAsync);
    }

    // isolation=exclusive: the fillers are fractions of the measured B_cpu; the lapse is a 60 s bound.
    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task ALargeTaskReservesOnABusyNodeAndTheReservationLapsesOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(ReservationAsync);
    }

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task ALargeTaskReservesOnABusyNodeAndTheReservationLapsesOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(ReservationAsync);
    }

    // isolation=exclusive: the root limits follow the measured budget, which other tests' processes would move.
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task TheRootLimitsFollowTheMeasuredBudgetOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(RootLimitsAsync);
    }

    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task TheRootLimitsFollowTheMeasuredBudgetOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(RootLimitsAsync);
    }

    // isolation=exclusive: the latency bound of 15 section 4.
    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task TheNextQueuedTaskStartsWithin500MsOfAReleaseOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(QueueStartAsync);
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task TheNextQueuedTaskStartsWithin500MsOfAReleaseOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(QueueStartAsync);
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task ARunningTasksPriorityChangesItsContainersCpuWeightOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(RunningPriorityAsync);
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "linux-real")]
    public async Task ARunningTasksPriorityChangesItsContainersCpuWeightOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(RunningPriorityAsync);
    }
    // ---------------------------------------------------------------------------------------------------------- pause, pressure

    [Fact(Timeout = 180_000)]
    [Trait("env", "linux-real")]
    public async Task APausableTaskIsFrozenAndThawedOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(PauseAsync);
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task PauseIsUnsupportedOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var spec = Sched.Hold(node, Path.Combine(node.Root, "p.txt"), 30_000);
        spec.Resources.Pausable = true;
        var taskId = await Tasks.SubmitAsync(channel, spec);
        await Tasks.RunningAsync(channel, taskId);
        var pause = await channel.Tasks.PauseTaskAsync(new TaskServicePauseTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.Equal("pause_unsupported", pause.Error?.Code);
        Assert.Equal(TaskState.Running, (await Tasks.GetAsync(channel, taskId)).State);
        await Sched.CancelAsync(channel, taskId);
    }

    // isolation=exclusive: the test moves the node to Pressure through the policy thresholds and waits for the 30 s thaw.
    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task PressureRequeuesPreemptibleBackgroundWorkAndAdmitsOnlyInteractiveOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(PressureAsync);
    }

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task PressureFreezesPausableBackgroundWorkAndThawsAfterNormalOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(PressureAsync);
    }

    /// <summary>
    /// The cause of a pause survives a node restart in the task's state_reason: a pressure freeze's reason starts with the pressure_frozen
    /// token (recovery thaws it after 30 s at Normal), PauseTask's does not (it waits for ResumeTask).
    /// </summary>
    [Fact]
    public void APressureFreezeIsKnownFromTheStateReasonAPauseTaskIsNot()
    {
        Assert.True(ExecutionSupervisor.IsPressureFrozen(ExecutionSupervisor.PressureFrozen + ": frozen at memory pressure (available; 1 of 2 bytes available)"));
        Assert.False(ExecutionSupervisor.IsPressureFrozen("paused by PauseTask"));
        Assert.False(ExecutionSupervisor.IsPressureFrozen("pressure_frozen_elsewhere"));
        Assert.False(ExecutionSupervisor.IsPressureFrozen(null));
    }

    // isolation=exclusive: like the Pressure test, it moves the node to Pressure through the policy thresholds and waits for the thaw.
    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task APressureFrozenAttemptThawsAfterANodeRestartOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(PressureRestartAsync);
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task SetTaskPriorityRestartsAWaitingTasksAgingOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(AgingRestartAsync);
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "linux-real")]
    public async Task SetTaskPriorityRestartsAWaitingTasksAgingOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(AgingRestartAsync);
    }

    // ---------------------------------------------------------------------------------------------------------- benchmarks

    // category=perf (15 section 4 fairness: 10 minutes of CPU-seconds; ARCFORGES_FAIRNESS_MINUTES shortens it), never by default.
    [Fact(Timeout = 1_200_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("category", "perf")]
    [Trait("isolation", "exclusive")]
    public async Task TwoSessionsReceiveEqualCpuSecondsOverTenMinutesOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnWindowsAsync(FairCpuSecondsAsync);
    }

    [Fact(Timeout = 1_200_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("category", "perf")]
    [Trait("isolation", "exclusive")]
    public async Task TwoSessionsReceiveEqualCpuSecondsOverTenMinutesOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await OnLinuxAsync(FairCpuSecondsAsync);
    }
    // ========================================================================================================== bodies

    private static async Task OnWindowsAsync(Func<Task> body)
    {
        Ct.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await body();
    }

    private static async Task OnLinuxAsync(Func<Task> body)
    {
        Ct.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux transient units.");
        Sched.RequirePlatform();
        await body();
    }

    private static string M(InProcessNode node, string name) => Path.Combine(node.Root, name + ".txt");

    /// <summary>
    /// 04 section 8: a SUCCEEDED dependent waits (WAITING_DEPENDENCY, blocking reason <c>dependency</c>, ExplainTask names the task) and
    /// starts after its dependency ended; a FINISHED dependent runs after a failed dependency; a SUCCEEDED dependent of a failed task is
    /// CANCELLED with <c>dependency_failed</c> and never starts.
    /// </summary>
    private static async Task DependenciesAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        await Sched.WidenAsync(channel);
        var (ma, mf, mb, mc, md) = (M(node, "a"), M(node, "f"), M(node, "b"), M(node, "c"), M(node, "d"));
        var releaseFirst = Path.Combine(node.Root, "first-release.flag");
        var first = await Tasks.SubmitAsync(channel, Sched.Hold(node, ma, 120_000, "--until-file", releaseFirst));
        var failing = await Tasks.SubmitAsync(channel, Sched.Hold(node, mf, 1_500, "--exit-code", "3"));
        var afterFirst = await Tasks.SubmitAsync(channel, Sched.DependsOn(Sched.Hold(node, mb, 100), first));
        var afterFinished = await Tasks.SubmitAsync(channel, Sched.DependsOn(Sched.Hold(node, mc, 100), failing, DependencyCondition.Finished));
        var afterFailed = await Tasks.SubmitAsync(channel, Sched.DependsOn(Sched.Hold(node, md, 100), failing));

        var waiting = await Tasks.GetAsync(channel, afterFirst);
        Assert.Equal(TaskState.WaitingDependency, waiting.State);
        Assert.Equal("dependency", waiting.Queue.BlockingReason);
        var explained = await Sched.ExplainAsync(channel, afterFirst);
        Assert.Equal("dependency", explained.BlockingReason);
        Assert.Contains(first, explained.WaitingOnTasks);
        await File.WriteAllTextAsync(releaseFirst, "release", Ct);

        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, afterFirst)).State);
        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, afterFinished)).State);
        var cancelled = await Tasks.WaitAsync(channel, afterFailed);
        Assert.Equal(TaskState.Cancelled, cancelled.State);
        Assert.StartsWith("dependency_failed", cancelled.StateReason, StringComparison.Ordinal);
        Assert.Equal(0u, cancelled.AttemptCount);
        Assert.Equal(TaskState.Failed, (await Tasks.GetAsync(channel, failing)).State);
        Assert.True(Sched.Window(mb).Start >= Sched.Window(ma).End, "The SUCCEEDED dependent started after its dependency ended.");
        Assert.True(Sched.Window(mc).Start >= Sched.Window(mf).End, "The FINISHED dependent started after its dependency ended.");
        Assert.Equal(-1, Sched.Window(md).Start);
    }

    /// <summary>
    /// 04 section 8: a READY dependent of a SERVICE starts only once the service is ready by each readiness condition (an output line
    /// matching a regex, a TCP port listened on by the service's processes, a file), while the service keeps running; a service that is not
    /// ready within its readiness timeout keeps running with <c>readiness_timeout</c>, and its READY dependents are cancelled.
    /// </summary>
    private static async Task ReadinessAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        await Sched.WidenAsync(channel);
        var port = Sched.FreePort();
        var flag = Path.Combine(node.Root, "ready.flag");
        var cases = new (string Name, string[] Extra, ReadinessCondition Readiness)[]
        {
            ("regex", ["--ready-line", "service listening on 7"], new ReadinessCondition { OutputRegex = @"listening on \d+" }),
            ("port", ["--port", port.ToString(CultureInfo.InvariantCulture)], new ReadinessCondition { TcpListenPort = (uint)port }),
            ("file", ["--file", flag], new ReadinessCondition { FileExists = flag }),
        };
        foreach (var (name, extra, readiness) in cases)
        {
            var serviceMarker = M(node, "service-" + name);
            var service = Sched.Hold(node, serviceMarker, 60_000, ["--ready-after-ms", "1500", .. extra]);
            service.Kind = TaskKind.Service;
            service.Readiness = readiness;
            var serviceId = await Tasks.SubmitAsync(channel, service);
            var dependentMarker = M(node, "dependent-" + name);
            var dependent = await Tasks.SubmitAsync(channel, Sched.DependsOn(Sched.Hold(node, dependentMarker, 100), serviceId, DependencyCondition.Ready));
            Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, dependent)).State);
            var readyAt = Sched.ReadyAt(serviceMarker);
            Assert.True(readyAt > 0, $"{name}: the service recorded its readiness.");
            Assert.True(Sched.Window(dependentMarker).Start >= readyAt, $"{name}: the dependent started after the service was ready.");
            var running = await Tasks.GetAsync(channel, serviceId);
            Assert.Equal(TaskState.Running, running.State);
            Assert.True(running.Ready, $"{name}: the service is ready.");
            await Sched.CancelAsync(channel, serviceId);
        }

        var never = Sched.Hold(node, M(node, "never"), 60_000);
        never.Kind = TaskKind.Service;
        never.Readiness = new ReadinessCondition { FileExists = Path.Combine(node.Root, "never.flag"), ReadinessTimeoutMs = 1_000 };
        var neverId = await Tasks.SubmitAsync(channel, never);
        var orphan = await Tasks.SubmitAsync(channel, Sched.DependsOn(Sched.Hold(node, M(node, "orphan"), 100), neverId, DependencyCondition.Ready));
        var timedOut = await Sched.UntilAsync(channel, neverId, task => task.StateReason?.StartsWith("readiness_timeout", StringComparison.Ordinal) == true, "readiness_timeout");
        Assert.Equal(TaskState.Running, timedOut.State);
        Assert.False(timedOut.Ready);
        var cancelled = await Tasks.WaitAsync(channel, orphan);
        Assert.Equal(TaskState.Cancelled, cancelled.State);
        Assert.StartsWith("dependency_failed", cancelled.StateReason, StringComparison.Ordinal);
        await Sched.CancelAsync(channel, neverId);
    }

    /// <summary>
    /// 03 section 4: a second writer of a key waits with <c>exclusive_key</c> and ExplainTask lists the key and its holder; readers of a key
    /// run together; a reader and a writer do not; directory keys conflict with their ancestors and descendants unless both name different
    /// purposes; the workspace key covers its directories; different tools' keys do not conflict.
    /// </summary>
    private static async Task KeysAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        await Sched.WidenAsync(channel);
        var cases = new (string Name, string First, KeyMode FirstMode, string Second, KeyMode SecondMode, bool Together)[]
        {
            ("writers", "name:db", KeyMode.Exclusive, "name:db", KeyMode.Exclusive, false),
            ("readers", "name:cache", KeyMode.Shared, "name:cache", KeyMode.Shared, true),
            ("reader-writer", "name:cfg", KeyMode.Shared, "name:cfg", KeyMode.Exclusive, false),
            ("writer-reader", "name:lock", KeyMode.Exclusive, "name:lock", KeyMode.Shared, false),
            ("ancestor", "ws:demo/src", KeyMode.Exclusive, "ws:demo/src/lib", KeyMode.Exclusive, false),
            ("purposes", "ws:demo/pkg:deps", KeyMode.Exclusive, "ws:demo/pkg:build", KeyMode.Exclusive, true),
            ("same-purpose", "ws:demo/app:deps", KeyMode.Exclusive, "ws:demo/app/web:deps", KeyMode.Exclusive, false),
            ("workspace", "ws:other", KeyMode.Exclusive, "ws:other/docs", KeyMode.Shared, false),
            ("tools", "tool:dotnet:ws1", KeyMode.Exclusive, "tool:cargo:ws1", KeyMode.Exclusive, true),
        };
        static TaskSpec With(TaskSpec spec, string key, KeyMode mode) => mode == KeyMode.Exclusive ? Sched.Exclusive(spec, key) : Sched.Shared(spec, key);

        // Each first task holds its key until the test releases it (a file its hold waits for), so the outcome never depends on how soon a
        // below-normal process starts under load: "together" is both RUNNING at once (the second runs to its end while the first still holds),
        // "one after the other" is the second never starting while the first holds.
        var release = Path.Combine(node.Root, "keys-release.flag");
        var firsts = new List<Id>();
        foreach (var (name, key, mode, _, _, _) in cases)
        {
            firsts.Add(await Tasks.SubmitAsync(channel, With(Sched.Hold(node, M(node, name + "-1"), 120_000, "--until-file", release), key, mode)));
        }

        foreach (var (first, index) in firsts.Select((first, index) => (first, index)))
        {
            await Tasks.RunningAsync(channel, first);
            var marker = M(node, cases[index].Name + "-1");
            await Tasks.WaitForAsync(() => Sched.ReadyAt(marker) > 0, Tasks.Bound, cases[index].Name + ": the first task's hold to start");
        }

        var seconds = new List<Id>();
        foreach (var (name, _, _, key, mode, _) in cases)
        {
            seconds.Add(await Tasks.SubmitAsync(channel, With(Sched.Hold(node, M(node, name + "-2"), 500), key, mode)));
        }

        for (var index = 0; index < cases.Length; index++)
        {
            var seen = await Sched.ExplainAsync(channel, seconds[index]);
            TestContext.Current.TestOutputHelper?.WriteLine($"{cases[index].Name}: {seen.State} {seen.BlockingReason} ({seen.Text})");
        }

        for (var index = 0; index < cases.Length; index++)
        {
            if (cases[index].Together)
            {
                Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, seconds[index])).State);
                Assert.Equal(TaskState.Running, (await Tasks.GetAsync(channel, firsts[index])).State);
                continue;
            }

            var explained = await Sched.ExplainedAsync(channel, seconds[index], "exclusive_key", what: cases[index].Name);
            Assert.Contains(firsts[index], explained.WaitingOnTasks);
            Assert.NotEmpty(explained.BlockingKeys);
            if (cases[index].Name == "writers")
            {
                Assert.Contains("name:db", explained.BlockingKeys);
                Assert.Equal("exclusive_key", (await Tasks.GetAsync(channel, seconds[index])).Queue.BlockingReason);
                Assert.Contains("name:db", (await Tasks.GetAsync(channel, seconds[index], full: true)).ExclusiveKeys);
            }
        }

        // While every first task still holds (none is released yet), no conflicting second task has started.
        for (var index = 0; index < cases.Length; index++)
        {
            if (!cases[index].Together)
            {
                Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, seconds[index])).State);
                Assert.Equal(-1, Sched.Window(M(node, cases[index].Name + "-2")).Start);
            }
        }

        await File.WriteAllTextAsync(release, "release", Ct);
        foreach (var id in firsts.Concat(seconds))
        {
            Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, id)).State);
        }

        foreach (var (name, _, _, _, _, together) in cases)
        {
            var overlap = Sched.Overlap(Sched.Window(M(node, name + "-1")), Sched.Window(M(node, name + "-2")));
            Assert.True(overlap == together, $"{name}: expected the two tasks to run {(together ? "together" : "one after the other")}.");
        }
    }

    /// <summary>A key held by a running attempt stays held after the node restarts and recovers the attempt (task_concurrency_key).</summary>
    private static async Task KeysAcrossRestartAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        Id holder;
        await using (var channel = await node.ChannelAsync())
        {
            holder = await Tasks.SubmitAsync(channel, Sched.Exclusive(Sched.Hold(node, M(node, "holder"), 120_000), "name:db"));
            await Tasks.RunningAsync(channel, holder);
        }

        await node.StopAsync();
        await node.StartAsync();
        await using var after = await node.ChannelAsync();
        Assert.Equal(TaskState.Running, (await Tasks.GetAsync(after, holder)).State);
        var waiter = await Tasks.SubmitAsync(after, Sched.Exclusive(Sched.Hold(node, M(node, "waiter"), 100), "name:db"));
        var explained = await Sched.ExplainedAsync(after, waiter, "exclusive_key");
        Assert.Contains(holder, explained.WaitingOnTasks);
        Assert.Contains("name:db", explained.BlockingKeys);
        await Sched.CancelAsync(after, holder);
        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(after, waiter)).State);
    }

    /// <summary>
    /// 03 section 4: every task of a SERIAL workspace takes <c>ws:&lt;workspace&gt;</c> exclusively, so they run one at a time; a SERVICE
    /// releases it once ready, so the next task runs while the service keeps running; <c>access = EXCLUSIVE</c> in an ADAPTER_KEYS workspace
    /// conflicts with the workspace's keys, while commands without keys run beside it (03 section 4 "Default").
    /// </summary>
    private static async Task WorkspacesAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        await Sched.WidenAsync(channel);
        var serialRoot = Directory.CreateDirectory(Path.Combine(node.Root, "serial")).FullName;
        var adapterRoot = Directory.CreateDirectory(Path.Combine(node.Root, "adapter")).FullName;
        byte[] serial = [], adapter = [];
        node.Runtime.Store.Write(transaction =>
        {
            serial = Sched.SeedWorkspace(transaction, serialRoot, WorkspaceConcurrency.Serial);
            adapter = Sched.SeedWorkspace(transaction, adapterRoot, WorkspaceConcurrency.AdapterKeys);
        });
        var serialKey = "ws:" + IdText.Format(serial);

        // The holders below hold until the test releases them (a file their hold waits for), so no outcome depends on how soon a
        // below-normal process starts under load.
        var releaseOne = Path.Combine(node.Root, "serial-release.flag");
        var one = await Tasks.SubmitAsync(channel, Sched.Hold(serialRoot, M(node, "serial-1"), 120_000, "--until-file", releaseOne));
        await Tasks.RunningAsync(channel, one);
        var two = await Tasks.SubmitAsync(channel, Sched.Hold(serialRoot, M(node, "serial-2"), 200));
        var explained = await Sched.ExplainedAsync(channel, two, "exclusive_key");
        Assert.Contains(serialKey, explained.BlockingKeys);
        Assert.Contains(one, explained.WaitingOnTasks);
        Assert.Equal(-1, Sched.Window(M(node, "serial-2")).Start);
        await File.WriteAllTextAsync(releaseOne, "release", Ct);
        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, two)).State);
        Assert.False(Sched.Overlap(Sched.Window(M(node, "serial-1")), Sched.Window(M(node, "serial-2"))), "A SERIAL workspace runs its tasks one at a time.");

        var flag = Path.Combine(node.Root, "service.flag");
        var serviceMarker = M(node, "serial-service");
        var service = Sched.Hold(serialRoot, serviceMarker, 60_000, "--ready-after-ms", "1500", "--file", flag);
        service.Kind = TaskKind.Service;
        service.Readiness = new ReadinessCondition { FileExists = flag };
        var serviceId = await Tasks.SubmitAsync(channel, service);
        await Tasks.RunningAsync(channel, serviceId);
        var next = await Tasks.SubmitAsync(channel, Sched.Hold(serialRoot, M(node, "serial-next"), 200));
        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, next)).State);
        Assert.True(Sched.Window(M(node, "serial-next")).Start >= Sched.ReadyAt(serviceMarker), "The next task waited for the service's readiness.");
        Assert.Equal(TaskState.Running, (await Tasks.GetAsync(channel, serviceId)).State);
        await Sched.CancelAsync(channel, serviceId);

        var adapterKey = "ws:" + IdText.Format(adapter);
        var releaseExclusive = Path.Combine(node.Root, "exclusive-release.flag");
        var exclusive = Sched.Hold(adapterRoot, M(node, "exclusive"), 120_000, "--until-file", releaseExclusive);
        exclusive.Concurrency = new ConcurrencySpec { Access = WorkspaceAccess.Exclusive };
        var exclusiveId = await Tasks.SubmitAsync(channel, exclusive);
        await Tasks.RunningAsync(channel, exclusiveId);
        await Tasks.WaitForAsync(() => Sched.Window(M(node, "exclusive")).Start > 0, Tasks.Bound, "the exclusive task's process");
        var keyed = await Tasks.SubmitAsync(channel, Sched.Shared(Sched.Hold(adapterRoot, M(node, "keyed"), 200), adapterKey + "/src"));
        var keyless = await Tasks.SubmitAsync(channel, Sched.Hold(adapterRoot, M(node, "keyless"), 1_000));
        Assert.Contains(adapterKey, (await Sched.ExplainedAsync(channel, keyed, "exclusive_key")).BlockingKeys);
        var beside = await Tasks.WaitAsync(channel, keyless);
        var besideText = $"{beside.State} {beside.StateReason}";
        Assert.Equal(TaskState.Running, (await Tasks.GetAsync(channel, exclusiveId)).State);
        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, keyed)).State);
        await File.WriteAllTextAsync(releaseExclusive, "release", Ct);
        foreach (var id in new[] { exclusiveId, keyed, keyless })
        {
            Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, id)).State);
        }

        Assert.False(Sched.Overlap(Sched.Window(M(node, "exclusive")), Sched.Window(M(node, "keyed"))), "A key of the workspace waits for access = EXCLUSIVE.");
        Assert.True(Sched.Overlap(Sched.Window(M(node, "exclusive")), Sched.Window(M(node, "keyless"))), $"A command without keys runs beside it ({besideText}).");
    }

    /// <summary>R-EXE-013: parallelism DISABLED for the node, a pool, a workspace or a session runs that scope's tasks one at a time.</summary>
    private static async Task ParallelismAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        await Sched.WidenAsync(channel);
        void Apart(string what, params string[] markers)
        {
            for (var first = 0; first < markers.Length; first++)
            {
                for (var second = first + 1; second < markers.Length; second++)
                {
                    Assert.False(Sched.Overlap(Sched.Window(markers[first]), Sched.Window(markers[second])), $"{what}: {Path.GetFileName(markers[first])} and {Path.GetFileName(markers[second])} overlapped.");
                }
            }
        }

        async Task AllAsync(IEnumerable<Id> ids)
        {
            foreach (var id in ids)
            {
                Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, id)).State);
            }
        }

        // GLOBAL.
        await Sched.SetParallelismAsync(channel, ParallelismScope.Global, string.Empty, ParallelismMode.Disabled);
        var global = Enumerable.Range(0, 3).Select(index => M(node, $"global-{index}")).ToList();
        var globalIds = new List<Id>();
        foreach (var marker in global)
        {
            globalIds.Add(await Tasks.SubmitAsync(channel, Sched.Hold(node, marker, 1_500)));
        }

        Assert.Equal("global_limit", (await Sched.ExplainedAsync(channel, globalIds[2], "global_limit")).BlockingReason);
        await AllAsync(globalIds);
        Apart("GLOBAL", [.. global]);
        await Sched.SetParallelismAsync(channel, ParallelismScope.Global, string.Empty, ParallelismMode.Auto);

        // POOL: the pool's tasks one at a time, another pool's beside them.
        var created = await channel.Queue.CreatePoolAsync(new QueueServiceCreatePoolRequest { Meta = Tasks.Meta(), Name = "serial" }, cancellationToken: Ct);
        Assert.Null(created.Error);
        await Sched.SetParallelismAsync(channel, ParallelismScope.Pool, "serial", ParallelismMode.Disabled);
        var releaseOutside = Path.Combine(node.Root, "outside-release.flag");
        var outside = await Tasks.SubmitAsync(channel, Sched.Hold(node, M(node, "pool-outside"), 120_000, "--until-file", releaseOutside));
        await Tasks.WaitForAsync(() => Sched.ReadyAt(M(node, "pool-outside")) > 0, Tasks.Bound, "the other pool's task to start");
        var pooled = new List<Id>();
        foreach (var index in new[] { 0, 1 })
        {
            var spec = Sched.Hold(node, M(node, $"pool-{index}"), 1_500);
            spec.Pool = "serial";
            pooled.Add(await Tasks.SubmitAsync(channel, spec));
        }

        Assert.Equal((uint)1, (await Sched.ExplainedAsync(channel, pooled[1], "pool_limit")).PoolMaxParallel);
        await AllAsync(pooled);
        Assert.Equal(TaskState.Running, (await Tasks.GetAsync(channel, outside)).State);
        await File.WriteAllTextAsync(releaseOutside, "release", Ct);
        await AllAsync([outside]);
        Apart("POOL", M(node, "pool-0"), M(node, "pool-1"));
        Assert.True(Sched.Overlap(Sched.Window(M(node, "pool-outside")), Sched.Window(M(node, "pool-0"))), "Another pool's task ran beside the serial pool.");

        // WORKSPACE.
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "ws")).FullName;
        byte[] workspace = [];
        node.Runtime.Store.Write(transaction => workspace = Sched.SeedWorkspace(transaction, root, WorkspaceConcurrency.AdapterKeys));
        await Sched.SetParallelismAsync(channel, ParallelismScope.Workspace, IdText.Format(workspace), ParallelismMode.Disabled);
        var inWorkspace = new List<Id>();
        foreach (var index in new[] { 0, 1 })
        {
            inWorkspace.Add(await Tasks.SubmitAsync(channel, Sched.Hold(root, M(node, $"ws-{index}"), 700)));
        }

        await AllAsync(inWorkspace);
        Apart("WORKSPACE", M(node, "ws-0"), M(node, "ws-1"));

        // SESSION.
        byte[] session = [];
        node.Runtime.Store.Write(transaction => session = Sched.SeedSession(transaction));
        await Sched.SetParallelismAsync(channel, ParallelismScope.Session, IdText.Format(session), ParallelismMode.Disabled);
        var inSession = new List<Id>();
        foreach (var index in new[] { 0, 1 })
        {
            inSession.Add(await Sched.SubmitAsSessionAsync(node, Sched.Hold(node, M(node, $"session-{index}"), 700), session));
        }

        await AllAsync(inSession);
        Apart("SESSION", M(node, "session-0"), M(node, "session-1"));
    }

    /// <summary>
    /// 03 section 4 (R-EXE-014): two sessions with equal work in one pool share admissions equally (deficit round robin across owners),
    /// whatever the submission order: one session submits all its tasks before the other, while the pool is paused, then the pool resumes.
    /// The 15 section 4 measurement over 10 minutes of CPU-seconds is the closed-loop benchmark; this checks the share of starts and of
    /// running time while both sessions have work.
    /// </summary>
    private static async Task FairnessAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        byte[] first = [], second = [];
        node.Runtime.Store.Write(transaction =>
        {
            first = Sched.SeedSession(transaction);
            second = Sched.SeedSession(transaction);
        });
        await Sched.SetParallelismAsync(channel, ParallelismScope.Global, string.Empty, ParallelismMode.Fixed, 2);
        Assert.Null((await channel.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), Pool = "default" }, cancellationToken: Ct)).Error);
        const int PerSession = 12;
        var tasks = new List<(Id Id, string Marker, bool First)>();
        foreach (var (session, isFirst) in new[] { (first, true), (second, false) })
        {
            for (var index = 0; index < PerSession; index++)
            {
                var marker = M(node, $"{(isFirst ? "a" : "b")}-{index}");
                tasks.Add((await Sched.SubmitAsSessionAsync(node, Sched.Hold(node, marker, 300), session), marker, isFirst));
            }
        }

        Assert.Null((await channel.Queue.ResumePoolAsync(new QueueServiceResumePoolRequest { Meta = Tasks.Meta(), Pool = "default" }, cancellationToken: Ct)).Error);
        foreach (var (id, _, _) in tasks)
        {
            Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, id)).State);
        }

        // Slot occupancy includes process launch and finalization delays. This time-share assertion is exclusive under the testing
        // policy; machine-isolated admission budgets do not isolate the below-normal processes from other projects' CPU load.
        var windows = new List<((long Start, long End) Window, bool First)>();
        foreach (var (id, _, isFirst) in tasks)
        {
            var record = await Tasks.GetAsync(channel, id);
            windows.Add(((Sched.Ms(record.StartedAt), Sched.Ms(record.FinishedAt)), isFirst));
        }

        windows = [.. windows.OrderBy(task => task.Window.Start)];
        var firstStarts = windows.Take(PerSession).Count(task => task.First);
        TestContext.Current.TestOutputHelper?.WriteLine($"first session: {firstStarts} of the first {PerSession} starts");
        Assert.InRange(firstStarts, 5, 7);

        // Running time while both had work: up to the earlier of the two sessions' last ends.
        var end = Math.Min(windows.Where(task => task.First).Max(task => task.Window.End), windows.Where(task => !task.First).Max(task => task.Window.End));
        double Share(bool which) => windows.Where(task => task.First == which).Sum(task => Math.Max(0, Math.Min(task.Window.End, end) - task.Window.Start));
        var share = Share(true) / (Share(true) + Share(false));
        TestContext.Current.TestOutputHelper?.WriteLine($"first session's share of running time while both had work: {share:P1}");
        Assert.InRange(share, 0.40, 0.60);
    }

    /// <summary>
    /// 15 section 4 fairness: two sessions keep equal CPU-bound work queued in one pool (<c>arcforges-testload cpu</c>, one thread each)
    /// while the node runs four at a time; over the run (10 minutes by default) each session receives 50% +- 10% of the managed
    /// CPU-seconds, read from the attempt records (<c>usage.cpu_time_ms</c>).
    /// </summary>
    private static async Task FairCpuSecondsAsync()
    {
        var minutes = double.TryParse(Environment.GetEnvironmentVariable("ARCFORGES_FAIRNESS_MINUTES"), NumberStyles.Float, CultureInfo.InvariantCulture, out var configured)
            ? configured : 10;
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        byte[] first = [], second = [];
        node.Runtime.Store.Write(transaction =>
        {
            first = Sched.SeedSession(transaction);
            second = Sched.SeedSession(transaction);
        });
        await Sched.SetParallelismAsync(channel, ParallelismScope.Global, string.Empty, ParallelismMode.Fixed, 4);
        var submitted = new List<(Id Id, bool First)>();
        async Task TopUpAsync(byte[] session, bool isFirst)
        {
            var open = 0;
            foreach (var (id, _) in submitted.Where(task => task.First == isFirst))
            {
                if ((await Tasks.GetAsync(channel, id)).State is TaskState.Queued or TaskState.Running)
                {
                    open++;
                }
            }

            for (; open < 6; open++)
            {
                var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "cpu", "--threads", "1", "--iterations", "1000000000");
                spec.Resources = new ResourceSpec { Hint = new ResourceDemand { CpuMillicores = 1000, MemExpectedBytes = 64UL << 20 } };
                submitted.Add((await Sched.SubmitAsSessionAsync(node, spec, session), isFirst));
            }
        }

        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < TimeSpan.FromMinutes(minutes))
        {
            await TopUpAsync(first, true);
            await TopUpAsync(second, false);
            await Task.Delay(1_000, Ct);
        }

        foreach (var (id, _) in submitted)
        {
            if ((await Tasks.GetAsync(channel, id)).State is TaskState.Queued or TaskState.Running)
            {
                await Sched.CancelAsync(channel, id);
            }
        }

        double a = 0, b = 0;
        foreach (var (id, which) in submitted)
        {
            if ((await Tasks.GetAsync(channel, id)).CurrentAttempt is { } attempt)
            {
                var seconds = attempt.Usage.CpuTimeMs / 1000.0;
                (a, b) = which ? (a + seconds, b) : (a, b + seconds);
            }
        }

        var share = a / (a + b);
        TestContext.Current.TestOutputHelper?.WriteLine($"{minutes} min: first session {a:0.0} CPU-s, second {b:0.0} CPU-s, share {share:P1}; {submitted.Count} tasks");
        Assert.InRange(share, 0.40, 0.60);
    }
    /// <summary>
    /// AD-0006 section 4 (R-EXE-010): a failing caller-asserted IDEMPOTENT task is retried (RETRY_WAIT, 1 + 2 attempts); PURE with
    /// <c>retry.max_attempts = 2</c> makes 2; UNKNOWN and SIDE_EFFECTING are never retried after the process started; an agent's PURE becomes
    /// UNKNOWN with a warning unless <c>accept_agent_assertions</c>; a <c>retry_safety</c> rule asserts IDEMPOTENT (source POLICY), and
    /// only a HUMAN may change those rules.
    /// </summary>
    private static async Task RetriesAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        TaskSpec Failing(string name, SideEffectClass? sideEffect, uint? maxAttempts = null)
        {
            var spec = Sched.Hold(node, M(node, name), 50, "--exit-code", "3");
            if (sideEffect is { } value)
            {
                spec.SideEffect = value;
            }

            spec.Retry = FastRetry.Clone();
            if (maxAttempts is { } attempts)
            {
                spec.Retry.MaxAttempts = attempts;
            }

            return spec;
        }

        async Task<ManagedTask> EndedAsync(NodeChannel through, TaskSpec spec)
        {
            var task = await Tasks.WaitAsync(through, await Tasks.SubmitAsync(through, spec));
            Assert.Equal(TaskState.Failed, task.State);
            return task;
        }

        var idempotentId = await Tasks.SubmitAsync(channel, Failing("idempotent", SideEffectClass.Idempotent));
        await Sched.UntilAsync(channel, idempotentId, task => task.State == TaskState.RetryWait || task.AttemptCount >= 2, "a retry");
        var idempotent = await Tasks.WaitAsync(channel, idempotentId);
        Assert.Equal(TaskState.Failed, idempotent.State);
        Assert.Equal(3u, idempotent.AttemptCount);
        Assert.Equal(SideEffectSource.Caller, idempotent.SideEffectSource);
        Assert.Equal(3, Tasks.Marker(M(node, "idempotent")).Count(line => line.Event == "start"));

        Assert.Equal(2u, (await EndedAsync(channel, Failing("pure", SideEffectClass.Pure, 2))).AttemptCount);
        Assert.Equal(1u, (await EndedAsync(channel, Failing("unknown", null, 5))).AttemptCount);
        Assert.Equal(1u, (await EndedAsync(channel, Failing("side-effecting", SideEffectClass.SideEffecting, 5))).AttemptCount);

        // An agent's assertion is not accepted by default.
        var submitted = await Tasks.SubmitRawAsync(agent, Failing("agent", SideEffectClass.Pure));
        Assert.Null(submitted.Error);
        Assert.Contains(submitted.Value.Warnings, warning => warning.Contains("accept_agent_assertions", StringComparison.Ordinal));
        var agentTask = await Tasks.WaitAsync(agent, submitted.Value.TaskId);
        Assert.Equal(SideEffectClass.Unknown, agentTask.SideEffect);
        Assert.Equal(1u, agentTask.AttemptCount);

        // retry_safety changes only from a HUMAN.
        Assert.NotNull((await Sched.ChangePolicyAsync(channel, policy => (policy.RetrySafety ??= new RetrySafetyPolicy()).AcceptAgentAssertions = true)).Error);
        Assert.NotNull((await Sched.ChangePolicyAsync(agent, policy => (policy.RetrySafety ??= new RetrySafetyPolicy()).AcceptAgentAssertions = true)).Error);
        var accepted = await Sched.ChangePolicyAsync(human, policy =>
        {
            policy.RetrySafety ??= new RetrySafetyPolicy();
            policy.RetrySafety.AcceptAgentAssertions = true;
            policy.RetrySafety.Rules.Add(new RetrySafetyRule { Pattern = ".*ruled-marker.*", SideEffect = SideEffectClass.Idempotent });
        });
        Assert.True(accepted.Error is null, $"UpdatePolicy: {accepted.Error?.Code} {accepted.Error?.Details}");

        var asserted = await EndedAsync(agent, Failing("agent-accepted", SideEffectClass.Pure));
        Assert.Equal(SideEffectClass.Pure, asserted.SideEffect);
        Assert.Equal(3u, asserted.AttemptCount);

        var ruled = await EndedAsync(channel, Failing("ruled-marker", null));
        Assert.Equal(SideEffectClass.Idempotent, ruled.SideEffect);
        Assert.Equal(SideEffectSource.Policy, ruled.SideEffectSource);
        Assert.Equal(3u, ruled.AttemptCount);
    }

    /// <summary>AD-0006 section 4: after a node loss (an attempt of an earlier boot is LOST) a SIDE_EFFECTING task stays LOST; an IDEMPOTENT one runs again.</summary>
    private static async Task NodeLossAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        Id sideEffecting, idempotent;
        var lostAttempts = new List<Id>();
        await using (var channel = await node.ChannelAsync())
        {
            var first = Sched.Hold(node, M(node, "side-effecting"), 120_000);
            first.SideEffect = SideEffectClass.SideEffecting;
            var second = Sched.Hold(node, M(node, "idempotent"), 120_000);
            second.SideEffect = SideEffectClass.Idempotent;
            second.Retry = FastRetry.Clone();
            sideEffecting = await Tasks.SubmitAsync(channel, first);
            idempotent = await Tasks.SubmitAsync(channel, second);
            lostAttempts.Add((await Tasks.RunningAsync(channel, sideEffecting)).AttemptId);
            lostAttempts.Add((await Tasks.RunningAsync(channel, idempotent)).AttemptId);
        }

        await node.StopAsync();

        // A simulated reboot: the attempts record another boot identity than this boot's (AD-0006 section 3).
        using (var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "previous-boot" }))
        {
            store.Write(transaction => transaction.Execute("UPDATE attempt SET boot_identity = 'previous-boot';"));
        }

        await node.StartAsync();
        await using var after = await node.ChannelAsync();
        var lost = await Tasks.GetAsync(after, sideEffecting);
        Assert.Equal(TaskState.Lost, lost.State);
        Assert.Equal(1u, lost.AttemptCount);
        var retried = await Sched.UntilAsync(after, idempotent, task => task.AttemptCount == 2 && task.CurrentAttempt?.State == AttemptState.Running, "the retry after the node loss");
        Assert.Equal(AttemptState.Running, retried.CurrentAttempt.State);
        await Sched.CancelAsync(after, idempotent);

        // The attempts of the simulated earlier boot still run (no reboot happened): on Linux their units are stopped here, as a reboot would.
        if (OperatingSystem.IsLinux())
        {
            foreach (var attempt in lostAttempts)
            {
                ArcForges.Tests.SystemdTestEnvironment.Systemctl("stop", ArcForges.Tests.SystemdTestEnvironment.AttemptUnit(IdText.Format(attempt)));
            }
        }
    }

    /// <summary>
    /// 03 section 4 (R-RES-005): two tasks whose expected memory together exceeds <c>B_mem</c> run one after the other (the second waits
    /// with <c>budget_memory</c>), and no admission ever brings the accounted memory of the running attempts above <c>B_mem</c>.
    /// </summary>
    private static async Task MemoryAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var snapshot = await Sched.SnapshotAsync(channel);
        var each = (ulong)(snapshot.BudgetMemBytes * 0.55);
        TaskSpec Large(string name, int holdMs)
        {
            var spec = Sched.Hold(node, M(node, name), holdMs);
            spec.Resources.Hint = new ResourceDemand { CpuMillicores = 100, MemExpectedBytes = each, MemCeilingBytes = each };
            return spec;
        }

        var releaseLarge = Path.Combine(node.Root, "large-release.flag");
        var firstSpec = Large("first", 120_000);
        firstSpec.Command.Argv.Argv.Add("--until-file");
        firstSpec.Command.Argv.Argv.Add(releaseLarge);
        var first = await Tasks.SubmitAsync(channel, firstSpec);
        await Tasks.RunningAsync(channel, first);
        var second = await Tasks.SubmitAsync(channel, Large("second", 200));
        var explained = await Sched.ExplainedAsync(channel, second, "budget_memory");
        Assert.True(explained.AvailableMemBytes < each, $"available {explained.AvailableMemBytes} < requested {each}");
        Assert.Equal("FEASIBLE", explained.Feasibility);
        await File.WriteAllTextAsync(releaseLarge, "release", Ct);
        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, first)).State);
        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, second)).State);
        Assert.False(Sched.Overlap(Sched.Window(M(node, "first")), Sched.Window(M(node, "second"))));
        var admitted = Sched.LogEvents(node, "execution.admitted");
        Assert.Equal(2, admitted.Count);
        Assert.All(admitted, admission => Assert.True(Sched.Field(admission, "accountedAfter") <= Sched.Field(admission, "budgetMemory"),
            $"accounted {Sched.Field(admission, "accountedAfter")} > B_mem {Sched.Field(admission, "budgetMemory")}"));
    }

    /// <summary>
    /// 03 section 4: a task whose memory exceeds the managed share even on an idle node waits with <c>exceeds_capacity</c>, raises
    /// TASK_INFEASIBLE, never holds the large-task reservation, and feasible work submitted after it runs at once.
    /// </summary>
    private static async Task InfeasibleAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var capacity = node.Runtime.Execution!.Settings.CapacityMemory;
        var changed = await Sched.ChangePolicyAsync(human, policy => policy.Resources.MaxTaskMemoryBytes = (ulong)capacity);
        Assert.True(changed.Error is null, $"UpdatePolicy: {changed.Error?.Code} {changed.Error?.Details}");
        var share = node.Runtime.Execution!.Settings.MaxShareMemory;
        var huge = Sched.Hold(node, M(node, "huge"), 100);
        huge.Resources.Hint = new ResourceDemand { CpuMillicores = 100, MemExpectedBytes = (ulong)(share + (256 * MiB)), MemCeilingBytes = (ulong)(share + (256 * MiB)) };
        var hugeId = await Tasks.SubmitAsync(channel, huge);
        var explained = await Sched.ExplainedAsync(channel, hugeId, "exceeds_capacity");
        Assert.Equal("EXCEEDS_CAPACITY", explained.Feasibility);
        Assert.False(explained.LargeReservationActive);

        var watch = Stopwatch.StartNew();
        var small = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, Sched.Hold(node, M(node, "small"), 100)));
        Assert.Equal(TaskState.Succeeded, small.State);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(30), $"Feasible work took {watch.Elapsed} behind an infeasible task.");

        var queue = await Sched.QueueAsync(channel);
        var entry = Assert.Single(queue.Entries, entry => entry.TaskId.Equals(hugeId));
        Assert.False(entry.ReservedForLarge);
        Assert.Equal("exceeds_capacity", entry.Queue.BlockingReason);
        var findings = node.Runtime.Store.Read(reader => ExecutionFindings.OpenFor(reader, "task", hugeId.Value.Span));
        Assert.Contains(findings, finding => finding.Kind == FindingKind.TaskInfeasible);
        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, hugeId)).State);
        await Sched.CancelAsync(channel, hugeId);
    }

    /// <summary>
    /// 03 sections 4 and 5.3: on an idle node a task estimated above <c>B_cpu</c> starts at once with its grant clamped to <c>B_cpu</c>, and
    /// the tool-level setting (a synthetic adapter's <c>--threads</c>) follows the grant: <c>ceil(grant / 1000)</c>.
    /// </summary>
    private static async Task CpuClampAsync()
    {
        await using var node = await InProcessNode.Create(tools: new Sched.TestLoadCpuAdapter()).StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var snapshot = await Sched.SnapshotAsync(channel);
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "cpu", "--iterations", "200000000");
        spec.Resources = new ResourceSpec { Hint = new ResourceDemand { CpuMillicores = 1_000_000 } };
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, spec));
        Assert.Equal(TaskState.Succeeded, task.State);
        var admission = Assert.Single(Sched.LogEvents(node, "execution.admitted"));
        var grant = Sched.Field(admission, "cpuGrant");
        TestContext.Current.TestOutputHelper?.WriteLine($"B_cpu {snapshot.BudgetCpuMillicores} mc at the start; grant {grant} mc; tool parallelism {task.CurrentAttempt.ToolParallelism}");
        Assert.InRange(grant, 1_000, (long)snapshot.CapacityCpuMillicores);
        Assert.InRange(grant, (long)(snapshot.BudgetCpuMillicores * 0.75), (long)(snapshot.BudgetCpuMillicores * 1.25) + 1);
        Assert.Equal("testload", task.CurrentAttempt.Tool);
        Assert.Equal((uint)ToolParallelism.For(grant, 64), task.CurrentAttempt.ToolParallelism);
        Assert.Equal(ToolParallelism.For(grant, 64), Sched.Field(admission, "toolParallelism"));
    }

    /// <summary>
    /// 03 section 4: on a busy node a large task that cannot start takes the reservation after <c>large_task_bypass</c>, which holds back a
    /// smaller task of its class (<c>large_task_reserved</c>) although that one would fit; after <c>large_task_reservation_max</c> the
    /// reservation lapses and the smaller task starts; once the node is free the large task starts with its grant clamped to <c>B_cpu</c>.
    /// </summary>
    private static async Task ReservationAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var changed = await Sched.ChangePolicyAsync(human, policy =>
        {
            policy.Resources.LargeTaskBypassMs = 10_000;
            policy.Resources.LargeTaskReservationMaxMs = 60_000;
        });
        Assert.True(changed.Error is null, $"UpdatePolicy: {changed.Error?.Code} {changed.Error?.Details}");
        var budget = (await Sched.SnapshotAsync(channel)).BudgetCpuMillicores;
        TaskSpec Cpu(string name, int holdMs, uint millicores)
        {
            var spec = Sched.Hold(node, M(node, name), holdMs);
            spec.Resources.Hint.CpuMillicores = millicores;
            return spec;
        }

        var fillers = new List<Id>();
        foreach (var name in new[] { "filler-1", "filler-2" })
        {
            fillers.Add(await Tasks.SubmitAsync(channel, Cpu(name, 240_000, (uint)(budget * 0.5))));
        }

        foreach (var filler in fillers)
        {
            await Tasks.RunningAsync(channel, filler);
        }

        var large = await Tasks.SubmitAsync(channel, Cpu("large", 200, 1_000_000));
        await Sched.ExplainedAsync(channel, large, "budget_cpu");
        var watch = Stopwatch.StartNew();
        while (!(await Sched.ExplainAsync(channel, large)).LargeReservationActive)
        {
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(40), "The large task took no reservation within 40 s.");
            await Task.Delay(200, Ct);
        }

        var reservedAfter = watch.Elapsed;
        TestContext.Current.TestOutputHelper?.WriteLine($"reserved after {reservedAfter.TotalSeconds:0.0} s");
        Assert.True(reservedAfter >= TimeSpan.FromSeconds(6), "The reservation waited for large_task_bypass.");
        Assert.True((await Sched.QueueAsync(channel)).Entries.Single(entry => entry.TaskId.Equals(large)).ReservedForLarge);

        var small = await Tasks.SubmitAsync(channel, Cpu("small", 100, 10));
        await Sched.ExplainedAsync(channel, small, "large_task_reserved");
        var ran = await Tasks.WaitAsync(channel, small, bound: TimeSpan.FromSeconds(120));
        Assert.Equal(TaskState.Succeeded, ran.State);
        var lapsedAfter = watch.Elapsed;
        TestContext.Current.TestOutputHelper?.WriteLine($"the small task ran {lapsedAfter.TotalSeconds:0.0} s after the large one waited");
        Assert.True(lapsedAfter - reservedAfter >= TimeSpan.FromSeconds(55), "The reservation held for large_task_reservation_max.");
        var lapsed = await Sched.ExplainAsync(channel, large);
        Assert.False(lapsed.LargeReservationActive);
        Assert.Equal(TaskState.Queued, lapsed.State);

        foreach (var filler in fillers)
        {
            await Sched.CancelAsync(channel, filler);
        }

        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, large)).State);
        var admission = Sched.LogEvents(node, "execution.admitted").Single(entry => Sched.Text(entry, "task") == IdText.Format(large));
        Assert.True(Sched.Field(admission, "cpuGrant") < 1_000_000, "The large task's grant was clamped to B_cpu.");
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

    /// <summary>15 section 4: when an execution ends, the next admissible queued task starts within 500 ms (task records: finished_at to started_at).</summary>
    private static async Task QueueStartAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        await Sched.SetParallelismAsync(channel, ParallelismScope.Global, string.Empty, ParallelismMode.Fixed, 1);
        var latencies = new List<long>();
        for (var round = 0; round < 5; round++)
        {
            var release = Path.Combine(node.Root, $"release-{round}.flag");
            var running = await Tasks.SubmitAsync(channel, Sched.Hold(node, M(node, $"running-{round}"), 120_000, "--until-file", release));
            await Tasks.RunningAsync(channel, running);
            var queued = await Tasks.SubmitAsync(channel, Sched.Hold(node, M(node, $"queued-{round}"), 100));
            await Sched.ExplainedAsync(channel, queued, "global_limit");
            await File.WriteAllTextAsync(release, "release", Ct);
            var ended = await Tasks.WaitAsync(channel, running);
            var next = await Tasks.WaitAsync(channel, queued);
            latencies.Add(Sched.Ms(next.StartedAt) - Sched.Ms(ended.FinishedAt));
        }

        TestContext.Current.TestOutputHelper?.WriteLine("queue start after release (ms): " + string.Join(", ", latencies));
        Assert.All(latencies, latency => Assert.InRange(latency, -50, 500));
    }

    /// <summary>
    /// <c>SetTaskPriority</c> on a running task (api-catalogue): the task takes the new class and its attempt's container the class's CPU
    /// weight (03 section 5.2: LOW is weight 3, Linux <c>CPUWeight</c> 50); a pool change is refused for a running task.
    /// </summary>
    private static async Task RunningPriorityAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var taskId = await Tasks.SubmitAsync(channel, Sched.Hold(node, M(node, "running"), 60_000));
        var attempt = await Tasks.RunningAsync(channel, taskId);
        var changed = await channel.Tasks.SetTaskPriorityAsync(new TaskServiceSetTaskPriorityRequest { Meta = Tasks.Meta(), TaskId = taskId, Priority = Priority.Low },
            cancellationToken: Ct);
        Assert.True(changed.Error is null, $"SetTaskPriority: {changed.Error?.Code}");
        Assert.Equal(Priority.Low, (await Tasks.GetAsync(channel, taskId)).EffectivePriority);
        await node.Runtime.Execution!.PlatformCalls.DrainAsync(TimeSpan.FromSeconds(10));
        if (OperatingSystem.IsWindows())
        {
            using var job = ArcForges.Node.Platform.Windows.JobObject.Open(
                ArcForges.Node.Platform.Windows.WindowsExecutionPlatform.JobName(IdText.Format(node.Runtime.NodeId.Span), IdText.Format(attempt.AttemptId)))!;
            Assert.Equal(3u, job.CpuRateControl().Value);
        }
        else
        {
            Assert.Equal("50", ArcForges.Tests.SystemdTestEnvironment.Property(ArcForges.Tests.SystemdTestEnvironment.AttemptUnit(IdText.Format(attempt.AttemptId)), "CPUWeight"));
        }

        Assert.Equal("invalid_argument", (await channel.Tasks.SetTaskPriorityAsync(new TaskServiceSetTaskPriorityRequest
        {
            Meta = Tasks.Meta(),
            TaskId = taskId,
            Pool = "background",
        }, cancellationToken: Ct)).Error?.Code);
        await Sched.CancelAsync(channel, taskId);
    }
    /// <summary>R-EXE-011 on Linux: PauseTask freezes a pausable task's unit (PAUSED, its timeout clock stopped), ResumeTask thaws it, and a paused task can be cancelled.</summary>
    private static async Task PauseAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var marker = M(node, "paused");
        var spec = Sched.Hold(node, marker, 3_000);
        spec.Resources.Pausable = true;
        spec.TimeoutMs = 4_000;
        var taskId = await Tasks.SubmitAsync(channel, spec);
        await Tasks.RunningAsync(channel, taskId);
        await Tasks.WaitForAsync(() => Sched.Window(marker).Start > 0, Tasks.Bound, "the hold to start");
        var pause = await channel.Tasks.PauseTaskAsync(new TaskServicePauseTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.True(pause.Error is null, $"PauseTask: {pause.Error?.Code}");
        await Sched.UntilAsync(channel, taskId, task => task.State == TaskState.Paused, "PAUSED");
        await Task.Delay(5_000, Ct);
        Assert.Equal(-1, Sched.Window(marker).End);
        Assert.Equal(TaskState.Paused, (await Tasks.GetAsync(channel, taskId)).State);
        var resumedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var resume = await channel.Tasks.ResumeTaskAsync(new TaskServiceResumeTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.True(resume.Error is null, $"ResumeTask: {resume.Error?.Code}");
        var done = await Tasks.WaitAsync(channel, taskId);

        // Its 3 s hold elapsed while it was frozen, so it ends once thawed; the 4 s timeout counts only the running time, not the 5 s frozen.
        Assert.Equal(TaskState.Succeeded, done.State);
        var (_, end) = Sched.Window(marker);
        Assert.True(end >= resumedAt - 100, $"The hold ended at {end}, before the resume at {resumedAt}.");

        var plain = await Tasks.SubmitAsync(channel, Sched.Hold(node, M(node, "plain"), 30_000));
        await Tasks.RunningAsync(channel, plain);
        var refused = await channel.Tasks.PauseTaskAsync(new TaskServicePauseTaskRequest { Meta = Tasks.Meta(), TaskId = plain }, cancellationToken: Ct);
        Assert.Equal("invalid_state", refused.Error?.Code);
        await Sched.CancelAsync(channel, plain);

        var again = Sched.Hold(node, M(node, "cancelled"), 30_000);
        again.Resources.Pausable = true;
        var againId = await Tasks.SubmitAsync(channel, again);
        await Tasks.RunningAsync(channel, againId);
        Assert.Null((await channel.Tasks.PauseTaskAsync(new TaskServicePauseTaskRequest { Meta = Tasks.Meta(), TaskId = againId }, cancellationToken: Ct)).Error);
        await Sched.UntilAsync(channel, againId, task => task.State == TaskState.Paused, "PAUSED");
        await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = againId }, cancellationToken: Ct);
        Assert.Equal(TaskState.Cancelled, (await Tasks.WaitAsync(channel, againId)).State);
    }

    /// <summary>
    /// 03 section 4 aging with SetTaskPriority: a BACKGROUND task that has waited 2.5 starvation bounds (its queueing moved 25 minutes back in
    /// the store, the default bound being 10 minutes) has aged to NORMAL; demoted to LOW, it stays LOW over later passes, because its aging
    /// restarts at the change (task.aged_at), and rises to NORMAL once a new bound has elapsed since the change (aged_at moved back 10
    /// minutes). The task waits in a paused pool, so no process runs.
    /// </summary>
    private static async Task AgingRestartAsync()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var execution = node.Runtime.Execution!;
        Assert.Null((await channel.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), Pool = "default" }, cancellationToken: Ct)).Error);
        var spec = Sched.Hold(node, M(node, "aging"), 100);
        spec.Priority = Priority.Background;
        var taskId = await Tasks.SubmitAsync(channel, spec);
        var id = taskId.Value.ToByteArray();
        const long Minute = 60L * 1_000_000;
        node.Runtime.Store.Write(transaction => transaction.Execute("UPDATE task SET queued_at = queued_at - $back WHERE task_id = $id;", ("$back", 25 * Minute), ("$id", id)));
        execution.Kick();
        await Sched.UntilAsync(channel, taskId, task => task.EffectivePriority == Priority.Normal, "aging to NORMAL after 2.5 bounds");

        var demoted = await channel.Tasks.SetTaskPriorityAsync(new TaskServiceSetTaskPriorityRequest { Meta = Tasks.Meta(), TaskId = taskId, Priority = Priority.Low },
            cancellationToken: Ct);
        Assert.True(demoted.Error is null, $"SetTaskPriority: {demoted.Error?.Code}");
        Assert.Equal(Priority.Low, (await Tasks.GetAsync(channel, taskId)).EffectivePriority);

        // Passes run every 2 s while a task waits: after several of them it is still LOW.
        for (var pass = 0; pass < 3; pass++)
        {
            execution.Kick();
            await Task.Delay(2_500, Ct);
            Assert.Equal(Priority.Low, (await Tasks.GetAsync(channel, taskId)).EffectivePriority);
        }

        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, taskId)).State);
        node.Runtime.Store.Write(transaction => transaction.Execute("UPDATE task SET aged_at = aged_at - $back WHERE task_id = $id;", ("$back", 10 * Minute), ("$id", id)));
        execution.Kick();
        await Sched.UntilAsync(channel, taskId, task => task.EffectivePriority == Priority.Normal, "aging one class a bound after the change");
        await Sched.CancelAsync(channel, taskId);
    }

    /// <summary>
    /// 03 section 7 across a node restart: an attempt frozen at Pressure (its MemoryHigh lowered) stays PAUSED while the node is down and
    /// after it starts again, and thaws once the level has been Normal for 30 s, with its launch MemoryHigh restored: the cause of the
    /// pause is persisted in the task's state_reason (pressure_frozen).
    /// </summary>
    private static async Task PressureRestartAsync()
    {
        // The live machine (exclusive): the thresholds are crossed by the machine's available memory.
        await using var node = await InProcessNode.Create().WithLiveMachine().StartAsync();
        Id backgroundId;
        string unit, launchHigh;
        await using (var channel = await node.ChannelAsync(helloAsHuman: true))
        {
            var background = Sched.Hold(node, M(node, "frozen"), 240_000);
            background.Priority = Priority.Background;
            background.Resources.Pausable = true;
            backgroundId = await Tasks.SubmitAsync(channel, background);
            var attempt = await Tasks.RunningAsync(channel, backgroundId);
            unit = ArcForges.Tests.SystemdTestEnvironment.AttemptUnit(IdText.Format(attempt.AttemptId));
            launchHigh = ArcForges.Tests.SystemdTestEnvironment.Property(unit, "MemoryHigh");
            var execution = node.Runtime.Execution!;
            var forced = await Sched.ChangePolicyAsync(channel, policy =>
            {
                policy.Resources.Pressure ??= new PressureThresholds();
                policy.Resources.Pressure.TightAvailableFraction = 0.995;
                policy.Resources.Pressure.PressureAvailableFraction = 0.99;
                policy.Resources.Pressure.CriticalAvailableFraction = 0.001;
            });
            Assert.True(forced.Error is null, $"UpdatePolicy: {forced.Error?.Code} {forced.Error?.Details}");
            await Tasks.WaitForAsync(() => execution.Resources?.Current?.Pressure == PressureLevel.Pressure, TimeSpan.FromSeconds(60), "the Pressure level");
            var frozen = await Sched.UntilAsync(channel, backgroundId, task => task.State == TaskState.Paused, "the freeze");
            Assert.StartsWith("pressure_frozen:", frozen.StateReason, StringComparison.Ordinal);
            await execution.PlatformCalls.DrainAsync(TimeSpan.FromSeconds(10));
            Assert.NotEqual(launchHigh, ArcForges.Tests.SystemdTestEnvironment.Property(unit, "MemoryHigh"));

            // Back to the default thresholds, and the node stops well within the 30 s at Normal that would thaw it.
            var restored = await Sched.ChangePolicyAsync(channel, policy => policy.Resources.Pressure = new PressureThresholds
            {
                TightAvailableFraction = 0.10,
                PressureAvailableFraction = 0.05,
                CriticalAvailableFraction = 0.02,
            });
            Assert.True(restored.Error is null, $"UpdatePolicy: {restored.Error?.Code} {restored.Error?.Details}");
            Assert.Equal(TaskState.Paused, (await Tasks.GetAsync(channel, backgroundId)).State);
        }

        await node.StopAsync();
        await node.StartAsync();
        await using var after = await node.ChannelAsync(helloAsHuman: true);
        Assert.Equal(TaskState.Paused, (await Tasks.GetAsync(after, backgroundId)).State);
        var watch = Stopwatch.StartNew();
        await Sched.UntilAsync(after, backgroundId, task => task.State == TaskState.Running, "the thaw after the restart", TimeSpan.FromSeconds(120));
        TestContext.Current.TestOutputHelper?.WriteLine($"thawed {watch.Elapsed.TotalSeconds:0.0} s after the restart");
        Assert.True(watch.Elapsed >= TimeSpan.FromSeconds(25), $"The thaw came {watch.Elapsed} after the restart, before 30 s at Normal.");
        await node.Runtime.Execution!.PlatformCalls.DrainAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(launchHigh, ArcForges.Tests.SystemdTestEnvironment.Property(unit, "MemoryHigh"));
        await Sched.CancelAsync(after, backgroundId);
    }

    /// <summary>
    /// 03 section 7: at Pressure (forced here through the policy's available-memory thresholds) only INTERACTIVE tasks start; on Linux a
    /// pausable BACKGROUND attempt is frozen with its MemoryHigh lowered and thaws after 30 s at Normal; on Windows a preemptible BACKGROUND
    /// attempt is requeued (PREEMPTED) and runs again once the level is Normal.
    /// </summary>
    private static async Task PressureAsync()
    {
        // The live machine (exclusive): the thresholds are crossed by the machine's available memory.
        await using var node = await InProcessNode.Create().WithLiveMachine().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var background = Sched.Hold(node, M(node, "background"), 240_000);
        background.Priority = Priority.Background;
        Id? unasserted = null;
        if (OperatingSystem.IsWindows())
        {
            // Requeued only if retryable (03 section 7): the asserted task is queued again, the unasserted one ends PREEMPTED.
            background.Resources.Preemptible = true;
            background.SideEffect = SideEffectClass.Idempotent;
            background.Retry = FastRetry.Clone();
            var plain = Sched.Hold(node, M(node, "unasserted"), 240_000);
            plain.Priority = Priority.Background;
            plain.Resources.Preemptible = true;
            unasserted = await Tasks.SubmitAsync(channel, plain);
            await Tasks.RunningAsync(channel, unasserted);
        }
        else
        {
            background.Resources.Pausable = true;
        }

        var backgroundId = await Tasks.SubmitAsync(channel, background);
        await Tasks.RunningAsync(channel, backgroundId);
        var execution = node.Runtime.Execution!;
        var forced = await Sched.ChangePolicyAsync(human, policy =>
        {
            policy.Resources.Pressure ??= new PressureThresholds();
            policy.Resources.Pressure.TightAvailableFraction = 0.995;
            policy.Resources.Pressure.PressureAvailableFraction = 0.99;
            policy.Resources.Pressure.CriticalAvailableFraction = 0.001;
        });
        Assert.True(forced.Error is null, $"UpdatePolicy: {forced.Error?.Code} {forced.Error?.Details}");
        await Tasks.WaitForAsync(() => execution.Resources?.Current?.Pressure == PressureLevel.Pressure, TimeSpan.FromSeconds(60), "the Pressure level");

        if (OperatingSystem.IsWindows())
        {
            var requeued = await Sched.UntilAsync(channel, backgroundId, task => task.State is TaskState.Queued or TaskState.RetryWait, "the requeue");
            Assert.Equal(TerminationReason.Preempted, requeued.CurrentAttempt.Result.TerminationReason);
            var ended = await Tasks.WaitAsync(channel, unasserted!);
            Assert.Equal(TerminationReason.Preempted, ended.CurrentAttempt.Result.TerminationReason);
            Assert.Equal(1u, ended.AttemptCount);
        }
        else
        {
            await Sched.UntilAsync(channel, backgroundId, task => task.State == TaskState.Paused, "the freeze");
        }

        var normal = await Tasks.SubmitAsync(channel, Sched.Hold(node, M(node, "normal"), 100));
        var interactive = Sched.Hold(node, M(node, "interactive"), 100);
        interactive.Priority = Priority.Interactive;
        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(human, await Tasks.SubmitAsync(human, interactive))).State);
        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, normal)).State);

        var restored = await Sched.ChangePolicyAsync(human, policy => policy.Resources.Pressure = new PressureThresholds
        {
            TightAvailableFraction = 0.10,
            PressureAvailableFraction = 0.05,
            CriticalAvailableFraction = 0.02,
        });
        Assert.True(restored.Error is null, $"UpdatePolicy: {restored.Error?.Code} {restored.Error?.Details}");
        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, normal, bound: TimeSpan.FromSeconds(90))).State);
        var watch = Stopwatch.StartNew();
        var back = await Sched.UntilAsync(channel, backgroundId, task => task.State == TaskState.Running, "the BACKGROUND task running again", TimeSpan.FromSeconds(120));
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal(2u, back.AttemptCount);
        }
        else
        {
            Assert.Equal(1u, back.AttemptCount);
            TestContext.Current.TestOutputHelper?.WriteLine($"thawed {watch.Elapsed.TotalSeconds:0.0} s after the normal task ran");
        }

        await Sched.CancelAsync(channel, backgroundId);
    }
}
