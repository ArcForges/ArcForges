// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform.Linux;
using ArcForges.Node.Platform.Windows;
using ArcForges.Node.Store;
using ArcForges.Tests;

namespace ArcForges.Node.Core.Tests;

public sealed partial class LaunchFaultTests
{
    /// <summary>MR-95: a root starting in the node gap, or after recovery, gets its real start clock and both polling limits back.</summary>
    [Theory(Timeout = 180_000)]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ARecoveredStartKeepsItsTimeoutAndCpuTimeLimit(bool cpu, bool startInGap)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        SkipWithoutPlatform();
        var hold = new LaunchHold();
        var node = InProcessNode.Create(steps: hold.Steps);
        await using var started = await node.StartAsync();
        await using var held = hold.Attach(node);
        var marker = Path.Combine(node.Root, "recovered-command.txt");
        var spec = cpu
            ? Tasks.Argv(node.Root, Tasks.TestLoad, "cpu", "--threads", "2", "--iterations", "20000000000")
            : Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "120000", "--marker", marker);
        spec.Resources ??= new();
        spec.Resources.CancelGraceMs = 0;
        if (cpu)
        {
            spec.CpuTimeLimitMs = 1_500;
        }
        else
        {
            spec.TimeoutMs = 2_000;
        }

        Id id;
        string attempt;
        var nodeName = ArcForges.Client.IdText.Format(node.Runtime.Store.Metadata.NodeId.Span);
        await using (var before = await node.ChannelAsync())
        {
            id = await Tasks.SubmitAsync(before, spec);
            attempt = await hold.HeldAsync();
            Assert.Equal(AttemptState.Starting, (await Tasks.GetAsync(before, id)).CurrentAttempt.State);
            Assert.Null(RecordedStart(node, id));
        }

        await node.StopAsync();
        if (startInGap)
        {
            hold.Release();
            await Tasks.WaitForAsync(() => CommandInContainer(nodeName, attempt), Tasks.Bound, "the command to start while the node is down");
            if (!cpu)
            {
                await Task.Delay(2_500, Ct); // The timeout is already spent before recovery, not a fresh budget afterwards.
            }
        }

        var recoveryAt = StoreTime.ToMicroseconds(DateTimeOffset.UtcNow);
        await node.StartAsync();
        await using var after = await node.ChannelAsync();
        try
        {
            if (!startInGap)
            {
                await Task.Delay(2_500, Ct);
                Assert.Equal(AttemptState.Starting, (await Tasks.GetAsync(after, id)).CurrentAttempt.State);
                Assert.Null(RecordedStart(node, id));
                hold.Release();
            }

            await Tasks.WaitForAsync(() => RecordedStart(node, id) is not null, TimeSpan.FromSeconds(15), "the recovered root's start to be persisted");
            var recorded = RecordedStart(node, id)!.Value;
            Assert.True(startInGap ? recorded < recoveryAt : recorded >= recoveryAt,
                $"Start {recorded}, recovery {recoveryAt}, startInGap={startInGap}: recovery must keep the real start time.");
            Assert.NotNull(RootPid(node, id));
            var task = await Tasks.WaitAsync(after, id);
            Assert.True(task.CurrentAttempt.NodeGap);
            Assert.Equal(TaskState.Failed, task.State);
            Assert.Equal(cpu ? TerminationReason.CpuTimeExceeded : TerminationReason.TimedOut, task.CurrentAttempt.Result.TerminationReason);
            Assert.Equal(EffectCertainty.Happened, task.CurrentAttempt.Result.Effect);
            if (cpu)
            {
                Assert.True(task.CurrentAttempt.Usage.CpuTimeMs >= 1_500);
            }
        }
        finally
        {
            hold.Release();
            _ = await after.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, GraceMs = 0 }, cancellationToken: Ct);
            _ = await Tasks.WaitAsync(after, id);
        }
    }

    /// <summary>A new process in a recovered job may be another launch step, never evidence that the command started.</summary>
    [Fact(Timeout = 180_000)]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task ANewLaunchStepAfterRecoveryDoesNotStartTheCommandClockOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The holder distinguishes launch steps from its command root.");
        InProcessNode? node = null;
        string Dir(string name) => Path.Combine(node!.Root, name);
        var steps = new Tasks.FixedSteps(_ => [WindowsHoldStep("one", Dir("one.txt"), Dir("go-one")), WindowsHoldStep("two", Dir("two.txt"), Dir("go-two"))], _ => []);
        node = InProcessNode.Create(steps: steps);
        await using var started = await node.StartAsync();
        try
        {
            Id id;
            await using (var before = await node.ChannelAsync())
            {
                var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "120000", "--marker", Dir("command.txt"));
                spec.TimeoutMs = 2_000;
                spec.Resources ??= new();
                spec.Resources.CancelGraceMs = 0;
                id = await Tasks.SubmitAsync(before, spec);
                await Tasks.WaitForAsync(() => Tasks.Marker(Dir("one.txt")).Any(line => line.Event == "start"), Tasks.Bound, "the first step to run");
            }

            await node.StopAsync();
            await node.StartAsync();
            await using var after = await node.ChannelAsync();
            await File.WriteAllTextAsync(Dir("go-one"), "go", Ct);
            await Tasks.WaitForAsync(() => Tasks.Marker(Dir("two.txt")).Any(line => line.Event == "start"), Tasks.Bound, "a new launch step to enter after recovery");
            await Task.Delay(2_500, Ct);
            Assert.Equal(AttemptState.Starting, (await Tasks.GetAsync(after, id)).CurrentAttempt.State);
            Assert.Null(RecordedStart(node, id));
            Assert.Null(RootPid(node, id));
            Assert.False(File.Exists(Dir("command.txt")));
            await File.WriteAllTextAsync(Dir("go-two"), "go", Ct);
            var task = await Tasks.WaitAsync(after, id);
            Assert.Equal(TerminationReason.TimedOut, task.CurrentAttempt.Result.TerminationReason);
            Assert.NotNull(RecordedStart(node, id));
            Assert.NotNull(RootPid(node, id));
        }
        finally
        {
            await File.WriteAllTextAsync(Dir("go-one"), "go", Ct);
            await File.WriteAllTextAsync(Dir("go-two"), "go", Ct);
        }
    }

    /// <summary>A failed evidence write cannot abandon a root that was already resumed; its live start is still supervised.</summary>
    [Fact(Timeout = 120_000)]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task ABlockedStartRecordStillReportsAndSupervisesTheLiveRootOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows holder evidence and Windows file sharing.");
        FileStream? blocked = null;
        string? evidence = null;
        var steps = new Tasks.FixedSteps(files =>
        {
            evidence = files.StartedPath;
            blocked = new FileStream(evidence + ".tmp", FileMode.Create, FileAccess.ReadWrite, FileShare.None);
            return [];
        }, _ => []);
        await using var node = await InProcessNode.Create(steps: steps).StartAsync();
        try
        {
            await using var channel = await node.ChannelAsync();
            var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "120000");
            spec.TimeoutMs = 1_000;
            spec.Resources ??= new();
            spec.Resources.CancelGraceMs = 0;
            var id = await Tasks.SubmitAsync(channel, spec);
            var task = await Tasks.WaitAsync(channel, id);
            Assert.Equal(TerminationReason.TimedOut, task.CurrentAttempt.Result.TerminationReason);
            Assert.NotNull(RecordedStart(node, id));
            Assert.NotNull(RootPid(node, id));
            Assert.False(File.Exists(evidence));
            Assert.Contains("execution.started.evidence_unavailable", NodeLog(node), StringComparison.Ordinal);
        }
        finally
        {
            blocked?.Dispose();
        }
    }

    private static long? RecordedStart(InProcessNode node, Id id) => node.Runtime.Store.Read(reader =>
        reader.Scalar("SELECT started_at FROM attempt WHERE task_id = $id;", ("$id", id.Value.ToByteArray())) as long?);

    private static bool CommandInContainer(string nodeName, string attempt)
    {
        var image = Path.GetFileNameWithoutExtension(Tasks.TestLoad);
        if (OperatingSystem.IsWindows())
        {
            using var job = JobObject.Open(WindowsExecutionPlatform.JobName(nodeName, attempt));
            if (job is not null)
            {
                foreach (var member in job.ProcessIds())
                {
                    if (string.Equals(Path.GetFileNameWithoutExtension(ProcessInfo.ImageName(member)), image, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        if (OperatingSystem.IsLinux() && int.TryParse(SystemdTestEnvironment.Property(SystemdTestEnvironment.AttemptUnit(attempt), "MainPID"), out var pid) && pid > 0)
        {
            return string.Equals(Path.GetFileNameWithoutExtension(ProcFs.Image(pid)), image, StringComparison.Ordinal);
        }

        return false;
    }
}
