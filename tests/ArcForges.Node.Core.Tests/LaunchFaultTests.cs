// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Interrupted operations with real processes (16-testing-strategy section 1, fault injection: cancellation during launch). A cancel that
/// arrives while an attempt's launch step runs (04 section 3: launch steps run in the attempt's job or unit before the command) cancels
/// the task (SM-TASK RUNNING -> CANCELLED), stops the step, and the command never starts; the fixture fails the test on any leftover.
/// The launch step is synthetic (fakes_allowed of the launch-step tasks: a provider returning fixed steps).
/// </summary>
public sealed class LaunchFaultTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>
    /// The stop terminates the attempt at once, so a step shorter than any wait for the start (3 s) never finishes and lets the command
    /// start after the cancel, and a long step (30 s) does not hold the cancel. The task ends CANCELLED well under the step's hold
    /// (generous safety bound: the forced stop waits for nothing, so it holds in the parallel suites), no root was ever recorded (Windows:
    /// the root is the command, started by the holder after the steps; on Linux the steps and the command share the unit's main process),
    /// and the effect is HAPPENED (04 section 7: DID_NOT_HAPPEN only for SPAWN_FAILED and POLICY_DENIED).
    /// </summary>
    [Theory(Timeout = 180_000)]
    [InlineData(3_000)]
    [InlineData(30_000)]
    public async Task ACancelDuringTheLaunchStepsCancelsTheTaskAndTheCommandNeverRuns(int stepHoldMs)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
        {
            Assert.SkipWhen(ArcForges.Tests.SystemdTestEnvironment.SkipReason is not null, ArcForges.Tests.SystemdTestEnvironment.SkipReason ?? string.Empty);
        }

        string? launchMarker = null;
        var steps = new Tasks.FixedSteps(_ => [Step("slow-launch", launchMarker!, stepHoldMs)], _ => []);
        await using var node = await InProcessNode.Create(steps: steps).StartAsync();
        launchMarker = Path.Combine(node.Root, "launch.txt");
        await using var channel = await node.ChannelAsync();
        var commandMarker = Path.Combine(node.Root, "command.txt");
        var id = await Tasks.SubmitAsync(channel, OperatingSystem.IsWindows()
            ? Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "60000", "--marker", commandMarker)
            : Tasks.Argv(node.Root, "/bin/sh", "-c", "echo ran > \"$1\"; exec sleep 60", "sh", commandMarker));

        // The launch step is running: the attempt is being launched, its command has not started.
        await Tasks.WaitForAsync(() => File.Exists(launchMarker), Tasks.Bound, "the launch step to run");
        var cancelled = System.Diagnostics.Stopwatch.StartNew();
        var cancel = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "fault" }, cancellationToken: Ct);
        Assert.Null(cancel.Error);

        var task = await Tasks.WaitAsync(channel, id);
        var toFinal = cancelled.Elapsed;
        TestContext.Current.TestOutputHelper?.WriteLine($"{task.State} after {toFinal.TotalMilliseconds:F0} ms: {task.CurrentAttempt.Result}");
        Assert.Equal(TaskState.Cancelled, task.State);
        Assert.Equal(TerminationReason.Cancelled, task.CurrentAttempt.Result.TerminationReason);
        Assert.Equal(EffectCertainty.Happened, task.CurrentAttempt.Result.Effect);
        Assert.True(toFinal < TimeSpan.FromSeconds(5), $"The cancel took {toFinal} to end the task (step hold {stepHoldMs} ms).");
        if (OperatingSystem.IsWindows())
        {
            var rootPid = node.Runtime.Store.Read(reader =>
            {
                using var command = reader.CreateCommand("SELECT root_pid FROM attempt WHERE task_id = $id;");
                command.Parameters.AddWithValue("$id", id.Value.ToByteArray());
                using var rows = command.ExecuteReader();
                Assert.True(rows.Read());
                return rows.IsDBNull(0) ? (long?)null : rows.GetInt64(0);
            });
            Assert.True(rootPid is null, $"The command started (root {rootPid}) although its task was cancelled during the launch.");
        }

        // Past the short step's hold, so a command started after the cancel would have written its marker (the long step was killed by
        // the termination; the fixture fails the test on any leftover, so waiting out its hold proves nothing more).
        await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(0, Math.Min(stepHoldMs + 1_000, 5_000) - cancelled.Elapsed.TotalMilliseconds)), Ct);
        Assert.False(File.Exists(commandMarker), "The command ran although its task was cancelled during the launch.");
    }

    /// <summary>
    /// Cancels racing the admission and the launch (16 section 1: cancellation during launch): tasks cancelled as soon as they are
    /// submitted, many at once, all end CANCELLED, whether the cancel found them queued, admitted but not yet supervised, being launched,
    /// or started; none runs on to its own end (a lost cancel left a task RUNNING for its whole 120 s hold).
    /// </summary>
    [Fact(Timeout = 300_000)]
    public async Task TasksCancelledAsSoonAsSubmittedAllEndCancelled()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
        {
            Assert.SkipWhen(ArcForges.Tests.SystemdTestEnvironment.SkipReason is not null, ArcForges.Tests.SystemdTestEnvironment.SkipReason ?? string.Empty);
        }

        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var tasks = await Task.WhenAll(Enumerable.Range(0, 24).Select(async index =>
        {
            var id = await Tasks.SubmitAsync(channel, OperatingSystem.IsWindows()
                ? Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "120000", "--marker", Path.Combine(node.Root, $"m{index}.txt"))
                : Tasks.Argv(node.Root, "/bin/sleep", "120"));
            Assert.Null((await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "fault" }, cancellationToken: Ct)).Error);
            return await Tasks.WaitAsync(channel, id, bound: TimeSpan.FromSeconds(60));
        }));

        Assert.All(tasks, task => Assert.True(task.State == TaskState.Cancelled, $"{task.State}: {task.CurrentAttempt?.Result}"));
    }

    /// <summary>A launch step that marks it started and then holds (the attempt is being launched meanwhile).</summary>
    private static StepSpec Step(string name, string marker, int holdMs)
    {
        string[] argv = OperatingSystem.IsWindows()
            ? [Tasks.TestLoad, "signal", "--hold-ms", holdMs.ToString(System.Globalization.CultureInfo.InvariantCulture), "--marker", marker]
            : ["/bin/sh", "-c", "echo started > \"$1\"; exec sleep \"$2\"", "sh", marker, (holdMs / 1000.0).ToString(System.Globalization.CultureInfo.InvariantCulture)];
        return OperatingSystem.IsWindows()
            ? new StepSpec { Name = name, Application = argv[0], CommandLine = WindowsCommandLine.Build(argv), TimeoutMs = 60_000 }
            : new StepSpec { Name = name, Application = argv[0], Argv = [.. argv], TimeoutMs = 60_000 };
    }
}
