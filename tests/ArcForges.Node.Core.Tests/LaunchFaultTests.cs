// SPDX-License-Identifier: AGPL-3.0-only
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

    [Fact(Timeout = 180_000)]
    public async Task ACancelDuringTheLaunchStepsCancelsTheTaskAndTheCommandNeverRuns()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
        {
            Assert.SkipWhen(ArcForges.Tests.SystemdTestEnvironment.SkipReason is not null, ArcForges.Tests.SystemdTestEnvironment.SkipReason ?? string.Empty);
        }

        string? launchMarker = null;
        var steps = new Tasks.FixedSteps(_ => [Step("slow-launch", launchMarker!)], _ => []);
        await using var node = await InProcessNode.Create(steps: steps).StartAsync();
        launchMarker = Path.Combine(node.Root, "launch.txt");
        await using var channel = await node.ChannelAsync();
        var commandMarker = Path.Combine(node.Root, "command.txt");
        var id = await Tasks.SubmitAsync(channel, OperatingSystem.IsWindows()
            ? Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "60000", "--marker", commandMarker)
            : Tasks.Argv(node.Root, "/bin/sh", "-c", "echo ran > \"$1\"; exec sleep 60", "sh", commandMarker));

        // The launch step is running: the attempt is being launched, its command has not started.
        await Tasks.WaitForAsync(() => File.Exists(launchMarker), Tasks.Bound, "the launch step to run");
        var cancel = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "fault" }, cancellationToken: Ct);
        Assert.Null(cancel.Error);

        var task = await Tasks.WaitAsync(channel, id);
        TestContext.Current.TestOutputHelper?.WriteLine($"{task.State}: {task.CurrentAttempt.Result}");
        Assert.Equal(TaskState.Cancelled, task.State);
        Assert.Equal(TerminationReason.Cancelled, task.CurrentAttempt.Result.TerminationReason);
        Assert.False(File.Exists(commandMarker), "The command ran although its task was cancelled during the launch.");
    }

    /// <summary>A launch step that marks it started and then holds for 30 s (the attempt is being launched meanwhile).</summary>
    private static StepSpec Step(string name, string marker)
    {
        string[] argv = OperatingSystem.IsWindows()
            ? [Tasks.TestLoad, "signal", "--hold-ms", "30000", "--marker", marker]
            : ["/bin/sh", "-c", "echo started > \"$1\"; exec sleep 30", "sh", marker];
        return OperatingSystem.IsWindows()
            ? new StepSpec { Name = name, Application = argv[0], CommandLine = WindowsCommandLine.Build(argv), TimeoutMs = 60_000 }
            : new StepSpec { Name = name, Application = argv[0], Argv = [.. argv], TimeoutMs = 60_000 };
    }
}
