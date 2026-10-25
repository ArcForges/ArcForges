// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;
using ArcForges.Tests;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Interrupted operations with real processes (16-testing-strategy section 1, fault injection: cancellation during launch). A cancel that
/// arrives while an attempt's launch step runs (04 section 3: launch steps run in the attempt's job or unit before the command) cancels
/// the task (SM-TASK RUNNING -> CANCELLED), stops the step, and the command never starts; the fixture fails the test on any leftover.
/// The launch step is synthetic (fakes_allowed of the launch-step tasks: a provider returning fixed steps).
/// </summary>
public sealed partial class LaunchFaultTests
{
    /// <summary>
    /// When the command (<c>hold --ready-after-ms</c>) marks itself ready: the failure-path bound (<see cref="Tasks.Bound"/>), so a command that
    /// marks itself ready ran on for the whole bound past its start. Nothing in a passing run waits for it.
    /// </summary>
    private const int ReadyAfterMs = 60_000;

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
    /// MR-101: the forced stop of an attempt in its launch steps does not wait for the stopped step to run down. The termination empties the
    /// step's job at once (the job reports no process and the step its termination code), but the step's process handle is signaled only once
    /// its own threads have run down, at the job's below-normal priority: under CPU load in the parallel suites that took seconds (up to 12 s),
    /// and the holder, which waited for that handle, wrote the stop's records only then, so the cancel above exceeded its bound. Here the step's
    /// run-down is held without load or timing: a debugger attached to the step holds its exit (<see cref="ExitHold"/>), so the step cannot run
    /// down before the test releases it, after the task ended. The task ends CANCELLED within the same bound before the step ran down, the
    /// termination did reach the step (its exit came once released), and the command never starts.
    /// </summary>
    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    [SupportedOSPlatform("windows")]
    public async Task ACancelDuringALaunchStepDoesNotWaitForTheStoppedStepToRunDownOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "A terminated Windows job's processes run down after it reports them gone; on Linux the steps and the command are the unit's main process.");
        string? launchMarker = null;
        var steps = new Tasks.FixedSteps(_ => [Step("slow-launch", launchMarker!, 60_000)], _ => []);
        await using var node = await InProcessNode.Create(steps: steps).StartAsync();
        launchMarker = Path.Combine(node.Root, "launch.txt");
        await using var channel = await node.ChannelAsync();
        var commandMarker = Path.Combine(node.Root, "command.txt");
        var id = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "60000", "--marker", commandMarker));

        // The launch step runs; from now on it cannot run down until released (a failure-path bound of 30 s after its exit releases it, so an
        // attempt that waits for the step's run-down ends only then).
        await Tasks.WaitForAsync(() => Tasks.Marker(launchMarker).Any(line => line.Event == "ready"), Tasks.Bound, "the launch step to run");
        using var hold = ExitHold.Attach(Tasks.Marker(launchMarker).First(line => line.Event == "ready").Pid, TimeSpan.FromSeconds(30));
        var cancelled = Stopwatch.StartNew();
        var cancel = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "fault" }, cancellationToken: Ct);
        Assert.Null(cancel.Error);

        var task = await Tasks.WaitAsync(channel, id);
        var toFinal = cancelled.Elapsed;
        var ranDown = hold.RanDown;
        hold.Release();
        TestContext.Current.TestOutputHelper?.WriteLine($"{task.State} after {toFinal.TotalMilliseconds:F0} ms, step ran down by then: {ranDown}: {task.CurrentAttempt.Result}");
        AssertCancelled(task);
        Assert.Equal("stopped during launch step slow-launch; the command did not start", task.CurrentAttempt.Result.Detail);
        Assert.False(ranDown, $"The task ended only after the stopped step had run down ({toFinal}): the stop waited for the step's run-down.");
        Assert.True(toFinal < TimeSpan.FromSeconds(5), $"The cancel took {toFinal} to end the task while the step's run-down was held.");

        // The step's exit comes from its own last thread, which load may starve: it is awaited (bounded), not assumed to have come already.
        Assert.True(await Task.WhenAny(hold.Exit, Task.Delay(Tasks.Bound, Ct)) == hold.Exit,
            $"The termination never reached the launch step: its exit did not come within {Tasks.Bound.TotalSeconds:0} s.");
        Assert.Null(RootPid(node, id));
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

    /// <summary>
    /// MR-84: a cancel that finds the attempt still launching terminates its container at once, and terminates it again once the start
    /// completes with a root, however the start interleaves with the termination. Here the start completes exactly between the termination
    /// and the supervisor's look at the start (the seam <c>ForcedBeforeStart</c> holds the forced phase there until the start completed),
    /// the interleaving in which the command ran on past the cancel and the attempt ended TERMINATION_INCOMPLETE (the task FAILED). The
    /// command cannot enter its container before the termination, whatever the timing (<see cref="LaunchHold"/>). The task ends CANCELLED
    /// and the command does not run on.
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task AStartCompletingBetweenTheForcedPhaseAndItsCheckIsTerminatedAgain()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        SkipWithoutPlatform();
        var hold = new LaunchHold();
        var seam = new StartSeam(hold);
        var node = InProcessNode.Create(steps: hold.Steps);
        node.ForcedBeforeStart = seam.Invoke;
        await using var started = await node.StartAsync();
        await using var held = hold.Attach(node);
        await using var channel = await node.ChannelAsync();
        var commandMarker = Path.Combine(node.Root, "command.txt");
        var id = await Tasks.SubmitAsync(channel, Command(node.Root, commandMarker));

        // The attempt is being launched, its command held back outside its container.
        await hold.HeldAsync();
        var cancel = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "fault" }, cancellationToken: Ct);
        Assert.Null(cancel.Error);

        var task = await Tasks.WaitAsync(channel, id);
        AssertCancelled(task);
        seam.AssertStartedInBetween(task);
        AssertNeverRanPastTheStop(commandMarker);
    }

    /// <summary>
    /// MR-02: a node restart in the middle of the launch of an attempt that is STOPPING (cancelled while its command was held back, then
    /// the node stopped). The restarted node continues the stop with the forced phase at once, and terminates the attempt again once the
    /// launch it no longer controls starts the command: the hold is released exactly after that termination (the seam), so the restarted
    /// node must see the start itself (Windows: a process entering the re-opened job, whose holder's reports went to the stopped node;
    /// Linux: the unit's queued start job completing). The task ends CANCELLED, never TERMINATION_INCOMPLETE, and the command does not run
    /// on.
    /// </summary>
    [Fact(Timeout = 240_000)]
    public async Task ARestartInTheMiddleOfTheLaunchOfAStoppingAttemptCancelsItAndTheCommandNeverRuns()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        SkipWithoutPlatform();
        var hold = new LaunchHold();
        var node = InProcessNode.Create(steps: hold.Steps);
        await using var started = await node.StartAsync();
        await using var held = hold.Attach(node);
        var commandMarker = Path.Combine(node.Root, "command.txt");
        Id id;
        await using (var channel = await node.ChannelAsync())
        {
            id = await Tasks.SubmitAsync(channel, Command(node.Root, commandMarker));
            await hold.HeldAsync();
            var cancel = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "fault" }, cancellationToken: Ct);
            Assert.Null(cancel.Error);

            // STOPPING is recorded; the command is still held back, so the stop cannot end before the node stops.
            Assert.Equal(AttemptState.Stopping, (await Tasks.GetAsync(channel, id)).CurrentAttempt.State);
        }

        await node.StopAsync();
        var seam = new StartSeam(hold);
        node.ForcedBeforeStart = seam.Invoke;
        await node.StartAsync();
        await using var after = await node.ChannelAsync();
        var task = await Tasks.WaitAsync(after, id);
        AssertCancelled(task);
        Assert.True(task.CurrentAttempt.NodeGap, "The attempt was recovered after the restart.");
        seam.AssertStartedInBetween(task);
        AssertNeverRanPastTheStop(commandMarker);
    }

    /// <summary>
    /// MR-89: a node restart in the middle of the launch of an attempt that is STARTING (its command held back, nothing cancelled yet), then a
    /// cancel after the restart. The restarted node re-opened the attempt as one it was not stopping, so its start completed at once without a
    /// root; the cancel's forced phase finds the container empty, and the launch the node no longer controls starts the command after it: the
    /// hold is released once the cancel answered, and the cancel stops the attempt before it answers. The restarted node must see that late
    /// start itself (Windows: a process entering the re-opened job; Linux: the unit's queued start job, read at the forced phase, completing)
    /// and terminate it. The task ends CANCELLED, never TERMINATION_INCOMPLETE, the late start was reported, and the command does not run on.
    /// </summary>
    [Fact(Timeout = 240_000)]
    public async Task ACancelAfterARestartInTheMiddleOfTheLaunchOfAStartingAttemptEndsTheCommandThatStartsLate()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        SkipWithoutPlatform();
        var hold = new LaunchHold();
        var node = InProcessNode.Create(steps: hold.Steps);
        await using var started = await node.StartAsync();
        await using var held = hold.Attach(node);
        var commandMarker = Path.Combine(node.Root, "command.txt");
        Id id;
        string attempt;
        await using (var channel = await node.ChannelAsync())
        {
            id = await Tasks.SubmitAsync(channel, Command(node.Root, commandMarker));
            attempt = await hold.HeldAsync();

            // Nothing cancelled it: the attempt is STARTING when the node stops, its command still held back.
            Assert.Equal(AttemptState.Starting, (await Tasks.GetAsync(channel, id)).CurrentAttempt.State);
        }

        await node.StopAsync();
        var pendingCalls = 0;
        node.ForcedBeforeStart = _ => Interlocked.Increment(ref pendingCalls);
        await node.StartAsync();
        await using var after = await node.ChannelAsync();
        Assert.Equal(AttemptState.Starting, (await Tasks.GetAsync(after, id)).CurrentAttempt.State);
        var handle = node.Runtime.Execution?.Running(attempt)?.Handle;
        Assert.True(handle is not null, "The restarted node did not re-open the attempt's container.");
        var entered = new ConcurrentQueue<int>();
        handle!.LaunchProcessEntered += entered.Enqueue;

        var cancel = await after.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "fault" }, cancellationToken: Ct);
        Assert.Null(cancel.Error);

        // The forced phase ran before the cancel answered: the command starts after it.
        hold.Release();
        var task = await Tasks.WaitAsync(after, id);
        AssertCancelled(task);
        Assert.True(task.CurrentAttempt.NodeGap, "The attempt was recovered after the restart.");
        Assert.True(!entered.IsEmpty,
            $"The restarted node did not see the command start after the forced phase ({LaunchEnded(handle)}; attempt result {task.CurrentAttempt?.Result}).");
        Assert.Equal(0, Volatile.Read(ref pendingCalls));
        AssertNeverRanPastTheStop(commandMarker);
        if (!OperatingSystem.IsWindows())
        {
            // The late start's root (the unit's main process, which becomes the command) is recorded with the attempt. On Windows the first
            // process that enters a re-opened job may be a launch step, so none is recorded there.
            Assert.True(RootPid(node, id) is not null, "The late start's root was not recorded with the attempt.");
        }
    }

    /// <summary>
    /// Review round 1, finding 1: the start completes only after the verification window of the forced phase that found it pending. The hold
    /// is released 6 s after that termination (a lower bound past the 5 s window, never a race with it), and the node sees the late start in
    /// the container before it sees the start complete: the seam <c>StartObserved</c> holds the start's continuation until the task ended.
    /// The verification terminates the late start (the termination owed to it) instead of recording TERMINATION_INCOMPLETE: the task ends
    /// CANCELLED, the command does not run on, and the node logs the late start.
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task AStartCompletingAfterTheVerificationWindowIsTerminatedNotLeftOver()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        SkipWithoutPlatform();
        var hold = new LaunchHold();
        var ended = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var released = new TaskCompletionSource<TimeSpan>(TaskCreationOptions.RunContinuationsAsynchronously);
        var forcedCalls = 0;
        var node = InProcessNode.Create(steps: hold.Steps);
        node.ForcedBeforeStart = handle =>
        {
            if (Interlocked.Increment(ref forcedCalls) == 1)
            {
                var forced = Stopwatch.StartNew();
                _ = Task.Run(async () =>
                {
                    await Task.Delay(ArcForges.Node.Core.Execution.ExecutionSupervisor.VerifyWindow + TimeSpan.FromSeconds(1));
                    hold.Release();
                    released.TrySetResult(forced.Elapsed);
                });
            }
        };
        node.StartObserved = (handle, terminated) =>
        {
            if (!terminated)
            {
                // The verification sees the late start first.
                ended.Task.Wait(Tasks.Bound);
            }
        };
        await using var started = await node.StartAsync();
        await using var held = hold.Attach(node);
        try
        {
            await using var channel = await node.ChannelAsync();
            var commandMarker = Path.Combine(node.Root, "command.txt");
            var id = await Tasks.SubmitAsync(channel, Command(node.Root, commandMarker));
            await hold.HeldAsync();
            var cancel = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "fault" }, cancellationToken: Ct);
            Assert.Null(cancel.Error);

            var task = await Tasks.WaitAsync(channel, id);
            ended.TrySetResult();
            AssertCancelled(task);
            Assert.Equal(1, Volatile.Read(ref forcedCalls));
            var releasedAfter = await released.Task.WaitAsync(Tasks.Bound, Ct);
            Assert.True(releasedAfter > ArcForges.Node.Core.Execution.ExecutionSupervisor.VerifyWindow,
                $"The hold was released {releasedAfter.TotalMilliseconds:F0} ms after the forced phase, within its verification window.");
            AssertNeverRanPastTheStop(commandMarker);
            await Tasks.WaitForAsync(() => NodeLog(node).Contains("execution.stop.late_start", StringComparison.Ordinal), Tasks.Bound,
                "the node to log the late start it terminated");
        }
        finally
        {
            ended.TrySetResult();
        }
    }

    /// <summary>
    /// Review round 1, finding 2 (Windows): a STOPPING attempt recovered in the middle of its launch, whose first late process (a launch step)
    /// completes the start and ends before the termination that follows it; the holder then starts the command after that termination. The
    /// re-opened job reports every process the launch starts, and each is terminated: the task ends CANCELLED and the command does not run on.
    /// The order is fixed without timing: the holder is suspended while the first step ends, the attempt is cancelled and the node restarted;
    /// the restarted node's forced phase resumes the holder, the start's continuation is held (the seam <c>StartObserved</c>) until the second
    /// step ended with the holder suspended again, and the holder resumes only after that continuation's termination. The job holds no process
    /// when the attempt is cancelled (<see cref="WaitForEmptyJobAsync"/>), so the holder can start the second step after the restarted node's
    /// termination. The second step's own report (each process that enters is terminated) may end it before the seam suspends the holder;
    /// the order under test still holds, and the seam tolerates a holder that ended meanwhile.
    /// </summary>
    [Fact(Timeout = 240_000)]
    [Trait("env", "windows-real")]
    [SupportedOSPlatform("windows")]
    public async Task EveryProcessTheLaunchOfARecoveredStoppingAttemptStartsIsTerminatedOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "A re-opened Windows job; on Linux the late start is the unit's queued start job.");
        var attempt = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        InProcessNode? node = null;
        string Dir(string name) => Path.Combine(node!.Root, name);
        var steps = new Tasks.FixedSteps(files =>
        {
            attempt.TrySetResult(files.AttemptName);
            return [WindowsHoldStep("first", Dir("step1.txt"), Dir("go1")), WindowsHoldStep("second", Dir("step2.txt"), Dir("go2"))];
        }, _ => []);
        node = InProcessNode.Create(steps: steps);
        await using var started = await node.StartAsync();
        var commandMarker = Dir("command.txt");
        var gate = new Lock();
        int? holder = null;
        var suspended = false;
        void Suspend()
        {
            lock (gate)
            {
                if (!suspended)
                {
                    Suspension.Suspend(holder!.Value);
                    suspended = true;
                }
            }
        }

        void Resume()
        {
            lock (gate)
            {
                if (suspended)
                {
                    Suspension.Resume(holder!.Value);
                    suspended = false;
                }
            }
        }

        try
        {
            Id id;
            await using (var channel = await node.ChannelAsync())
            {
                id = await Tasks.SubmitAsync(channel, Command(node.Root, commandMarker));
                var name = await attempt.Task.WaitAsync(Tasks.Bound, Ct);
                await Tasks.WaitForAsync(() => Tasks.Marker(Dir("step1.txt")).Any(line => line.Event == "start"), Tasks.Bound, "the first launch step to run");
                holder = ExecutionCleanup.Holders([name]).Single();
                Suspend();
                await File.WriteAllTextAsync(Dir("go1"), "go", Ct);
                var first = Tasks.Processes(Dir("step1.txt")).Single();
                await Tasks.WaitForAsync(() => !first.IsRunning(), Tasks.Bound, "the first launch step to end");
                await WaitForEmptyJobAsync(node, name);
                var cancel = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "fault" }, cancellationToken: Ct);
                Assert.Null(cancel.Error);
                Assert.Equal(AttemptState.Stopping, (await Tasks.GetAsync(channel, id)).CurrentAttempt.State);
            }

            await node.StopAsync();
            var forcedCalls = 0;
            var observed = 0;
            IAttemptHandle? forced = null;
            node.ForcedBeforeStart = handle =>
            {
                if (Interlocked.Increment(ref forcedCalls) == 1)
                {
                    forced = handle;
                    // The holder goes on: it starts the second launch step, whose entry completes the restarted node's start.
                    Resume();
                }
            };
            node.StartObserved = (handle, terminated) =>
            {
                try
                {
                    if (!terminated && Interlocked.Increment(ref observed) == 1)
                    {
                        // The second step ends with the holder suspended, before the continuation's termination, which then finds the job
                        // empty.
                        Suspend();
                        File.WriteAllText(Dir("go2"), "go");
                        var watch = Stopwatch.StartNew();
                        while (handle.Accounting().ActiveProcesses > 0 && watch.Elapsed < Tasks.Bound)
                        {
                            Thread.Sleep(20);
                        }
                    }
                    else if (terminated && Volatile.Read(ref observed) == 1)
                    {
                        // After that termination the holder goes on: it starts the command (or records the step it found terminated).
                        Resume();
                    }
                }
                catch (Exception exception) when (exception is Win32Exception or ObjectDisposedException)
                {
                    // The second step's own termination ended the launch first: the holder exited (or the handle was released) meanwhile.
                }
            };
            await node.StartAsync();
            await using var after = await node.ChannelAsync();
            var task = await Tasks.WaitAsync(after, id);
            AssertCancelled(task);
            Assert.True(task.CurrentAttempt.NodeGap, "The attempt was recovered after the restart.");
            Assert.Equal(1, Volatile.Read(ref forcedCalls));
            Assert.True(Volatile.Read(ref observed) == 1,
                $"The restarted node's start never completed with a root ({LaunchEnded(forced)}; attempt result {task.CurrentAttempt?.Result}).");
            AssertNeverRanPastTheStop(commandMarker);
        }
        finally
        {
            if (holder is not null)
            {
                Resume();
            }
        }
    }

    /// <summary>
    /// Review round 2, item A (Windows): a STOPPING attempt recovered in the middle of its launch whose start completed before the restarted
    /// node's forced phase: a launch step entered the re-opened job (completing the start) and ended before that phase, so the phase finds the
    /// start complete and the job empty, and owes nothing. The holder's next process (the command) enters after the termination; it is
    /// reported and terminated all the same: the task ends CANCELLED and the command does not run on. The order is fixed without timing: the
    /// holder is suspended while the first step ends, the attempt is cancelled and the node restarted; the restarted node's forced phase (the
    /// seam <c>ForcedPhase</c>, before it reads the start) resumes the holder until the second step entered and completed the start, suspends
    /// it again until that step ended and the job is empty, and resumes it only after the termination, so the command enters after it.
    /// </summary>
    [Fact(Timeout = 240_000)]
    [Trait("env", "windows-real")]
    [SupportedOSPlatform("windows")]
    public async Task AProcessEnteringAfterTheRecoveredForcedPhaseIsTerminatedWhenTheStartCompletedBeforeItOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(),
            "A re-opened Windows job; on Linux the launch steps and the command run in the unit, which the forced phase ends.");
        var attempt = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        InProcessNode? node = null;
        string Dir(string name) => Path.Combine(node!.Root, name);
        var steps = new Tasks.FixedSteps(files =>
        {
            attempt.TrySetResult(files.AttemptName);
            return [WindowsHoldStep("first", Dir("step1.txt"), Dir("go1")), WindowsHoldStep("second", Dir("step2.txt"), Dir("go2"))];
        }, _ => []);
        node = InProcessNode.Create(steps: steps);
        await using var started = await node.StartAsync();
        var commandMarker = Dir("command.txt");
        var gate = new Lock();
        int? holder = null;
        var suspended = false;
        void Suspend()
        {
            lock (gate)
            {
                if (!suspended)
                {
                    Suspension.Suspend(holder!.Value);
                    suspended = true;
                }
            }
        }

        void Resume()
        {
            lock (gate)
            {
                if (suspended)
                {
                    Suspension.Resume(holder!.Value);
                    suspended = false;
                }
            }
        }

        try
        {
            Id id;
            await using (var channel = await node.ChannelAsync())
            {
                id = await Tasks.SubmitAsync(channel, Command(node.Root, commandMarker));
                var name = await attempt.Task.WaitAsync(Tasks.Bound, Ct);
                await Tasks.WaitForAsync(() => Tasks.Marker(Dir("step1.txt")).Any(line => line.Event == "start"), Tasks.Bound, "the first launch step to run");
                holder = ExecutionCleanup.Holders([name]).Single();
                Suspend();
                await File.WriteAllTextAsync(Dir("go1"), "go", Ct);
                var first = Tasks.Processes(Dir("step1.txt")).Single();
                await Tasks.WaitForAsync(() => !first.IsRunning(), Tasks.Bound, "the first launch step to end");
                await WaitForEmptyJobAsync(node, name);
                var cancel = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "fault" }, cancellationToken: Ct);
                Assert.Null(cancel.Error);
                Assert.Equal(AttemptState.Stopping, (await Tasks.GetAsync(channel, id)).CurrentAttempt.State);
            }

            await node.StopAsync();
            var phases = 0;
            var pendingCalls = 0;
            RootProcess? startedBefore = null;
            var emptyBefore = false;
            node.ForcedBeforeStart = _ => Interlocked.Increment(ref pendingCalls);
            node.ForcedPhase = (handle, terminated) =>
            {
                if (!terminated && Interlocked.Increment(ref phases) == 1)
                {
                    // The second step enters the re-opened job and completes the start; it then ends with the holder suspended.
                    Resume();
                    startedBefore = handle.Started.Wait(Tasks.Bound) ? handle.Started.Result : null;
                    Suspend();
                    File.WriteAllText(Dir("go2"), "go");
                    var watch = Stopwatch.StartNew();
                    while (handle.Accounting().ActiveProcesses > 0 && watch.Elapsed < Tasks.Bound)
                    {
                        Thread.Sleep(20);
                    }

                    emptyBefore = handle.Accounting().ActiveProcesses == 0;
                }
                else if (terminated && Volatile.Read(ref phases) == 1)
                {
                    // After the termination the holder goes on: it starts the command, which enters the job after the forced phase.
                    Resume();
                }
            };
            await node.StartAsync();
            await using var after = await node.ChannelAsync();
            var task = await Tasks.WaitAsync(after, id);
            AssertCancelled(task);
            Assert.True(task.CurrentAttempt.NodeGap, "The attempt was recovered after the restart.");
            Assert.Equal(1, Volatile.Read(ref phases));
            Assert.True(startedBefore is not null, "The second launch step did not complete the restarted node's start before its forced phase.");
            Assert.True(emptyBefore, "The second launch step had not ended when the forced phase terminated the job.");
            Assert.Equal(0, Volatile.Read(ref pendingCalls));
            AssertNeverRanPastTheStop(commandMarker);
        }
        finally
        {
            if (holder is not null)
            {
                Resume();
            }
        }
    }

    private static void SkipWithoutPlatform()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        }
    }

    /// <summary>The command: marks its start, marks itself ready after <see cref="ReadyAfterMs"/>, then holds.</summary>
    private static TaskSpec Command(string directory, string marker) => Tasks.Argv(directory, Tasks.TestLoad, "hold", "--hold-ms", "60000",
        "--ready-after-ms", ReadyAfterMs.ToString(System.Globalization.CultureInfo.InvariantCulture), "--marker", marker);

    /// <summary>CANCELLED with the cancel's reason; effect HAPPENED (04 section 7: DID_NOT_HAPPEN only for SPAWN_FAILED and POLICY_DENIED).</summary>
    private static void AssertCancelled(ManagedTask task)
    {
        Assert.True(task.State == TaskState.Cancelled, $"{task.State}: {task.CurrentAttempt?.Result}");
        var result = Assert.IsType<Attempt>(task.CurrentAttempt).Result;
        Assert.Equal(TerminationReason.Cancelled, result.TerminationReason);
        Assert.Equal(EffectCertainty.Happened, result.Effect);
    }

    /// <summary>
    /// The command never ran on past the stop: every process it started is gone once its task ended (so it marks nothing later), and none
    /// marked itself ready (<see cref="ReadyAfterMs"/>, the failure-path bound). There is no success-path time bound: the task ending CANCELLED,
    /// not TERMINATION_INCOMPLETE, is what shows that the stop ended the command within its verification window.
    /// </summary>
    private static void AssertNeverRanPastTheStop(string marker)
    {
        foreach (var process in Tasks.Processes(marker))
        {
            Assert.False(process.IsRunning(), $"The command {process} still runs after its task ended.");
        }

        Assert.DoesNotContain(Tasks.Marker(marker), line => line.Event == "ready");
    }

    /// <summary>A Windows launch step that marks its start and holds until <paramref name="untilFile"/> exists, then exits 0.</summary>
    [SupportedOSPlatform("windows")]
    private static StepSpec WindowsHoldStep(string name, string marker, string untilFile)
    {
        string[] argv = [Tasks.TestLoad, "hold", "--until-file", untilFile, "--hold-ms", "120000", "--marker", marker];
        return new StepSpec { Name = name, Application = argv[0], CommandLine = WindowsCommandLine.Build(argv), TimeoutMs = 120_000 };
    }

    /// <summary>
    /// Waits until the attempt's job holds no process. A launch step's console host may outlive the step, and a termination that still finds a
    /// process makes the job refuse new processes until they are gone (observed on the workstation: AssignProcessToJobObject right after
    /// TerminateJobObject failed with ERROR_ACCESS_DENIED 200 times of 200, and succeeded 50 of 50 after an empty job's termination), so the
    /// holder's later start would fail instead of coming late.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static async Task WaitForEmptyJobAsync(InProcessNode node, string attempt)
    {
        using var job = JobObject.Open(WindowsExecutionPlatform.JobName(ArcForges.Client.IdText.Format(node.Runtime.Store.Metadata.NodeId.Span), attempt));
        var emptied = Stopwatch.StartNew();
        while (job is not null && job.Accounting().ActiveProcesses > 0)
        {
            Assert.True(emptied.Elapsed < Tasks.Bound, $"Timed out after {Tasks.Bound.TotalSeconds:0} s waiting for the attempt's job to hold no process.");
            await Task.Delay(25, Ct);
        }
    }

    /// <summary>What ended a launch without a command (diagnostics of a failure; never throws).</summary>
    private static string LaunchEnded(IAttemptHandle? handle)
    {
        try
        {
            return $"launch record: {handle?.TryReadLaunchFailure()?.ToJson() ?? "none"}; exit record: {handle?.TryReadExit()?.ToJson() ?? "none"}";
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException or UnauthorizedAccessException)
        {
            return "records unreadable: " + exception.Message;
        }
    }

    /// <summary>The recorded root process ID of the task's attempt, or null.</summary>
    private static long? RootPid(InProcessNode node, Id id) => node.Runtime.Store.Read(reader =>
    {
        using var command = reader.CreateCommand("SELECT root_pid FROM attempt WHERE task_id = $id;");
        command.Parameters.AddWithValue("$id", id.Value.ToByteArray());
        using var rows = command.ExecuteReader();
        Assert.True(rows.Read());
        return rows.IsDBNull(0) ? (long?)null : rows.GetInt64(0);
    });

    /// <summary>The node's log so far (<c>logs/node/node.log</c> under its data root).</summary>
    private static string NodeLog(InProcessNode node)
    {
        var path = Path.Combine(node.DataRoot, "logs", "node", "node.log");
        if (!File.Exists(path))
        {
            return string.Empty;
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return new StreamReader(stream).ReadToEnd();
    }

    /// <summary>
    /// The forced-phase seam: on its first call it releases the hold and waits (bounded) until the start completed, all inside the forced
    /// phase, between the termination and the supervisor's look at the start.
    /// </summary>
    private sealed class StartSeam(LaunchHold hold)
    {
        private int _calls;
        private bool _pendingAtCall;
        private RootProcess? _started;
        private string? _launchEnded;

        public void Invoke(IAttemptHandle handle)
        {
            if (Interlocked.Increment(ref _calls) != 1)
            {
                return;
            }

            _pendingAtCall = !handle.Started.IsCompleted;
            hold.Release();
            _started = handle.Started.Wait(Tasks.Bound) ? handle.Started.Result : null;
            if (_started is null)
            {
                // What ended the launch without a command, for the failure message.
                _launchEnded = $"launch record: {handle.TryReadLaunchFailure()?.ToJson() ?? "none"}; exit record: {handle.TryReadExit()?.ToJson() ?? "none"}; "
                    + hold.Describe();
            }
        }

        /// <summary>The forced phase ran once while the start was pending, and the start completed with a root while it was held.</summary>
        public void AssertStartedInBetween(ManagedTask task)
        {
            Assert.Equal(1, Volatile.Read(ref _calls));
            Assert.True(_pendingAtCall, "The start had completed before the forced phase's termination.");
            Assert.True(_started is not null,
                $"The start did not complete with a root while the forced phase was held ({_launchEnded}; attempt result {task.CurrentAttempt?.Result}).");
        }
    }

    /// <summary>
    /// Holds an attempt's command back from its container until the test releases it, from outside the container (the forced phase cannot
    /// end the hold) and without waiting on any timing:
    /// <list type="bullet">
    /// <item>Windows: the attempt's launch step (<c>hold --until-file</c>) runs; its holder, which runs outside the job, is suspended; the
    /// step is released and exits 0, so the job holds nothing and the holder starts the command only once it is resumed.</item>
    /// <item>Linux: a gate unit in the node's slice, whose start waits for a file, is ordered before the attempt's unit (<c>Before=</c>, the
    /// mirror of the unit's <c>After=</c>), so the unit's start job waits (nothing forked, no cgroup) until the gate ends.</item>
    /// </list>
    /// </summary>
    private sealed class LaunchHold : IAsyncDisposable
    {
        private readonly TaskCompletionSource<string> _attempt = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private InProcessNode? _node;
        private int? _holder;
        private int? _stepExitCode;
        private int _released;
        private string? _gate;

        public ArcForges.Node.Core.Execution.ILaunchStepProvider Steps => new Tasks.FixedSteps(Launch, _ => []);

        private string Directory => _node?.Root ?? throw new InvalidOperationException("The hold is not attached to its node.");

        private string StepMarker => Path.Combine(Directory, "step.txt");

        private string StepGo => Path.Combine(Directory, "step-go");

        private string GateGo => Path.Combine(Directory, "gate-go");

        /// <summary>Binds the hold to its started node.</summary>
        public LaunchHold Attach(InProcessNode node)
        {
            _node = node;
            return this;
        }

        /// <summary>Waits until the attempt is being launched and its command is held back; returns the attempt's name.</summary>
        public async Task<string> HeldAsync()
        {
            var attempt = await _attempt.Task.WaitAsync(Tasks.Bound, Ct);
            if (OperatingSystem.IsWindows())
            {
                await Tasks.WaitForAsync(() => Tasks.Marker(StepMarker).Any(line => line.Event == "start"), Tasks.Bound, "the launch step to run");
                _holder = ExecutionCleanup.Holders([attempt]).Single();
                Suspension.Suspend(_holder.Value);

                // A handle on the step before it is released, so its exit code can be read afterwards (diagnostics; never fails the test).
                using var stepHandle = ProcessInfo.Open(Tasks.Marker(StepMarker).First(line => line.Event == "start").Pid);
                await File.WriteAllTextAsync(StepGo, "go", Ct);
                var step = Tasks.Processes(StepMarker).Single();
                await Tasks.WaitForAsync(() => !step.IsRunning(), Tasks.Bound, "the launch step to end");
                _stepExitCode = stepHandle is not null && Native.GetExitCodeProcess(stepHandle, out var code) ? unchecked((int)code) : null;

                // The job must hold nothing when the stop terminates it (the case under test).
                await WaitForEmptyJobAsync(_node!, attempt);
            }
            else
            {
                // The unit's start job waits for the gate's (the job table).
                var unit = SystemdTestEnvironment.AttemptUnit(attempt);
                await Tasks.WaitForAsync(() => SystemdTestEnvironment.Systemctl("list-jobs", "--no-legend", unit).Output.Contains(unit, StringComparison.Ordinal),
                    Tasks.Bound, "the attempt unit's start job to wait for the gate");
                Assert.True(SystemdTestEnvironment.Property(unit, "ActiveState") == "inactive", SystemdTestEnvironment.Describe(unit));
            }

            return attempt;
        }

        /// <summary>What the hold saw (diagnostics of a failure).</summary>
        public string Describe() =>
            "launch step exit code " + (_stepExitCode is { } code ? code.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unknown");

        /// <summary>Lets the command start (once).</summary>
        public void Release()
        {
            if (Interlocked.Exchange(ref _released, 1) != 0 || _node is null)
            {
                return;
            }

            if (OperatingSystem.IsWindows())
            {
                if (_holder is { } holder)
                {
                    Suspension.Resume(holder);
                }
            }
            else
            {
                File.WriteAllText(GateGo, "go");
            }
        }

        /// <summary>Releases the hold if the test did not (nothing stays suspended or waiting) and removes the gate.</summary>
        public ValueTask DisposeAsync()
        {
            Release();
            if (!OperatingSystem.IsWindows())
            {
                if (_gate is not null)
                {
                    SystemdTestEnvironment.Systemctl("stop", _gate);
                    SystemdTestEnvironment.Systemctl("reset-failed", _gate);
                }
            }

            return ValueTask.CompletedTask;
        }

        private IReadOnlyList<StepSpec> Launch(AttemptFiles files)
        {
            if (OperatingSystem.IsWindows())
            {
                _attempt.TrySetResult(files.AttemptName);
                string[] argv = [Tasks.TestLoad, "hold", "--until-file", StepGo, "--hold-ms", "120000", "--marker", StepMarker];
                return [new StepSpec { Name = "held", Application = argv[0], CommandLine = WindowsCommandLine.Build(argv), TimeoutMs = 120_000 }];
            }

            // Before the node starts the unit: the gate orders itself before it, so the unit's start job waits for the gate's. The gate is a
            // shell loop (the user manager's environment has no .NET runtime for the JIT test binaries; no '$', which systemd expands).
            var unit = SystemdTestEnvironment.AttemptUnit(files.AttemptName);
            _gate = "arcforges-test-gate-" + Guid.NewGuid().ToString("N")[..12] + ".service";
            SystemdRun("--user", "--no-block", "--unit=" + _gate, "--slice=" + _node!.Slice, "-p", "Type=oneshot", "-p", "Before=" + unit, "/bin/sh", "-c",
                $"while [ ! -e '{GateGo}' ]; do sleep 0.05; done");
            var watch = Stopwatch.StartNew();
            while (SystemdTestEnvironment.Property(_gate, "ActiveState") != "activating")
            {
                Assert.True(watch.Elapsed < Tasks.Bound, "The gate unit did not start: " + SystemdTestEnvironment.Describe(_gate));
                Thread.Sleep(50);
            }

            _attempt.TrySetResult(files.AttemptName);
            return [];
        }

        private static void SystemdRun(params string[] arguments)
        {
            var start = new ProcessStartInfo("systemd-run") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            foreach (var argument in arguments)
            {
                start.ArgumentList.Add(argument);
            }

            using var process = Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync(Ct);
            var error = process.StandardError.ReadToEndAsync(Ct);
            Assert.True(process.WaitForExit(TimeSpan.FromSeconds(30)), "systemd-run did not finish within 30 s.");
            Assert.True(process.ExitCode == 0, $"systemd-run {string.Join(' ', arguments)} failed ({process.ExitCode}): {output.Result}{error.Result}");
        }
    }

    /// <summary>
    /// Holds a process's run-down on Windows, without load or timing: a debugger attached to it continues every debug event but the process's
    /// exit, which it holds until <see cref="Release"/> or a bound after the exit. A debugged process cannot finish exiting before its exit
    /// event is continued, so a terminated one stays unsignaled until then (<see cref="RanDown"/>), as a starved one does, while its job
    /// already reports it gone and its exit code is final (both observed on the workstation: 5 of 5 times within 2 ms of TerminateJobObject,
    /// the handle signaled only after a 3 s hold). After <see cref="Release"/> the debugger lets the exit go on whenever it comes, until it is
    /// disposed; detaching never kills the process.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private sealed partial class ExitHold : IDisposable
    {
        private const uint ExceptionEvent = 1;
        private const uint CreateProcessEvent = 3;
        private const uint ExitProcessEvent = 5;
        private const uint LoadDllEvent = 6;
        private const uint Continue = 0x00010002;
        private const uint ExceptionNotHandled = 0x80010001;
        private const uint Breakpoint = 0x80000003;
        private const uint Synchronize = 0x00100000;
        private const uint QueryLimitedInformation = 0x00001000;
        private const uint StillActive = 259;
        private readonly ManualResetEventSlim _release = new();
        private readonly ManualResetEventSlim _detach = new();
        private readonly TaskCompletionSource _attached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _exit = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly SafeProcessHandle _process;
        private readonly Thread _debugger;

        private ExitHold(int pid, TimeSpan bound)
        {
            _process = OpenProcess(Synchronize | QueryLimitedInformation, inherit: false, pid);
            if (_process.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"OpenProcess({pid}) failed.");
            }

            // Every debug call of a debuggee is made by the thread that attached.
            _debugger = new Thread(() => Debug(pid, bound)) { IsBackground = true, Name = "exit-hold-" + pid };
            _debugger.Start();
        }

        /// <summary>Completes once the process's exit reached the debugger.</summary>
        public Task Exit => _exit.Task;

        /// <summary>The process has run down (its handle is signaled).</summary>
        public bool RanDown => WaitForSingleObject(_process, 0) == 0;

        /// <summary>Attaches to <paramref name="pid"/> and returns once the attach completed (the debugger's initial breakpoint).</summary>
        public static ExitHold Attach(int pid, TimeSpan bound)
        {
            Assert.SkipUnless(Environment.Is64BitProcess, "The exit hold reads DEBUG_EVENT with its 64-bit layout.");
            var hold = new ExitHold(pid, bound);
            try
            {
                Assert.True(hold._attached.Task.Wait(TimeSpan.FromSeconds(30)), $"The debugger did not attach to {pid} within 30 s.");
                return hold;
            }
            catch (AggregateException exception) when (exception.InnerException is Win32Exception failed)
            {
                // Never a skip: a step that has exited or is being terminated refuses a debugger too (STATUS_PROCESS_IS_TERMINATING reads as
                // ERROR_ACCESS_DENIED), so a launch that ends the step early would otherwise hide here. A host that forbids debugging fails clearly.
                var state = hold.State();
                hold.Dispose();
                Assert.Fail($"Attaching a debugger to the launch step ({pid}) failed: Win32 error {failed.NativeErrorCode} ({failed.Message}); the step {state}.");
                throw;
            }
            catch
            {
                hold.Dispose();
                throw;
            }
        }

        /// <summary>The process's state, for a failure message: alive, terminating (its exit code known, not run down yet) or exited.</summary>
        public string State()
        {
            var code = GetExitCodeProcess(_process, out var exitCode) ? exitCode.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unreadable";
            return RanDown ? $"has exited with code {code}" : exitCode == StillActive ? "is alive" : $"is terminating (exit code {code})";
        }

        /// <summary>Lets the process's exit go on, now or whenever it comes.</summary>
        public void Release() => _release.Set();

        public void Dispose()
        {
            _release.Set();
            _detach.Set();
            Assert.True(_debugger.Join(TimeSpan.FromSeconds(30)), "The exit hold's debugger did not end within 30 s.");
            _release.Dispose();
            _detach.Dispose();
            _process.Dispose();
        }

        private void Debug(int pid, TimeSpan bound)
        {
            if (!DebugActiveProcess(pid))
            {
                _attached.TrySetException(new Win32Exception(Marshal.GetLastPInvokeError(), $"DebugActiveProcess({pid}) failed."));
                return;
            }

            try
            {
                _ = DebugSetProcessKillOnExit(kill: false);
                while (true)
                {
                    if (!WaitForDebugEvent(out var debugEvent, 100))
                    {
                        if (_detach.IsSet)
                        {
                            return;
                        }

                        continue;
                    }

                    var status = Continue;
                    switch (debugEvent.Code)
                    {
                        case ExceptionEvent when (uint)debugEvent.Info == Breakpoint:
                            _attached.TrySetResult();
                            break;
                        case ExceptionEvent:
                            status = ExceptionNotHandled;
                            break;
                        case CreateProcessEvent or LoadDllEvent when debugEvent.Info != 0:
                            _ = CloseHandle(debugEvent.Info);
                            break;
                        case ExitProcessEvent:
                            _exit.TrySetResult();
                            _release.Wait(bound);
                            _ = ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, status);
                            return;
                    }

                    _ = ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, status);
                }
            }
            finally
            {
                _ = DebugActiveProcessStop(pid);
                _attached.TrySetException(new InvalidOperationException($"The debugger detached from {pid} before its attach completed."));
            }
        }

        /// <summary>DEBUG_EVENT (64-bit): the code, the process and thread, and the first field of the event's information.</summary>
        [StructLayout(LayoutKind.Explicit, Size = 176)]
        private struct DebugEvent
        {
            [FieldOffset(0)]
            public uint Code;

            [FieldOffset(4)]
            public int ProcessId;

            [FieldOffset(8)]
            public int ThreadId;

            /// <summary>The exception code (EXCEPTION_DEBUG_EVENT), or the image file handle (CREATE_PROCESS and LOAD_DLL).</summary>
            [FieldOffset(16)]
            public nint Info;
        }

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool DebugActiveProcess(int processId);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool DebugActiveProcessStop(int processId);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool DebugSetProcessKillOnExit([MarshalAs(UnmanagedType.Bool)] bool kill);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool WaitForDebugEvent(out DebugEvent debugEvent, uint milliseconds);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool ContinueDebugEvent(int processId, int threadId, uint status);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool CloseHandle(nint handle);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int processId);

        [LibraryImport("kernel32.dll")]
        private static partial uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);
    }

    /// <summary>Suspends and resumes a whole process (all its threads), for the Windows hold of an attempt's holder.</summary>
    [SupportedOSPlatform("windows")]
    private static partial class Suspension
    {
        private const uint SuspendResume = 0x0800;

        public static void Suspend(int pid) => Call(pid, suspend: true);

        public static void Resume(int pid) => Call(pid, suspend: false);

        private static void Call(int pid, bool suspend)
        {
            using var process = OpenProcess(SuspendResume, inherit: false, pid);
            if (process.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"OpenProcess({pid}) failed.");
            }

            var status = suspend ? NtSuspendProcess(process) : NtResumeProcess(process);
            Assert.True(status == 0, $"{(suspend ? "NtSuspendProcess" : "NtResumeProcess")}({pid}) failed: 0x{status:X8}.");
        }

        [LibraryImport("kernel32.dll", SetLastError = true)]
        private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int processId);

        [LibraryImport("ntdll.dll")]
        private static partial int NtSuspendProcess(SafeProcessHandle process);

        [LibraryImport("ntdll.dll")]
        private static partial int NtResumeProcess(SafeProcessHandle process);
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
