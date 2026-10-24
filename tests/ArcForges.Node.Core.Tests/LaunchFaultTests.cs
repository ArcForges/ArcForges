// SPDX-License-Identifier: AGPL-3.0-only
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
    /// <summary>When the command (<c>hold --ready-after-ms</c>) marks itself ready: a command still running then ran on past its stop.</summary>
    private const int ReadyAfterMs = 3_000;

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
        seam.AssertStartedInBetween();
        await AssertNeverRanPastTheStopAsync(commandMarker);
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
        seam.AssertStartedInBetween();
        await AssertNeverRanPastTheStopAsync(commandMarker);
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
    /// The command never ran on past the stop: every process it started is gone once its task ended, and none reached its ready mark
    /// <see cref="ReadyAfterMs"/> after its start (generous: the second termination follows the start at once).
    /// </summary>
    private static async Task AssertNeverRanPastTheStopAsync(string marker)
    {
        foreach (var process in Tasks.Processes(marker))
        {
            Assert.False(process.IsRunning(), $"The command {process} still runs after its task ended.");
        }

        var starts = Tasks.Marker(marker).Where(line => line.Event == "start").Select(line => line.At).ToList();
        if (starts.Count > 0)
        {
            var wait = starts.Max() + ReadyAfterMs + 1_000 - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (wait > 0)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(wait), Ct);
            }
        }

        Assert.DoesNotContain(Tasks.Marker(marker), line => line.Event == "ready");
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

        public void Invoke(IAttemptHandle handle)
        {
            if (Interlocked.Increment(ref _calls) != 1)
            {
                return;
            }

            _pendingAtCall = !handle.Started.IsCompleted;
            hold.Release();
            _started = handle.Started.Wait(Tasks.Bound) ? handle.Started.Result : null;
        }

        /// <summary>The forced phase ran once while the start was pending, and the start completed with a root while it was held.</summary>
        public void AssertStartedInBetween()
        {
            Assert.Equal(1, Volatile.Read(ref _calls));
            Assert.True(_pendingAtCall, "The start had completed before the forced phase's termination.");
            Assert.True(_started is not null, "The start did not complete with a root while the forced phase was held.");
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

        /// <summary>Waits until the attempt is being launched and its command is held back.</summary>
        public async Task HeldAsync()
        {
            var attempt = await _attempt.Task.WaitAsync(Tasks.Bound, Ct);
            if (OperatingSystem.IsWindows())
            {
                await Tasks.WaitForAsync(() => Tasks.Marker(StepMarker).Any(line => line.Event == "start"), Tasks.Bound, "the launch step to run");
                _holder = ExecutionCleanup.Holders([attempt]).Single();
                Suspension.Suspend(_holder.Value);
                await File.WriteAllTextAsync(StepGo, "go", Ct);
                var step = Tasks.Processes(StepMarker).Single();
                await Tasks.WaitForAsync(() => !step.IsRunning(), Tasks.Bound, "the launch step to end");
            }
            else
            {
                // The unit's start job waits for the gate's (the job table).
                var unit = SystemdTestEnvironment.AttemptUnit(attempt);
                await Tasks.WaitForAsync(() => SystemdTestEnvironment.Systemctl("list-jobs", "--no-legend", unit).Output.Contains(unit, StringComparison.Ordinal),
                    Tasks.Bound, "the attempt unit's start job to wait for the gate");
                Assert.True(SystemdTestEnvironment.Property(unit, "ActiveState") == "inactive", SystemdTestEnvironment.Describe(unit));
            }
        }

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
