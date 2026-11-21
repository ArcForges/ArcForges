// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;
using ArcForges.Node.Store;
using ArcForges.Tests;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Tests;

/// <summary>Controls on retained legacy Tasks after fresh Task admission was removed.</summary>
public sealed partial class LaunchFaultTests
{
    // The fresh Task launch and late-start process races remain executable at Windows historical anchor
    // eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a using this project's LaunchFaultTests on the original test profile.
    // The current V2 Run recovery cases are in RecoveryPreparedMxcRunServiceTests, RecoveryNativeDispatchMxcRunServiceTests
    // and RecoveryMxcRunServiceTests. Retained platform re-open checks still have their own JobTests and UnitPlatformTests.

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 30_000)]
    public async Task ConcurrentCancelsSettleAndReplayEveryRetainedQueuedTaskWithoutStartingAnAttempt()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions
        {
            DataRoot = fixture.DataRoot,
            BootIdentity = BootIdentity.Read(),
            Clock = fixture.Clock,
        });
        using var log = new NodeLog(Path.Combine(fixture.DataRoot, "logs", "node"), LogLevel.Info, fixture.Clock);
        using var heartbeat = new NodeHeartbeatWriter(fixture.DataRoot, log, fixture.Clock);
        using var keys = new NodeDataKeyRing(store, fixture.Secrets.Selection);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        var recovery = new RecoveryReport(false, false, null, store.Opening);
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = fixture.Clock,
            DataRoot = fixture.DataRoot,
            Secrets = new TaskSecrets(store, keys),
            Heartbeat = heartbeat,
        });
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(fixture.ConfigPath, fixture.DataRoot, log), fixture.DataRoot, "offline-fixture", fixture.Clock,
            recovery, new CapabilityReport())
        {
            Execution = execution,
        };

        const int count = 24;
        var owner = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli };
        var taskIds = store.Write(transaction => Enumerable.Range(0, count)
            .Select(_ => LegacyTaskHistoryFixture.SeedQueued(transaction, owner)).ToArray(), CommitDurability.Full);
        await runtime.TransitionAsync(NodeLifecycleState.Recovering, "fixture").WaitAsync(ct);
        await execution.RecoverAsync(recovery, processor, ct);
        await runtime.TransitionAsync(NodeLifecycleState.Ready, "fixture").WaitAsync(ct);

        var handler = new TaskServiceHandler(runtime, new ClientSessions());
        var human = new Caller(Origin.Human, ClientKind.Cli, null);
        var requests = taskIds.Select(id => new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "migration" }).ToArray();
        Assert.Equal((long)count, store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE state=$state;",
            ("$state", (int)TaskState.Queued))));
        var original = await Task.WhenAll(requests.Select(request => handler.CancelTask(human, request, ct)));
        var replay = await Task.WhenAll(requests.Select(request => handler.CancelTask(human, request, ct)));
        for (var index = 0; index < requests.Length; index++)
        {
            Assert.Null(original[index].Error);
            Assert.Equal(TaskState.Cancelled, original[index].Value.State);
            Assert.Equal(requests[index].Meta.CommandId, original[index].Value.Receipt.CommandId);
            Assert.Equal(EffectCertainty.Happened, original[index].Value.Receipt.Effect);
            Assert.Null(replay[index].Error);
            Assert.Equal(original[index].Value, replay[index].Value);
        }

        Assert.Equal((long)count, store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE state=$state;",
            ("$state", (int)TaskState.Cancelled))));
        Assert.Empty(execution.RunningAttempts);
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
    }

    [SupportedOSPlatform("windows")]
    private static Task WaitForWindowsRundownAsync(SafeHandle process) =>
        Tasks.WaitForAsync(() => !ProcessInfo.IsRunning(process), Tasks.Bound, "the stopped launch step to finish running down before fixture cleanup");

    private static void SkipWithoutPlatform()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        }
    }

    /// <summary>CANCELLED with the cancel's reason; effect HAPPENED (04 section 7: DID_NOT_HAPPEN only for SPAWN_FAILED and POLICY_DENIED).</summary>
    private static void AssertCancelled(ManagedTask task)
    {
        Assert.True(task.State == TaskState.Cancelled, $"{task.State}: {task.CurrentAttempt?.Result}");
        var result = Assert.IsType<Attempt>(task.CurrentAttempt).Result;
        Assert.Equal(TerminationReason.Cancelled, result.TerminationReason);
        Assert.Equal(EffectCertainty.Happened, result.Effect);
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

        /// <summary>Waits until the attempt is being launched and its command is held back; returns the attempt's name.</summary>
        public async Task<string> HeldAsync()
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

        /// <summary>Waits for the exact process object to be signaled before fixture cleanup.</summary>
        public Task WaitForRundownAsync() => WaitForWindowsRundownAsync(_process);

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
