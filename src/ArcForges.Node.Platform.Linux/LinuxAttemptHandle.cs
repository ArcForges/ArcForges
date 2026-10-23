// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using Tmds.DBus.Protocol;

namespace ArcForges.Node.Platform.Linux;

/// <summary>What a limit stop did (04 section 6 step 4): whether the unit was frozen before its processes were killed.</summary>
/// <param name="Frozen">The unit was frozen first.</param>
/// <param name="Killed">Processes killed.</param>
/// <param name="FrozenAt">When the freeze completed (UTC).</param>
/// <param name="KilledAt">When the kill was sent (UTC).</param>
public sealed record LimitStop(bool Frozen, int Killed, DateTimeOffset? FrozenAt, DateTimeOffset KilledAt)
{
    /// <summary>The cgroup was thawed through its own file (true also when it was never frozen).</summary>
    public bool DirectThaw { get; init; } = true;

    /// <summary>When the thaw finished.</summary>
    public DateTimeOffset? ThawedAt { get; init; }

    /// <summary>The stop in words: <c>frozen at ..., then N process(es) killed at ...</c>.</summary>
    public string Describe() => Frozen
        ? string.Create(CultureInfo.InvariantCulture, $"frozen at {FrozenAt:O}, then {Killed} process(es) killed at {KilledAt:O}, thawed at {ThawedAt:O} (direct {DirectThaw})")
        : string.Create(CultureInfo.InvariantCulture, $"not frozen (the unit was not active); {Killed} process(es) killed at {KilledAt:O}");
}

/// <summary>
/// One attempt's transient unit <c>arcforges-a-&lt;attempt&gt;.service</c> (AD-0005 Linux section 2; 04 sections 3, 6 and 9):
/// <list type="bullet">
/// <item>Started with <c>StartTransientUnit</c> in the slice, stdio passed as file descriptors (<c>Standard*FileDescriptor</c>), the exact
/// environment (<c>Environment</c> plus <c>UnsetEnvironment</c> for every manager variable outside it), rlimits, the limits of 03 section
/// 5.2, <c>ExecStart</c> through <c>exec-launch</c>, <c>ExecStop=-</c> through <c>exec-stop</c> and <c>ExecStopPost</c> through
/// <c>exit-record</c>. The node waits for the start job's <c>JobRemoved</c> (result <c>done</c>) before it records the root process.</item>
/// <item>Cancellation: <c>KillUnit("all", stop_signal)</c>, then the forced phase. The forced phase and limit stops freeze the unit
/// (<c>FreezeUnit</c>), kill every process of its cgroup (the main process last), and thaw the cgroup directly: the user manager spawns
/// <c>ExecStop</c> into the unit's cgroup once the main process is gone, and a spawn into a frozen cgroup blocks it until the cgroup is
/// thawed (seen on systemd 257), so the thaw never waits on the manager. <c>KillUnit("all", SIGKILL)</c> is not used: it also kills the
/// unit's later control processes, so <c>ExecStopPost</c> would not write the exit record.</item>
/// <item>Observation: <c>PropertiesChanged</c> of the unit and a state read every 2 s. A failed unit without <c>exit.json</c> (an OOM
/// kill while <c>ExecStopPost</c> runs sends the unit to its final SIGKILL, which ends <c>exit-record</c> too) is recorded from the
/// unit's own properties and reset.</item>
/// </list>
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxAttemptHandle : IAttemptHandle
{
    private static readonly TimeSpan StatePollInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan VanishedGrace = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan FailedResetBound = TimeSpan.FromSeconds(30);
    private readonly LinuxExecutionPlatform _platform;
    private readonly TaskCompletionSource<RootProcess?> _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Dictionary<int, long> _members = [];
    private readonly Lock _gate = new();
    private IDisposable? _watch;
    private RootProcess? _root;
    private string? _cgroup;
    private UnitState? _lastState;
    private volatile bool _launchFinished;
    private volatile bool _signalled = true;
    private long _lastStateRead = long.MinValue;
    private long _vanishedAt = long.MinValue;
    private bool _disposed;

    private LinuxAttemptHandle(LinuxExecutionPlatform platform, AttemptFiles files, Stream? stdinWriter)
    {
        _platform = platform;
        Files = files;
        Unit = LinuxExecutionPlatform.UnitName(files.AttemptName);
        StdinWriter = stdinWriter;
    }

    /// <inheritdoc />
    public event Action? Changed;

    /// <summary>The attempt's files.</summary>
    public AttemptFiles Files { get; }

    /// <summary>The unit's name.</summary>
    public string Unit { get; }

    /// <inheritdoc />
    public string ContainerName => Unit;

    /// <inheritdoc />
    public RootProcess? Root => Volatile.Read(ref _root);

    /// <inheritdoc />
    public Task<RootProcess?> Started => _started.Task;

    /// <inheritdoc />
    public Stream? StdinWriter { get; }

    /// <summary>The unit's cgroup directory, once known.</summary>
    public string? CgroupDirectory => Volatile.Read(ref _cgroup);

    /// <summary>The last limit stop, if any (tests and the log check the freeze-before-kill order).</summary>
    public LimitStop? LastLimitStop { get; private set; }

    /// <inheritdoc />
    public bool RootRunning
    {
        get
        {
            if (File.Exists(Files.ExitPath))
            {
                return false;
            }

            if (Root is not { } root)
            {
                return !_launchFinished;
            }

            return ProcFs.StartOf(root.Pid) is { } start && Math.Abs((start.Start - root.StartTime).TotalMilliseconds) < 1_000;
        }
    }

    /// <inheritdoc />
    public bool MemoryLimitHit => CgroupDirectory is { } directory && ProcFs.KeyValues(Path.Combine(directory, "memory.events")).GetValueOrDefault("oom_kill") > 0;

    /// <summary>Starts the unit of <paramref name="launch"/>.</summary>
    internal static LinuxAttemptHandle Start(LinuxExecutionPlatform platform, AttemptLaunch launch)
    {
        var files = launch.Files;
        var manager = platform.Manager;
        SafeFileHandle? stdout = null, stderr = null, stdin = null;
        Stream? writer = null;
        try
        {
            stdout = Libc.Open(launch.DiscardOutput ? "/dev/null" : files.StdoutPath, write: true);
            stderr = Libc.Open(launch.DiscardOutput ? "/dev/null" : files.StderrPath, write: true);
            switch (launch.Stdin)
            {
                case StdinKind.File:
                    stdin = Libc.Open(launch.StdinPath ?? throw new ArgumentException("A stdin file is required.", nameof(launch)), write: false);
                    break;
                case StdinKind.Stream:
                    var (read, write) = Libc.Pipe();
                    stdin = new SafeFileHandle(read, ownsHandle: true);
                    writer = new FileStream(new SafeFileHandle(write, ownsHandle: true), FileAccess.Write, 1, isAsync: false);
                    break;
                default:
                    stdin = Libc.Open("/dev/null", write: false);
                    break;
            }

            var handle = new LinuxAttemptHandle(platform, files, writer);
            var properties = platform.AttemptProperties(launch, manager.ManagerEnvironment(), stdin, stdout, stderr);
            handle._watch = manager.WatchUnit(SystemdManager.UnitPath(handle.Unit), handle.OnUnitChanged);
            string job;
            try
            {
                job = manager.StartTransientUnit(handle.Unit, properties);
            }
            catch
            {
                handle._watch.Dispose();
                throw;
            }

            _ = Task.Run(() => handle.AwaitStart(job));
            writer = null;
            return handle;
        }
        catch (DBusErrorReplyException exception)
        {
            throw new IOException($"The user manager refused the attempt unit: {exception.ErrorName}: {LinuxExecutionPlatform.OneLine(exception.Message)}", exception);
        }
        finally
        {
            // The user manager holds its own copies of the descriptors now.
            stdout?.Dispose();
            stderr?.Dispose();
            stdin?.Dispose();
            writer?.Dispose();
        }
    }

    /// <summary>Re-opens a recovered attempt's unit by name, or null when it is gone.</summary>
    internal static LinuxAttemptHandle? Reopen(LinuxExecutionPlatform platform, AttemptFiles files, RootProcess? root)
    {
        var handle = new LinuxAttemptHandle(platform, files, null);
        var manager = platform.Manager;
        var state = manager.State(handle.Unit);
        if (state is null)
        {
            return null;
        }

        handle._lastState = state;
        if (state.ControlGroup.Length > 0)
        {
            handle._cgroup = ProcFs.CgroupDirectory(state.ControlGroup);
            handle.ReleaseStuckFreeze(state);
        }

        handle._root = root ?? RootOf(state);
        handle._launchFinished = true;
        handle._started.TrySetResult(handle._root);
        handle._watch = manager.WatchUnit(SystemdManager.UnitPath(handle.Unit), handle.OnUnitChanged);
        if (state.ActiveState == "failed" && !File.Exists(files.ExitPath))
        {
            handle.RecordFromUnit(state);
        }

        return handle;
    }

    /// <inheritdoc />
    public ExitRecord? TryReadExit() => ExitRecord.TryRead(Files.ExitPath);

    /// <inheritdoc />
    public LaunchRecord? TryReadLaunchFailure() => LaunchRecord.TryRead(Files.LaunchPath);

    /// <inheritdoc />
    public IReadOnlyList<ContainerProcess> Processes()
    {
        var directory = Resolve();
        if (directory is null)
        {
            return [];
        }

        var result = new List<ContainerProcess>();
        foreach (var pid in ProcFs.Procs(directory))
        {
            Remember(pid);
            result.Add(new ContainerProcess(pid, ProcFs.Image(pid)));
        }

        return result;
    }

    /// <inheritdoc />
    public ContainerAccounting Accounting()
    {
        var directory = Resolve();
        var accounting = directory is null ? null : ProcFs.Accounting(directory);
        if (accounting is null)
        {
            return new ContainerAccounting(0, 0, 0, 0, 0, 0, []);
        }

        return new ContainerAccounting(accounting.CpuUserMs, accounting.CpuKernelMs, accounting.MemPeakBytes, accounting.IoReadBytes, accounting.IoWriteBytes,
            ActiveProcesses(directory!), accounting.Violations());
    }

    /// <inheritdoc />
    public bool UsageNeedsProcessTable => false;

    /// <inheritdoc />
    public AttemptUsage Usage(IReadOnlyDictionary<int, ProcessSample>? processes)
    {
        // The unit's cgroup (03 section 1): cpu.stat, memory.current less inactive_file (03 section 3), io.stat and cgroup.procs.
        var directory = Resolve();
        if (directory is null || ProcFs.MemoryWithoutCache(directory) is not { } memory)
        {
            return new AttemptUsage(0, 0, 0, 0, []);
        }

        var cpu = ProcFs.KeyValues(Path.Combine(directory, "cpu.stat")).GetValueOrDefault("usage_usec") / 1000;
        var (read, written) = ProcFs.IoBytes(directory);
        return new AttemptUsage(cpu, memory, read, written, ProcFs.Procs(directory));
    }

    /// <inheritdoc />
    public void Terminate() => FreezeAndKill();

    /// <inheritdoc />
    public string StopAtLimit()
    {
        FreezeAndKill();
        return LastLimitStop is { } stop ? stop.Describe() : "killed";
    }

    /// <inheritdoc />
    public GracefulOutcome RequestGracefulStop() => RequestGracefulStop(null);

    /// <inheritdoc />
    public GracefulOutcome RequestGracefulStop(string? stopSignal)
    {
        var signal = LinuxRecords.SignalNumber(stopSignal) is > 0 and var number ? number : Libc.SigTerm;
        try
        {
            _platform.Manager.KillUnit(Unit, "all", signal);
            return new GracefulOutcome(true, 0, null);
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or InvalidOperationException)
        {
            return new GracefulOutcome(false, 0, $"KillUnit(all, SIG{LinuxRecords.SignalName(signal)}) failed: {LinuxExecutionPlatform.OneLine(exception.Message)}");
        }
    }

    /// <summary><c>FreezeUnit</c> (pause; R-EXE-011): returns once the unit is frozen.</summary>
    public void Freeze() => _platform.Manager.FreezeUnit(Unit);

    /// <summary><c>ThawUnit</c>.</summary>
    public void Thaw() => _platform.Manager.ThawUnit(Unit);

    /// <inheritdoc />
    public bool CanPause => _platform.Freezer;

    /// <inheritdoc />
    public void SetCpuWeight(int weight) =>
        _platform.Manager.SetUnitProperties(Unit, runtime: true, [new UnitProperty("CPUWeight", (ulong)LinuxExecutionPlatform.CpuWeight(weight))]);

    /// <inheritdoc />
    public void SetMemoryHigh(long bytes) =>
        _platform.Manager.SetUnitProperties(Unit, runtime: true, [new UnitProperty("MemoryHigh", (ulong)Math.Max(1024 * 1024, bytes))]);

    /// <inheritdoc />
    public IReadOnlyList<EscapedProcess> ScanEscaped()
    {
        var directory = Resolve();
        if (directory is null)
        {
            return [];
        }

        var inside = ProcFs.Procs(directory).ToHashSet();
        foreach (var pid in inside)
        {
            Remember(pid);
        }

        var table = new Dictionary<int, (int Parent, long Start)>();
        foreach (var pid in ProcFs.AllProcesses())
        {
            if (ProcFs.Stat(pid) is { } stat && stat.State is not ('Z' or 'X'))
            {
                table[pid] = (stat.ParentPid, stat.StartTicks);
            }
        }

        Dictionary<int, long> members;
        lock (_gate)
        {
            // A member that exited (or whose ID now names a later process) is never a parent again: its children were re-parented when it
            // exited, so a process whose parent ID is that ID belongs to whoever reused it (AF-SEC-01 repair of AF-EXEC-02's scan).
            foreach (var gone in _members.Where(member => !table.TryGetValue(member.Key, out var now) || now.Start != member.Value).Select(member => member.Key).ToList())
            {
                _members.Remove(gone);
            }

            members = new Dictionary<int, long>(_members);
        }

        var self = ProcFs.UserId;
        return [.. Descendants(members, inside, table).Select(pair => new EscapedProcess(pair.Key, pair.Value.Parent, ProcFs.StartInstant(pair.Value.Start),
            ProcFs.Image(pair.Key), ProcFs.OwnerOf(pair.Key) == self))];
    }

    /// <summary>
    /// The escaped processes of an attempt (03 section 9): processes outside the unit's cgroup (<paramref name="inside"/>) whose parent is a
    /// recorded member or another escaped process, created no earlier than that parent. A member is a parent only while its ID still names
    /// the same process (its current start in <paramref name="table"/> equals the recorded one), so after an ID is reused, the children of
    /// the unrelated process that reused it are never reported (and never killed). <paramref name="table"/> holds every live process with
    /// its parent and start (clock ticks since boot).
    /// </summary>
    internal static Dictionary<int, (int Parent, long Start)> Descendants(IReadOnlyDictionary<int, long> members, IReadOnlySet<int> inside,
        IReadOnlyDictionary<int, (int Parent, long Start)> table)
    {
        ArgumentNullException.ThrowIfNull(members);
        ArgumentNullException.ThrowIfNull(inside);
        ArgumentNullException.ThrowIfNull(table);
        var escaped = new Dictionary<int, (int Parent, long Start)>();
        for (var pass = 0; pass < 8; pass++)
        {
            var added = false;
            foreach (var (pid, (parent, start)) in table)
            {
                if (inside.Contains(pid) || escaped.ContainsKey(pid))
                {
                    continue;
                }

                var fromMember = members.TryGetValue(parent, out var memberStart) && table.TryGetValue(parent, out var current) && current.Start == memberStart
                    && memberStart <= start;
                var fromEscaped = escaped.TryGetValue(parent, out var escapedParent) && escapedParent.Start <= start;
                if (fromMember || fromEscaped)
                {
                    escaped[pid] = (parent, start);
                    added = true;
                }
            }

            if (!added)
            {
                break;
            }
        }

        return escaped;
    }

    /// <inheritdoc />
    public IReadOnlyList<string> TerminateEscaped()
    {
        var terminated = new List<string>();
        foreach (var process in ScanEscaped().Where(process => process.SameUser))
        {
            if (ProcFs.StartOf(process.Pid) is { } start && Math.Abs((start.Start - process.StartTime).TotalMilliseconds) < 1_000
                && Libc.Kill(process.Pid, Libc.SigKill) == 0)
            {
                terminated.Add($"{process.Image} ({process.Pid.ToString(CultureInfo.InvariantCulture)})");
            }
        }

        return terminated;
    }

    /// <inheritdoc />
    public void Acknowledge()
    {
        // The exit record is durable in the attempt's directory and nothing waits. A unit that ended failed (an OOM kill, a stop timeout)
        // stays loaded (CollectMode=inactive) until the node recorded it: once it is failed, it is reset and unloaded. exit-record runs
        // before the unit turns failed, so this waits for that state off the enforcement loop (bounded; units that succeeded are collected).
        if (TryReadExit() is not { RecordedBy: "exit-record" } exit || exit.ServiceResult == "success")
        {
            return;
        }

        _ = Task.Run(() =>
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            while (watch.Elapsed < FailedResetBound)
            {
                try
                {
                    switch (_platform.Manager.State(Unit)?.ActiveState)
                    {
                        case "failed":
                            _platform.Manager.ResetFailedUnit(Unit);
                            return;
                        case null or "inactive" or "active" or "activating":
                            return;
                    }
                }
                catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or InvalidOperationException or ObjectDisposedException)
                {
                    return;
                }

                Thread.Sleep(100);
            }
        });
    }

    /// <inheritdoc />
    public void Refresh()
    {
        if (_disposed || !_launchFinished || File.Exists(Files.ExitPath))
        {
            return;
        }

        var now = Environment.TickCount64;
        if (!_signalled && _lastStateRead != long.MinValue && now - _lastStateRead < StatePollInterval.TotalMilliseconds)
        {
            return;
        }

        _signalled = false;
        _lastStateRead = now;
        UnitState? state;
        try
        {
            state = _platform.Manager.State(Unit);
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or InvalidOperationException)
        {
            return;
        }

        if (state is null)
        {
            // Collected without a record (it should have been written before the unit became inactive): record it from what is known.
            if (_vanishedAt == long.MinValue)
            {
                _vanishedAt = now;
            }
            else if (now - _vanishedAt >= VanishedGrace.TotalMilliseconds && !File.Exists(Files.ExitPath))
            {
                RecordFromUnit(_lastState ?? new UnitState("inactive", "dead", "unknown", 0, string.Empty, 0, 0, 0, 0, 0, 0, 0, 0));
            }

            return;
        }

        _vanishedAt = long.MinValue;
        _lastState = state;
        if (state.ControlGroup.Length > 0)
        {
            Volatile.Write(ref _cgroup, ProcFs.CgroupDirectory(state.ControlGroup));
        }

        if (state.ActiveState == "failed" && !File.Exists(Files.ExitPath))
        {
            RecordFromUnit(state);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _watch?.Dispose();
        StdinWriter?.Dispose();
        _started.TrySetResult(Root);
    }

    private static RootProcess? RootOf(UnitState state)
    {
        var pid = state.MainPid != 0 ? (int)state.MainPid : (int)state.ExecMainPid;
        if (pid == 0)
        {
            return null;
        }

        if (ProcFs.StartOf(pid) is { } start)
        {
            return new RootProcess(pid, start.Start);
        }

        return state.ExecMainStartUs > 0 ? new RootProcess(pid, DateTimeOffset.UnixEpoch.AddTicks((long)state.ExecMainStartUs * 10)) : null;
    }

    private void AwaitStart(string job)
    {
        RootProcess? root = null;
        try
        {
            var result = _platform.Manager.WaitJob(job, TimeSpan.FromSeconds(90));
            if (result == "done" && _platform.Manager.State(Unit) is { } state)
            {
                _lastState = state;
                if (state.ControlGroup.Length > 0)
                {
                    Volatile.Write(ref _cgroup, ProcFs.CgroupDirectory(state.ControlGroup));
                }

                root = RootOf(state);
                if (root is not null)
                {
                    Remember(root.Pid);
                    if (_platform.Hardening is not null)
                    {
                        // AD-0007 section 8: the hardening is read back from the running unit; one that did not apply is reported as such, and
                        // one whose root ended before the read is "not verified", never "applied".
                        var (readOnly, inaccessible) = _platform.HardenedPaths;
                        _platform.HardeningReadBack(Files.AttemptName,
                            ProcFs.Stat(root.Pid) is { } stat ? LinuxExecutionPlatform.HardeningReadBackOf(root.Pid, stat.StartTicks, readOnly, inaccessible) : null);
                    }
                }
            }
            else if (!File.Exists(Files.LaunchPath) && result != "done")
            {
                HelperFiles.WriteAtomically(Files.LaunchPath, new LaunchRecord
                {
                    AttemptId = Files.AttemptName,
                    Step = "command",
                    Error = $"the user manager did not start the attempt unit (job result {result ?? "timeout"})",
                    RecordedAt = HelperFiles.Now(),
                }.ToJson());
            }
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or InvalidOperationException or IOException)
        {
            // The unit's own record (exit.json, launch.json) still finalizes the attempt.
        }

        Volatile.Write(ref _root, root);
        _launchFinished = true;
        _started.TrySetResult(root);
        Changed?.Invoke();
    }

    private void OnUnitChanged()
    {
        _signalled = true;
        Changed?.Invoke();
    }

    private string? Resolve()
    {
        if (CgroupDirectory is { } known)
        {
            return known;
        }

        try
        {
            if (_platform.Manager.State(Unit) is { ControlGroup.Length: > 0 } state)
            {
                Volatile.Write(ref _cgroup, ProcFs.CgroupDirectory(state.ControlGroup));
            }
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or InvalidOperationException)
        {
        }

        return CgroupDirectory;
    }

    private void Remember(int pid)
    {
        if (ProcFs.Stat(pid) is { } stat)
        {
            lock (_gate)
            {
                _members[pid] = stat.StartTicks;
            }
        }
    }

    /// <summary>The unit's processes, without its control process (<c>ExecStop</c> or <c>ExecStopPost</c>) and that process's descendants.</summary>
    private int ActiveProcesses(string directory)
    {
        var pids = ProcFs.Procs(directory);
        if (pids.Count == 0)
        {
            return 0;
        }

        uint control;
        try
        {
            control = _platform.Manager.State(Unit)?.ControlPid ?? 0;
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or InvalidOperationException)
        {
            control = 0;
        }

        if (control == 0)
        {
            return pids.Count;
        }

        var parents = pids.ToDictionary(pid => pid, pid => ProcFs.Stat(pid)?.ParentPid ?? 0);
        bool UnderControl(int pid)
        {
            for (var depth = 0; depth < 64 && pid > 1; depth++)
            {
                if (pid == (int)control)
                {
                    return true;
                }

                if (!parents.TryGetValue(pid, out var parent))
                {
                    return false;
                }

                pid = parent;
            }

            return false;
        }

        return pids.Count(pid => !UnderControl(pid));
    }

    /// <summary>The forced phase and limit stops: freeze, kill every process (the main process last), thaw (see the class remarks).</summary>
    private void FreezeAndKill()
    {
        LastLimitStop = UnitControl.FreezeAndKill(_platform.Manager, Unit, Resolve(), Root?.Pid ?? 0);
        Changed?.Invoke();
    }

    /// <summary>Thaws a unit left frozen by a node that died between its freeze and its thaw (its main process is gone).</summary>
    private void ReleaseStuckFreeze(UnitState state)
    {
        var directory = CgroupDirectory!;
        if (ProcFs.Text(Path.Combine(directory, "cgroup.freeze")) == "1" && (state.MainPid == 0 || ProcFs.StartOf((int)state.MainPid) is null))
        {
            ProcFs.WriteControl(Path.Combine(directory, "cgroup.freeze"), "0");
        }
    }

    private void RecordFromUnit(UnitState state)
    {
        try
        {
            if (!File.Exists(Files.ExitPath))
            {
                HelperFiles.WriteAtomically(Files.ExitPath, LinuxRecords.FromUnit(Files.AttemptName, state, StopRecord.TryRead(Files.StopPath), DateTimeOffset.UtcNow).ToJson());
            }

            if (state.ActiveState == "failed")
            {
                _platform.Manager.ResetFailedUnit(Unit);
            }
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or IOException or UnauthorizedAccessException or Win32Exception)
        {
        }

        Changed?.Invoke();
    }
}
