// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using ArcForges.Contracts.Node.V1;
using Microsoft.Win32.SafeHandles;
using Tmds.DBus.Protocol;

namespace ArcForges.Node.Platform.Linux;

/// <summary>How the Linux platform runs (the node's configuration; tests give each node its own slice and may withhold the manager).</summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxPlatformOptions
{
    /// <summary>The root slice (13 section 3.4: <c>arcforges.slice</c>; tests: <c>arcforges-test-&lt;id&gt;.slice</c>, 16 section 4).</summary>
    public string Slice { get; init; } = LinuxExecutionPlatform.DefaultSlice;

    /// <summary>The user manager's D-Bus address; null for the default (the user bus, else the manager's private socket).</summary>
    public string? ManagerAddress { get; init; }

    /// <summary>
    /// The controllers treated as delegated instead of those the user manager's cgroup offers (test mode: simulates a manager without
    /// delegation of a controller, R-RES-008); null reads <c>cgroup.controllers</c>.
    /// </summary>
    public IReadOnlyCollection<string>? DelegatedControllers { get; init; }

    /// <summary>The node's own unit, which <c>kill_with_node</c> attempts bind to; null detects it from the node's cgroup.</summary>
    public string? NodeUnit { get; init; }

    /// <summary>
    /// Tests only: entries added to every attempt unit's <c>Environment=</c> outside the resolved environment, standing in for a variable
    /// the user manager passes to its services (the command must never see them).
    /// </summary>
    internal IReadOnlyList<string> ExtraUnitEnvironment { get; init; } = [];
}

/// <summary>
/// The Linux execution platform (AD-0005 Linux; architecture 04 sections 2, 3, 6 and 9; 03 sections 5 and 8):
/// <list type="bullet">
/// <item>The root container is the slice (<c>arcforges.slice</c>) with runtime limits (<c>CPUQuota</c>, <c>MemoryHigh</c>,
/// <c>MemoryMax</c>, <c>MemorySwapMax</c>, <c>TasksMax</c>) set through the user manager; a transient slice when no unit file
/// defines it. Startup verifies enforcement with a probe unit whose cgroup files must carry its limits.</item>
/// <item>Each attempt is the transient service <c>arcforges-a-&lt;attempt&gt;.service</c> (see <see cref="LinuxAttemptHandle"/>).</item>
/// <item>Without a user manager the platform runs attempts as plain child processes of the node (observe only; see
/// <see cref="DirectAttemptHandle"/>); a controller missing from the manager's delegation makes that resource observe only.</item>
/// </list>
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxExecutionPlatform : IExecutionPlatform
{
    /// <summary>The production slice (13 section 3.4).</summary>
    public const string DefaultSlice = "arcforges.slice";

    /// <summary>The oldest systemd this platform drives (AD-0005 Linux section 3).</summary>
    public const int MinimumSystemd = 247;

    /// <summary>The prefix of attempt units.</summary>
    public const string UnitPrefix = "arcforges-a-";

    /// <summary>The conventional soft open-file limit passed to attempts (the kernel default a login shell has).</summary>
    public const ulong DefaultNoFileSoft = 1024;

    /// <summary>
    /// Added to <c>TimeoutStopSec</c> beyond the end-step budget and <c>leftover_grace</c>: the <c>exec-stop</c> role's own start and the
    /// write of <c>stop.json</c>, so systemd never stops the role while it records the leftovers.
    /// </summary>
    public const int StopRecordMarginMs = 5_000;

    /// <summary>The .NET runtime's switch for its diagnostic endpoints (framework-dependent helpers only).</summary>
    internal const string DiagnosticsVariable = "DOTNET_EnableDiagnostics";

    private readonly LinuxPlatformOptions _options;
    private readonly Lock _gate = new();
    private SystemdManager? _manager;
    private HashSet<string>? _failedUnits;
    private long _failedUnitsAt;
    private string? _managerReason;
    private HashSet<string> _controllers = new(StringComparer.Ordinal);
    private string? _selfTest;
    private RootLimits? _rootLimits;
    private string _helper = string.Empty;
    private string _nodeName = string.Empty;
    private string? _nodeUnit;
    private string? _sliceCgroup;
    private bool _freezer;
    private int _systemdVersion;
    private bool _disposed;

    /// <summary>Creates the platform.</summary>
    public LinuxExecutionPlatform(LinuxPlatformOptions? options = null)
    {
        _options = options ?? new LinuxPlatformOptions();
        Capacity = new MachineCapacity(Environment.ProcessorCount, ProcFs.PhysicalMemory());
    }

    /// <inheritdoc />
    public string Name => UnitMode ? "linux-systemd" : "linux-direct";

    /// <inheritdoc />
    public StringComparer EnvironmentNames => StringComparer.Ordinal;

    /// <inheritdoc />
    public MachineCapacity Capacity { get; }

    /// <summary>The root slice.</summary>
    public string Slice => _options.Slice;

    /// <summary>True when attempts run as transient units of the user manager (false: plain child processes, degraded).</summary>
    public bool UnitMode => _manager is not null;

    /// <summary>Why there is no user manager, when there is none.</summary>
    public string? ManagerUnavailableReason => _managerReason;

    /// <summary>The controllers delegated to the user manager (or the test override).</summary>
    public IReadOnlySet<string> Controllers => _controllers;

    /// <summary>The helper executable (<c>arcforges</c>).</summary>
    public string Helper => _helper;

    /// <summary>The unit name of an attempt.</summary>
    public static string UnitName(string attemptName) => UnitPrefix + attemptName + ".service";

    /// <summary>The attempt cgroups found frozen and blocking the user manager at start, thawed directly (for the node log).</summary>
    public IReadOnlyList<string> ReleasedFreezes { get; private set; } = [];

    /// <summary>The user manager connection (reconnected after the user manager restarted).</summary>
    internal SystemdManager Manager
    {
        get
        {
            lock (_gate)
            {
                if (_manager is { Closed: false } current)
                {
                    return current;
                }

                if (_manager is null)
                {
                    throw new InvalidOperationException("No systemd user manager is connected.");
                }

                // The user manager restarted (systemctl --user daemon-reexec) or the connection dropped: connect again.
                _manager.Dispose();
                _manager = SystemdManager.Connect(_manager.Address, SystemdManager.CallTimeout);
                return _manager;
            }
        }
    }

    /// <inheritdoc />
    public void Start(string nodeName, RootLimits limits, string helperExecutable)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeName);
        ArgumentNullException.ThrowIfNull(limits);
        ArgumentException.ThrowIfNullOrWhiteSpace(helperExecutable);
        _nodeName = nodeName;
        _helper = helperExecutable;
        _nodeUnit = _options.NodeUnit ?? OwnUnit();
        var address = _options.ManagerAddress ?? SystemdManager.DefaultAddress();
        if (address is null)
        {
            _managerReason = "no systemd user manager runs for this user ($XDG_RUNTIME_DIR/systemd/private does not exist)";
            return;
        }

        // Before any call to the manager, which a frozen attempt cgroup left by a dead node or guard would block.
        ReleasedFreezes = UnitControl.ReleaseStuckFreezes();

        SystemdManager manager;
        try
        {
            manager = SystemdManager.Connect(address, TimeSpan.FromSeconds(5));
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or IOException or System.Net.Sockets.SocketException
            or OperationCanceledException or AggregateException)
        {
            _managerReason = $"the systemd user manager at {address} cannot be reached ({exception.GetType().Name}: {OneLine(exception.Message)})";
            return;
        }

        _systemdVersion = int.TryParse(manager.Version.Split('.', ' ', '-')[0], NumberStyles.None, CultureInfo.InvariantCulture, out var version) ? version : 0;
        if (_systemdVersion < MinimumSystemd)
        {
            _managerReason = $"the systemd user manager is version {manager.Version}; transient attempt units need {MinimumSystemd} or later";
            manager.Dispose();
            return;
        }

        _manager = manager;
        _controllers = _options.DelegatedControllers is { } simulated
            ? new HashSet<string>(simulated, StringComparer.Ordinal)
            : ReadControllers(manager);
        try
        {
            EnsureSlice(limits);
            _selfTest = Probe();
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or IOException or InvalidOperationException)
        {
            _selfTest = $"the slice or the probe unit failed ({exception.GetType().Name}: {OneLine(exception.Message)})";
        }
    }

    /// <inheritdoc />
    public void UpdateRootLimits(RootLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        _rootLimits = limits;
        if (_manager is null)
        {
            return;
        }

        Manager.SetUnitProperties(Slice, runtime: true, SliceProperties(limits));
    }

    /// <inheritdoc />
    public CapabilityReport Evaluate()
    {
        var report = new CapabilityReport();
        if (_manager is null)
        {
            var why = _managerReason ?? "the platform has not started";
            report.Cpu = CpuControl.ObserveOnly;
            report.CpuReason = why;
            report.Memory = MemoryControl.ObserveOnly;
            report.MemoryReason = why;
            report.Pids = ProcessCountControl.ObserveOnly;
            report.PidsReason = why;
            report.Io = IoControl.ObserveOnly;
            report.IoReason = why;
            report.Pause = PauseSupport.Unsupported;
            report.PauseReason = why;
            report.KillTree = KillTreeGuarantee.BestEffort;
            report.KillTreeReason = "attempts are plain child processes of the node in their own process group; a process that leaves the group is not reached";
            report.Adopt = AdoptSupport.Unsupported;
            report.AdoptReason = "process adoption is not part of this build";
            report.RestartSurvival = false;
            report.RestartSurvivalReason = "attempts are plain child processes of the node: their exit status is lost when the node restarts before they finish";
        }
        else
        {
            var failed = _selfTest;
            string Reason(string controller, string enforced) => failed is not null
                ? failed
                : _controllers.Contains(controller)
                    ? enforced
                    : $"the user manager has no {controller} delegation (DelegateControllers of user@{ProcFs.UserId.ToString(CultureInfo.InvariantCulture)}.service)";
            bool Has(string controller) => failed is null && _controllers.Contains(controller);
            report.Cpu = Has("cpu") ? CpuControl.EnforcedShareAndCap : CpuControl.ObserveOnly;
            report.CpuReason = Reason("cpu", "CPUWeight per attempt unit under the slice's CPUQuota (cpu.weight, cpu.max; L-13)");
            report.Memory = Has("memory") ? MemoryControl.EnforcedSoftAndHard : MemoryControl.ObserveOnly;
            report.MemoryReason = Reason("memory", "MemoryHigh and MemoryMax per attempt unit and on the slice, MemorySwapMax from swap_allowance (03 section 5.4)");
            report.Pids = Has("pids") ? ProcessCountControl.Enforced : ProcessCountControl.ObserveOnly;
            report.PidsReason = Reason("pids", "TasksMax per attempt unit and on the slice (pids.max)");
            report.Io = IoControl.ObserveOnly;
            report.IoReason = _controllers.Contains("io")
                ? "I/O limits are a privileged option that is not part of this build; io.stat is observed"
                : "the io controller is not delegated to the user manager (L-06); I/O limits are a privileged option; io.stat is observed";
            report.Pause = _freezer && failed is null ? PauseSupport.Supported : PauseSupport.Unsupported;
            report.PauseReason = report.Pause == PauseSupport.Supported
                ? "FreezeUnit and ThawUnit (cgroup.freeze)"
                : failed ?? "the kernel or the user manager offers no unit freezer (cgroup.freeze)";
            report.KillTree = failed is null ? KillTreeGuarantee.Guaranteed : KillTreeGuarantee.BestEffort;
            report.KillTreeReason = failed ?? "every process of an attempt is in its unit's cgroup, which the node freezes and kills; no process can leave it without the user manager";
            report.Adopt = AdoptSupport.Unsupported;
            report.AdoptReason = "process adoption is not part of this build";
            report.RestartSurvival = failed is null;
            report.RestartSurvivalReason = failed ?? "attempts are transient units of the user manager, never children of the node, with a durable exit record from ExecStopPost (L-13)";
        }

        report.PlatformFacts.Add(Fact("os", RuntimeInformation.OSDescription));
        report.PlatformFacts.Add(Fact("arch", RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant()));
        report.PlatformFacts.Add(Fact("runtime", RuntimeInformation.FrameworkDescription));
        report.PlatformFacts.Add(Fact("cgroup_v2", File.Exists(Path.Combine(ProcFs.CgroupRoot, "cgroup.controllers")) ? "present" : "absent"));
        report.PlatformFacts.Add(Fact("systemd_user_manager", _manager is null ? "absent" : "running"));
        report.PlatformFacts.Add(Fact("execution", _manager is null ? "child processes (observe only)" : "transient user units"));
        if (_manager is { } manager)
        {
            report.PlatformFacts.Add(Fact("systemd_version", manager.Version));
            report.PlatformFacts.Add(Fact("manager_address", manager.Address));
            report.PlatformFacts.Add(Fact("delegated_controllers", string.Join(' ', _controllers.Order(StringComparer.Ordinal))));
            report.PlatformFacts.Add(Fact("slice", Slice));
            if (_sliceCgroup is not null)
            {
                report.PlatformFacts.Add(Fact("slice_cgroup", _sliceCgroup));
            }
        }

        report.PlatformFacts.Add(Fact("logical_processors", Capacity.LogicalProcessors.ToString(CultureInfo.InvariantCulture)));
        report.PlatformFacts.Add(Fact("physical_memory_bytes", Capacity.PhysicalMemoryBytes.ToString(CultureInfo.InvariantCulture)));
        report.PlatformFacts.Add(Fact("linger", File.Exists("/var/lib/systemd/linger/" + Environment.UserName) ? "yes" : "no"));
        if (_nodeUnit is not null)
        {
            report.PlatformFacts.Add(Fact("node_unit", _nodeUnit));
        }

        if (_rootLimits is { } limits)
        {
            report.PlatformFacts.Add(Fact("root_cpu_rate", limits.CpuRate.ToString(CultureInfo.InvariantCulture)));
            report.PlatformFacts.Add(Fact("root_memory_max_bytes", limits.HardMemoryBytes.ToString(CultureInfo.InvariantCulture)));
            report.PlatformFacts.Add(Fact("root_memory_high_bytes", limits.NotificationBytes.ToString(CultureInfo.InvariantCulture)));
            report.PlatformFacts.Add(Fact("root_swap_max_bytes", limits.SwapAllowanceBytes.ToString(CultureInfo.InvariantCulture)));
        }

        return report;
    }

    /// <inheritdoc />
    public PreparedCommand Prepare(CommandRequest request) => LinuxCommands.Prepare(request);

    /// <inheritdoc />
    public string ContainerName(string nodeName, string attemptName) => _manager is null ? "pgid:" + attemptName : UnitName(attemptName);

    /// <inheritdoc />
    public IAttemptHandle Launch(AttemptLaunch launch)
    {
        ArgumentNullException.ThrowIfNull(launch);
        var files = launch.Files;
        Directory.CreateDirectory(files.Directory);
        Directory.CreateDirectory(files.TempDirectory);
        if (launch.Command.ScriptFile is { } scriptFile)
        {
            File.WriteAllText(scriptFile, launch.Command.ScriptContent ?? string.Empty, new UTF8Encoding(false));
        }

        HelperFiles.WriteAtomically(files.StepsPath, new StepsFile
        {
            AttemptId = files.AttemptName,
            LaunchSteps = [.. launch.LaunchSteps],
            EndSteps = [.. launch.EndSteps],
            LeftoverGraceMs = launch.LeftoverGraceMs,
            EnvironmentNames = [.. launch.Environment.Select(entry => entry[..Math.Max(0, entry.IndexOf('=', StringComparison.Ordinal))]).Distinct(StringComparer.Ordinal)],
        }.ToJson());
        if (_manager is null)
        {
            return DirectAttemptHandle.Start(this, launch);
        }

        try
        {
            return LinuxAttemptHandle.Start(this, launch);
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException)
        {
            throw new IOException("The systemd user manager did not start the attempt unit: " + OneLine(exception.Message), exception);
        }
    }

    /// <inheritdoc />
    public IAttemptHandle? Reopen(string nodeName, AttemptFiles files, RootProcess? root)
    {
        ArgumentNullException.ThrowIfNull(files);
        if (_manager is null)
        {
            return null;
        }

        try
        {
            return LinuxAttemptHandle.Reopen(this, files, root);
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException)
        {
            throw new IOException("The systemd user manager did not answer for the attempt unit: " + OneLine(exception.Message), exception);
        }
    }

    /// <summary>
    /// No holder ever waits on Linux, so this returns false; it unloads the attempt's unit when it was left failed (CollectMode=inactive
    /// keeps it until the node recorded it, and the node stopped first). The failed attempt units are listed once per sweep.
    /// </summary>
    public bool AcknowledgeRecorded(string nodeName, string attemptName)
    {
        if (_manager is null)
        {
            return false;
        }

        try
        {
            var now = Environment.TickCount64;
            if (_failedUnits is null || now - _failedUnitsAt > 10_000)
            {
                _failedUnits = Manager.FailedUnits(UnitPrefix + "*");
                _failedUnitsAt = now;
            }

            if (_failedUnits.Remove(UnitName(attemptName)))
            {
                Manager.ResetFailedUnit(UnitName(attemptName));
            }
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or InvalidOperationException)
        {
        }

        return false;
    }

    /// <summary>
    /// Starts the guard unit (13 section 3.4: <c>arcforges-guard.service</c>) when it is installed and not running; returns its state for
    /// the log: <c>active</c>, <c>started</c>, <c>not installed</c> or why it could not start.
    /// </summary>
    public string EnsureGuard(string unit)
    {
        if (_manager is null)
        {
            return "no user manager";
        }

        try
        {
            var (load, active, fragment) = Manager.LoadUnit(unit);
            if (load != "loaded" || fragment.Length == 0)
            {
                return "not installed";
            }

            if (active == "active")
            {
                return "active";
            }

            Manager.StartUnit(unit);
            return "started";
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException)
        {
            return "start failed: " + OneLine(exception.Message);
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
        lock (_gate)
        {
            _manager?.Dispose();
        }
    }

    /// <summary>The unit properties of an attempt (AD-0005 Linux section 2; 03 section 5.2; 04 section 3).</summary>
    internal List<UnitProperty> AttemptProperties(AttemptLaunch launch, string[] managerEnvironment, SafeHandle stdin, SafeHandle stdout, SafeHandle stderr)
    {
        var files = launch.Files;
        var limits = launch.Limits;
        var resolved = launch.Environment.Select(entry => entry[..Math.Max(0, entry.IndexOf('=', StringComparison.Ordinal))]).ToHashSet(StringComparer.Ordinal);
        var nofileHard = Libc.GetRLimit(Libc.RlimitNofile, out var nofile) == 0 ? nofile.Maximum : 524_288UL;
        var nofileSoft = Math.Min(DefaultNoFileSoft, nofileHard);
        List<string> start =
        [
            _helper, "node", "exec-launch", "--attempt", files.AttemptName, "--dir", files.Directory, "--cwd", launch.WorkingDirectory,
            "--program", launch.Command.Application, "--nofile", nofileSoft.ToString(CultureInfo.InvariantCulture),
        ];
        foreach (var name in ExecLaunchRole.ManagerAddedVariables.Where(name => !resolved.Contains(name)))
        {
            start.Add("--unset");
            start.Add(name);
        }

        var helperDiagnosticsOff = HelperRuntime is not null && !resolved.Contains(DiagnosticsVariable);
        if (HelperRuntime is not null && !resolved.Contains("DOTNET_ROOT"))
        {
            // A framework-dependent helper (the JIT build next to the tests) gets DOTNET_ROOT for itself only.
            start.Add("--unset");
            start.Add("DOTNET_ROOT");
        }

        if (helperDiagnosticsOff)
        {
            start.Add("--unset");
            start.Add(DiagnosticsVariable);
        }

        start.Add("--");
        start.AddRange(launch.Command.Argv);
        var properties = new List<UnitProperty>
        {
            new("Description", "ArcForges attempt " + files.AttemptName),
            new("Slice", Slice),
            new("Type", "exec"),
            new("ExecStartEx", (IReadOnlyList<ExecCommand>)[HelperCommand(start, false, helperDiagnosticsOff)]),
            new("ExecStopEx", (IReadOnlyList<ExecCommand>)[HelperCommand([_helper, "node", "exec-stop", "--attempt", files.AttemptName, "--dir", files.Directory], true,
                helperDiagnosticsOff)]),
            new("ExecStopPostEx", (IReadOnlyList<ExecCommand>)[HelperCommand([_helper, "node", "exit-record", "--attempt", files.AttemptName, "--dir", files.Directory], false,
                helperDiagnosticsOff)]),
            // Every exit status and signal is a success of the unit, so ExecStop (the end steps) runs after any exit; the attempt's result
            // is taken from $EXIT_CODE and $EXIT_STATUS by exit-record (04 section 3).
            new("SuccessExitStatus", new ExitStatusSet([.. Enumerable.Range(1, 255)],
                [.. Enumerable.Range(1, 31), .. Enumerable.Range(Libc.SigRtMin, Libc.SigRtMax - Libc.SigRtMin + 1)])),
            new("WorkingDirectory", "-" + launch.WorkingDirectory),
            new("Environment", (string[])[.. UnitEnvironment(launch.Environment), .. _options.ExtraUnitEnvironment]),
            new("UnsetEnvironment", managerEnvironment.Select(entry => entry[..Math.Max(0, entry.IndexOf('=', StringComparison.Ordinal))])
                .Where(name => name.Length > 0 && !resolved.Contains(name)).Distinct(StringComparer.Ordinal).ToArray()),
            new("StandardInputFileDescriptor", stdin),
            new("StandardOutputFileDescriptor", stdout),
            new("StandardErrorFileDescriptor", stderr),
            new("LimitNOFILE", nofileHard),
            new("LimitNOFILESoft", nofileSoft),
            new("KillMode", "control-group"),
            new("TimeoutStopUSec", (ulong)(new StepsFile().EndStepBudgetMs + launch.LeftoverGraceMs + StopRecordMarginMs) * 1000),
            // Failed units stay loaded (an OOM kill while ExecStopPost runs ends exit-record too), so the node records them from the unit.
            new("CollectMode", "inactive"),
            new("IgnoreSIGPIPE", false),
            new("CPUAccounting", true),
            new("MemoryAccounting", true),
            new("TasksAccounting", true),
        };
        foreach (var (resource, name) in (ReadOnlySpan<(int, string)>)[(Libc.RlimitCore, "LimitCORE"), (Libc.RlimitStack, "LimitSTACK")])
        {
            if (Libc.GetRLimit(resource, out var limit) == 0)
            {
                properties.Add(new(name, limit.Maximum));
                properties.Add(new(name + "Soft", limit.Current));
            }
        }

        if (_controllers.Contains("cpu"))
        {
            properties.Add(new("CPUWeight", (ulong)CpuWeight(limits.CpuWeight)));
            if (limits.CpuRateCap is { } cap)
            {
                properties.Add(new("CPUQuotaPerSecUSec", (ulong)cap * (ulong)Capacity.LogicalProcessors * 100UL));
            }
        }

        if (_controllers.Contains("memory"))
        {
            if (limits.MemoryHighBytes > 0)
            {
                properties.Add(new("MemoryHigh", (ulong)limits.MemoryHighBytes));
            }

            if (limits.MemoryMaxBytes > 0)
            {
                properties.Add(new("MemoryMax", (ulong)limits.MemoryMaxBytes));
            }

            if (limits.SwapMaxBytes is { } swap)
            {
                properties.Add(new("MemorySwapMax", (ulong)swap));
            }

            // stop, never kill (AD-0005 Linux section 2, L-27): kill sets memory.oom.group, and a group kill also signals the user
            // manager's posix_spawn child while it still shares the manager's address space, which kills the user manager.
            properties.Add(new("OOMPolicy", "stop"));
        }

        if (_controllers.Contains("pids"))
        {
            properties.Add(new("TasksMax", (ulong)(limits.ActiveProcessLimit ?? limits.TasksMax)));
        }

        if (launch.KillWithNode && _nodeUnit is { } nodeUnit)
        {
            // kill_with_node: bound to the node's own unit, so it stops with the node (13 section 3.4).
            properties.Add(new("BindsTo", new[] { nodeUnit }));
            properties.Add(new("After", new[] { nodeUnit }));
        }

        return properties;
    }

    /// <summary>
    /// The .NET location a framework-dependent helper needs (the JIT build of the tests: an <c>arcforges.dll</c> beside it), or null for
    /// the Native AOT executable, which needs nothing.
    /// </summary>
    internal string? HelperRuntime => File.Exists(Path.ChangeExtension(_helper, ".dll")) ? Environment.GetEnvironmentVariable("DOTNET_ROOT") : null;

    /// <summary>
    /// A helper command line; a framework-dependent helper is started through <c>env DOTNET_ROOT=...</c>, and without the runtime's
    /// diagnostic endpoints (<c>DOTNET_EnableDiagnostics=0</c>, unless the attempt sets it), so a helper that becomes the command
    /// (<c>execve</c>) or is killed leaves no IPC socket behind in the temporary directory.
    /// </summary>
    private ExecCommand HelperCommand(List<string> argv, bool ignoreFailure, bool diagnosticsOff) => HelperRuntime is { } runtime && File.Exists("/usr/bin/env")
        ? new ExecCommand("/usr/bin/env", ["env", "DOTNET_ROOT=" + runtime, .. diagnosticsOff ? (string[])[DiagnosticsVariable + "=0"] : [], .. argv], ignoreFailure)
        : new ExecCommand(_helper, argv, ignoreFailure);

    /// <summary>
    /// The unit's <c>Environment=</c>: systemd accepts only names of letters, digits and underscores (not starting with a digit) and
    /// values without other control characters than tab and newline, so any other entry (for example a bash function
    /// <c>BASH_FUNC_x%%</c>, a name with a dash) travels in <see cref="ExecLaunchRole.CarrierVariable"/> (base64 of the NUL-separated
    /// entries), which <c>exec-launch</c> unpacks into the command's environment and removes, so the command still gets exactly the
    /// resolved environment. A caller's own variable of that name is carried the same way, and the carrier is always set (empty when
    /// nothing is carried); <c>exec-launch</c> then keeps only the resolved names (<see cref="StepsFile.EnvironmentNames"/>).
    /// </summary>
    internal static string[] UnitEnvironment(IReadOnlyList<string> environment)
    {
        var accepted = new List<string>();
        var carried = new List<string>();
        foreach (var entry in environment)
        {
            (SystemdAccepts(entry) ? accepted : carried).Add(entry);
        }

        // Always set, empty when nothing is carried: a carrier variable of the user manager's own never reaches exec-launch.
        accepted.Add(ExecLaunchRole.CarrierVariable + "="
            + (carried.Count == 0 ? string.Empty : Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join('\0', carried)))));
        return [.. accepted];
    }

    private static bool SystemdAccepts(string entry)
    {
        var equals = entry.IndexOf('=', StringComparison.Ordinal);
        if (equals <= 0 || char.IsAsciiDigit(entry[0]))
        {
            return false;
        }

        // A caller's own variable with the carrier's name travels inside the carrier, like any entry systemd refuses.
        if (entry.AsSpan(0, equals).SequenceEqual(ExecLaunchRole.CarrierVariable))
        {
            return false;
        }

        for (var index = 0; index < equals; index++)
        {
            if (!(char.IsAsciiLetterOrDigit(entry[index]) || entry[index] == '_'))
            {
                return false;
            }
        }

        for (var index = equals + 1; index < entry.Length; index++)
        {
            var character = entry[index];
            if (char.IsHighSurrogate(character) && index + 1 < entry.Length && char.IsLowSurrogate(entry[index + 1]))
            {
                index++;
                continue;
            }

            // A lone surrogate is not valid UTF-8; other control characters than tab and newline are refused.
            if (char.IsSurrogate(character) || (char.IsControl(character) && character is not ('\t' or '\n')))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>The <c>CPUWeight</c> of a priority weight (03 section 5.2: 9, 7, 5, 3, 1 to 400, 200, 100, 50, 10).</summary>
    public static int CpuWeight(int weight) => weight switch
    {
        >= 9 => 400,
        >= 7 => 200,
        >= 5 => 100,
        >= 3 => 50,
        _ => 10,
    };

    /// <summary>The node's own systemd unit, from its cgroup (<c>.../user@uid.service/app.slice/&lt;unit&gt;.service</c>), or null.</summary>
    public static string? OwnUnit()
    {
        var cgroup = ProcFs.OwnCgroup();
        if (cgroup is null || !cgroup.Contains("/user@", StringComparison.Ordinal))
        {
            return null;
        }

        var last = cgroup[(cgroup.LastIndexOf('/') + 1)..];
        return last.EndsWith(".service", StringComparison.Ordinal) && !last.StartsWith("user@", StringComparison.Ordinal) ? last : null;
    }

    internal static string OneLine(string text) => text.ReplaceLineEndings(" ");

    private List<UnitProperty> SliceProperties(RootLimits limits)
    {
        var properties = new List<UnitProperty>();
        if (_controllers.Contains("cpu"))
        {
            properties.Add(new("CPUQuotaPerSecUSec", (ulong)Math.Clamp(limits.CpuRate, 100, 10_000) * (ulong)Capacity.LogicalProcessors * 100UL));
        }

        if (_controllers.Contains("memory"))
        {
            if (limits.NotificationBytes > 0)
            {
                properties.Add(new("MemoryHigh", (ulong)limits.NotificationBytes));
            }

            if (limits.HardMemoryBytes > 0)
            {
                properties.Add(new("MemoryMax", (ulong)limits.HardMemoryBytes));
            }

            properties.Add(new("MemorySwapMax", (ulong)Math.Max(0, limits.SwapAllowanceBytes)));
        }

        if (_controllers.Contains("pids"))
        {
            properties.Add(new("TasksMax", (ulong)limits.TasksMax));
        }

        return properties;
    }

    /// <summary>
    /// The slice exists as a unit file (13 section 3.4: its limits are then runtime properties) or as a transient slice the node creates
    /// with its limits; either way it is started and carries the root limits.
    /// </summary>
    private void EnsureSlice(RootLimits limits)
    {
        _rootLimits = limits;
        var manager = Manager;
        var (_, active, fragment) = manager.LoadUnit(Slice);
        if (fragment.Length == 0)
        {
            try
            {
                var job = manager.StartTransientUnit(Slice, [new("Description", "ArcForges managed executions"), .. SliceProperties(limits)]);
                manager.WaitJob(job, TimeSpan.FromSeconds(10));
                return;
            }
            catch (DBusErrorReplyException)
            {
                // An implicit slice already in use (a parent of another slice, or referenced by a unit): runtime properties below.
            }
        }

        manager.SetUnitProperties(Slice, runtime: true, SliceProperties(limits));
        if (active != "active")
        {
            manager.WaitJob(manager.StartUnit(Slice), TimeSpan.FromSeconds(10));
        }
    }

    /// <summary>
    /// The startup probe (02 section 2 step 6): a short unit in the slice with known limits; its cgroup files must carry them, and the
    /// slice's own files the root limits. Returns null when enforcement is verified, otherwise why not.
    /// </summary>
    private string? Probe()
    {
        var sleep = File.Exists("/usr/bin/sleep") ? "/usr/bin/sleep" : File.Exists("/bin/sleep") ? "/bin/sleep" : null;
        if (sleep is null)
        {
            return "the probe unit needs /usr/bin/sleep, which is missing";
        }

        var manager = Manager;
        var name = "arcforges-probe-" + _nodeName[..Math.Min(12, _nodeName.Length)].ToLowerInvariant() + "-" + Guid.NewGuid().ToString("N")[..8] + ".service";
        var properties = new List<UnitProperty>
        {
            new("Description", "ArcForges enforcement probe"),
            new("Slice", Slice),
            new("Type", "exec"),
            new("ExecStartEx", (IReadOnlyList<ExecCommand>)[new ExecCommand(sleep, [sleep, "3"], false)]),
            new("CollectMode", "inactive-or-failed"),

            // A node that dies during its startup leaves no probe behind for long.
            new("RuntimeMaxUSec", 3_000_000UL),
        };
        if (_controllers.Contains("cpu"))
        {
            properties.Add(new("CPUWeight", 400UL));
        }

        if (_controllers.Contains("memory"))
        {
            properties.Add(new("MemoryMax", 64UL << 20));
            properties.Add(new("MemoryHigh", 48UL << 20));
        }

        if (_controllers.Contains("pids"))
        {
            properties.Add(new("TasksMax", 64UL));
        }

        var job = manager.StartTransientUnit(name, properties);
        try
        {
            if (manager.WaitJob(job, TimeSpan.FromSeconds(10)) is not "done")
            {
                return "the probe unit did not start";
            }

            var state = manager.State(name);
            if (state is null || state.ControlGroup.Length == 0)
            {
                return "the probe unit has no cgroup";
            }

            var unit = ProcFs.CgroupDirectory(state.ControlGroup);
            _sliceCgroup = Path.GetDirectoryName(state.ControlGroup);
            _freezer = File.Exists(Path.Combine(unit, "cgroup.freeze"));
            var slice = ProcFs.CgroupDirectory(_sliceCgroup!);
            var failures = new List<string>();
            void Expect(string directory, string file, string expected)
            {
                var actual = ProcFs.Text(Path.Combine(directory, file));
                if (!string.Equals(actual, expected, StringComparison.Ordinal))
                {
                    failures.Add($"{Path.GetFileName(directory)}/{file} is '{actual ?? "missing"}', not '{expected}'");
                }
            }

            if (_controllers.Contains("cpu"))
            {
                Expect(unit, "cpu.weight", "400");
                var quota = (ulong)Math.Clamp(_rootLimits!.CpuRate, 100, 10_000) * (ulong)Capacity.LogicalProcessors * 10UL;
                Expect(slice, "cpu.max", quota.ToString(CultureInfo.InvariantCulture) + " 100000");
            }

            if (_controllers.Contains("memory"))
            {
                Expect(unit, "memory.max", (64L << 20).ToString(CultureInfo.InvariantCulture));
                Expect(unit, "memory.high", (48L << 20).ToString(CultureInfo.InvariantCulture));
                if (_rootLimits!.HardMemoryBytes > 0)
                {
                    Expect(slice, "memory.max", PageAligned(_rootLimits.HardMemoryBytes));
                }

                if (File.Exists(Path.Combine(slice, "memory.swap.max")))
                {
                    Expect(slice, "memory.swap.max", PageAligned(_rootLimits.SwapAllowanceBytes));
                }
            }

            if (_controllers.Contains("pids"))
            {
                Expect(unit, "pids.max", "64");
                Expect(slice, "pids.max", _rootLimits!.TasksMax.ToString(CultureInfo.InvariantCulture));
            }

            return failures.Count == 0 ? null : "the probe unit's limits did not take effect: " + string.Join("; ", failures);
        }
        finally
        {
            try
            {
                manager.StopUnit(name);
            }
            catch (DBusErrorReplyException)
            {
            }
        }
    }

    private static string PageAligned(long bytes) => (bytes - (bytes % Environment.SystemPageSize)).ToString(CultureInfo.InvariantCulture);

    private static HashSet<string> ReadControllers(SystemdManager manager)
    {
        var controllers = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            var cgroup = manager.ManagerString("ControlGroup");
            if (ProcFs.Text(Path.Combine(ProcFs.CgroupDirectory(cgroup), "cgroup.controllers")) is { } text)
            {
                controllers.UnionWith(text.Split(' ', StringSplitOptions.RemoveEmptyEntries));
            }
        }
        catch (DBusErrorReplyException)
        {
        }

        return controllers;
    }

    private static KeyValue Fact(string name, string value) => new() { Name = name, Value = value };
}
