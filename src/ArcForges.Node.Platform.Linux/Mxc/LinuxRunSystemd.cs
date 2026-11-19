// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.Node.Platform.Linux.Mxc;

internal sealed record LinuxRunServiceState(string Name, string Invocation, string Boot, string Group, int OwnerPid,
    long OwnerStartTicks, string ActiveState, string SubState, string Result, int ExecCode, int ExecStatus, bool Loaded);

[SupportedOSPlatform("linux")]
internal static class LinuxRunSystemd
{
    private const string SystemdRun = "/usr/bin/systemd-run";
    private const string Systemctl = "/usr/bin/systemctl";
    private const string Env = "/usr/bin/env";
    private const string ToolPath = "/usr/bin:/bin:/usr/sbin:/sbin";
    private static readonly string[] s_showProperties = ["Id", "Description", "LoadState", "ActiveState", "SubState",
        "Result", "Type", "Delegate", "KillMode", "Restart", "Transient", "InvocationID", "ControlGroup", "MainPID",
        "ExecMainCode", "ExecMainStatus"];

    internal static void RequireLimits(uint cpu, ulong memory, uint maxProcesses, uint? cpuWeight, LinuxRunLimits observed)
    {
        if (observed.CpuQuota != 100UL * cpu || observed.CpuPeriod != 100_000 || observed.MemoryBytes != memory ||
            observed.SwapBytes != 0 || observed.Tasks != maxProcesses || (cpuWeight.HasValue && observed.CpuWeight != cpuWeight.Value))
        {
            throw new IOException("Native cgroup resource readback differs from the Run request.");
        }
    }

    internal static async Task StartAsync(string unit, string executable, string installation, string manifest,
        uint cpu, ulong memory, uint maxProcesses, uint? cpuWeight)
    {
        LinuxRunCgroup.RequireTrustedTool(SystemdRun);
        LinuxRunCgroup.RequireTrustedTool(Systemctl);
        LinuxRunCgroup.RequireTrustedTool(Env);
        ValidateServicePath(executable);
        ValidateServicePath(installation);
        ValidateServicePath(manifest);
        if (LinuxRunCgroup.NormalizeRunLimit(RunResourceDimension.Cpu, cpu) != cpu
            || LinuxRunCgroup.NormalizeRunLimit(RunResourceDimension.Memory, memory) != memory
            || LinuxRunCgroup.NormalizeRunLimit(RunResourceDimension.ProcessCount, maxProcesses) != maxProcesses
            || (cpuWeight.HasValue && LinuxRunCgroup.NormalizeRunLimit(RunResourceDimension.CpuWeight, cpuWeight.Value) != cpuWeight))
        {
            throw new IOException("Required finite Run resource limits are unavailable.");
        }

        var previous = await ReadAsync(unit, CancellationToken.None).ConfigureAwait(false);
        if (previous.Loaded)
        {
            throw new IOException("A Run unit already exists.");
        }

        var properties = new List<string>
        {
            "--user", "--no-block", "--quiet", "--service-type=exec", "--expand-environment=no",
            "--unit=" + unit, "--description=" + Description(unit),
            "--property=Delegate=yes", "--property=KillMode=control-group", "--property=Restart=no",
            "--property=RemainAfterExit=no", "--property=SendSIGKILL=yes", "--property=TimeoutStopSec=5s",
            "--property=UMask=0077",
            // This applies before the dynamic loader for the fixed env executable runs.
            "--property=UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_PROFILE GCONV_PATH LOCPATH GLIBC_TUNABLES",
            "--property=CPUAccounting=yes", "--property=MemoryAccounting=yes",
            "--property=TasksAccounting=yes", "--property=CPUQuotaPeriodSec=100ms", "--property=MemorySwapMax=0",
            "--property=StandardInput=null", "--property=StandardOutput=null", "--property=StandardError=journal",
            "--property=CPUQuota=" + (cpu / 10m).ToString("0.###", CultureInfo.InvariantCulture) + "%",
            "--property=MemoryMax=" + memory.ToString(CultureInfo.InvariantCulture),
            "--property=TasksMax=" + maxProcesses.ToString(CultureInfo.InvariantCulture),
            "--working-directory=" + installation,
        };
        if (cpuWeight is { } weight)
        {
            properties.Add("--property=CPUWeight=" + weight.ToString(CultureInfo.InvariantCulture));
        }

        properties.AddRange(["--", Env, "-i", "PATH=" + ToolPath, "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
            "DOTNET_EnableDiagnostics=0", "HOME=" + Path.GetDirectoryName(manifest),
            "TMPDIR=" + Path.GetDirectoryName(manifest), "XDG_RUNTIME_DIR=" + RuntimeDirectory(),
            executable, "--run-control", manifest]);
        var result = await RunCommandAsync(SystemdRun, properties, CancellationToken.None).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw new RunNativeException("start_linux_service", "systemd_run_exit_" +
                result.ExitCode.ToString(CultureInfo.InvariantCulture));
        }
    }

    internal static async Task<LinuxRunServiceState> ReadAsync(string unit, CancellationToken cancellationToken)
    {
        ValidateUnit(unit);
        var boot = LinuxRunCgroup.BootId();
        var result = await RunCommandAsync(Systemctl, ["--user", "--no-pager", "show", "--property=" +
            string.Join(',', s_showProperties), "--", unit], cancellationToken).ConfigureAwait(false);
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var split = line.IndexOf('=');
            if (split <= 0 || !fields.TryAdd(line[..split], line[(split + 1)..].TrimEnd('\r')))
            {
                throw new IOException("The user manager returned invalid Run service state.");
            }
        }

        string Field(string name) => fields.GetValueOrDefault(name, "");
        int Number(string name) => int.TryParse(Field(name), NumberStyles.None, CultureInfo.InvariantCulture, out var value)
            ? value : 0;

        if (Field("LoadState") == "not-found")
        {
            return new(unit, "", boot, "", 0, 0, "inactive", "dead", "", 0, 0, false);
        }

        if (result.ExitCode != 0 || Field("LoadState") != "loaded" || Field("Id") != unit ||
            Field("Transient") != "yes" || Field("Description") != Description(unit) ||
            Field("Type") != "exec" || Field("Delegate") != "yes" ||
            Field("KillMode") != "control-group" || Field("Restart") != "no")
        {
            throw new IOException("The user manager did not observe the requested Run service identity and lifecycle.");
        }

        var pid = Number("MainPID");
        var start = pid > 0 && ProcFs.Stat(pid) is { State: not ('Z' or 'X') } process ? process.StartTicks : 0;
        return new(unit, Field("InvocationID"), boot, Field("ControlGroup"), pid, start, Field("ActiveState"),
            Field("SubState"), Field("Result"), Number("ExecMainCode"), Number("ExecMainStatus"), true);
    }

    internal static async Task<(LinuxRunServiceState State, LinuxRunCgroup Scope)> WaitForReadyAsync(string unit, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        do
        {
            var state = await ReadAsync(unit, deadline.Token).ConfigureAwait(false);
            if (state.ActiveState == "active" && state.SubState == "running")
            {
                return (state, OpenOwnerScope(state));
            }

            if (state.Loaded && (state.ActiveState == "failed" || (state.ActiveState == "inactive" && state.ExecCode != 0)))
            {
                throw new RunNativeException("start_linux_service", string.Create(CultureInfo.InvariantCulture,
                    $"systemd_service_{state.Result}_{state.ExecCode}_{state.ExecStatus}"));
            }

            await Task.Delay(25, deadline.Token).ConfigureAwait(false);
        }
        while (!deadline.IsCancellationRequested);

        throw new IOException("The trusted Run supervisor did not become ready.");
    }

    internal static LinuxRunCgroup OpenOwnerScope(LinuxRunServiceState state)
    {
        if (!Guid.TryParseExact(state.Invocation, "N", out _) || state.OwnerPid <= 0 || state.OwnerStartTicks <= 0
            || !state.Group.EndsWith('/' + state.Name, StringComparison.Ordinal) ||
            !LinuxRunCgroup.MatchesProcess(state.OwnerPid, state.OwnerStartTicks, state.Group))
        {
            throw new IOException("The trusted Run supervisor is not bound to its expected cgroup.");
        }

        return LinuxRunCgroup.Open(state.Group);
    }

    internal static async Task StopAsync(LinuxRunServiceState original, LinuxRunCgroup scope, CancellationToken cancellationToken)
    {
        if (scope.IsEmpty())
        {
            return;
        }

        var current = await ReadAsync(original.Name, cancellationToken).ConfigureAwait(false);
        if (scope.IsEmpty())
        {
            return;
        }

        RequireSameGeneration(original, current);
        await StopUnitAsync(original.Name, cancellationToken).ConfigureAwait(false);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        while (!scope.IsEmpty())
        {
            var state = await ReadAsync(original.Name, deadline.Token).ConfigureAwait(false);
            if (!scope.IsEmpty())
            {
                RequireSameGeneration(original, state);
                await Task.Delay(25, deadline.Token).ConfigureAwait(false);
            }
        }
    }

    internal static async Task<bool> RollbackUnreleasedAsync(string unit)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        try
        {
            var state = await ReadAsync(unit, deadline.Token).ConfigureAwait(false);
            if (!state.Loaded)
            {
                return true;
            }

            if (state.Group.Length == 0)
            {
                return state.OwnerPid == 0 && state.ActiveState is "failed" or "inactive";
            }

            if (!state.Group.EndsWith('/' + unit, StringComparison.Ordinal))
            {
                return false;
            }

            using var scope = LinuxRunCgroup.Open(state.Group);
            await StopAsync(state, scope, deadline.Token).ConfigureAwait(false);
            return scope.IsEmpty();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or OperationCanceledException or Win32Exception or InvalidOperationException)
        {
            return false;
        }
    }

    private static void RequireSameGeneration(LinuxRunServiceState original, LinuxRunServiceState current)
    {
        if (current.Boot != original.Boot || !current.Loaded || original.Invocation.Length != 32 ||
            current.Invocation != original.Invocation || current.Group != original.Group ||
            (current.OwnerPid != 0 && (current.OwnerPid != original.OwnerPid || current.OwnerStartTicks != original.OwnerStartTicks ||
            !LinuxRunCgroup.MatchesProcess(current.OwnerPid, current.OwnerStartTicks, original.Group))))
        {
            throw new IOException("The original native Run service can no longer be identified.");
        }
    }

    private static async Task StopUnitAsync(string unit, CancellationToken cancellationToken)
    {
        var result = await RunCommandAsync(Systemctl, ["--user", "--no-pager", "--no-block", "stop", "--", unit],
            cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw new RunNativeException("stop_linux_service", "systemctl_stop_exit_" +
                result.ExitCode.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static string Description(string unit) => "ArcForges V2 Run " + unit;

    private static void ValidateUnit(string unit)
    {
        if (!unit.StartsWith("arcforges-run-", StringComparison.Ordinal) || !unit.EndsWith(".service", StringComparison.Ordinal)
            || unit.Length != 54 || !Guid.TryParseExact(unit[14..^8], "N", out _))
        {
            throw new IOException("The Run service name is invalid.");
        }
    }

    private static void ValidateServicePath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.IndexOfAny(['\0', '\r', '\n', '%', '$']) >= 0)
        {
            throw new IOException("A protected Run path cannot be passed literally to systemd.");
        }
    }

    private static string RuntimeDirectory()
    {
        var directory = "/run/user/" + LinuxRunCgroup.UserId.ToString(CultureInfo.InvariantCulture);
        LinuxRunCgroup.RequirePrivateRuntime(directory);
        return directory;
    }

    private static async Task<(int ExitCode, string Output)> RunCommandAsync(string executable, IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        LinuxRunCgroup.RequireTrustedTool(executable);
        var runtime = RuntimeDirectory();
        var settings = new ProcessStartInfo(executable)
        {
            WorkingDirectory = "/",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        settings.Environment.Clear();
        settings.Environment.Add("LANG", "C.UTF-8");
        settings.Environment.Add("LC_ALL", "C.UTF-8");
        settings.Environment.Add("PATH", ToolPath);
        settings.Environment.Add("XDG_RUNTIME_DIR", runtime);
        settings.Environment.Add("DBUS_SESSION_BUS_ADDRESS", "unix:path=" + runtime + "/bus");
        foreach (var argument in arguments)
        {
            settings.ArgumentList.Add(argument);
        }

        using var process = Process.Start(settings) ?? throw new IOException("The fixed user manager command did not start.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(8));
        var output = ReadBoundedAsync(process.StandardOutput, deadline.Token);
        var error = ReadBoundedAsync(process.StandardError, deadline.Token);
        try
        {
            await Task.WhenAll(process.WaitForExitAsync(deadline.Token), output, error).ConfigureAwait(false);
            return (process.ExitCode, output.Result);
        }
        finally
        {
            if (!process.HasExited)
            {
                try
                {
                    process.Kill();
                    await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(1), CancellationToken.None).ConfigureAwait(false);
                }
                catch (InvalidOperationException) when (process.HasExited) { }
                catch (TimeoutException) { }
            }
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var buffer = new char[65_537];
        var read = await reader.ReadBlockAsync(buffer, cancellationToken).ConfigureAwait(false);
        return read > 65_536 ? throw new IOException("A user manager response exceeded its bound.") : new string(buffer, 0, read);
    }
}
