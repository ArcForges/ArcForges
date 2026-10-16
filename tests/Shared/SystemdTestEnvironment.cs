// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;

namespace ArcForges.Tests;

/// <summary>
/// The systemd user manager as the Linux tests meet it (16 section 4: each test node gets its own slice <c>arcforges-test-&lt;id&gt;.slice</c>,
/// and a fixture removes the units, slices, files and processes a test created and fails the test when any was left running). Linked into
/// every test project from <c>tests/Directory.Build.props</c>; everything here does nothing on Windows.
/// </summary>
internal static class SystemdTestEnvironment
{
    /// <summary>The parent of every test slice (the dash in a slice name nests it under this one).</summary>
    public const string TestParentSlice = "arcforges-test.slice";

    private static readonly Lazy<HashSet<string>> s_controllers = new(ReadControllers);
    private static readonly string[] DropInRoots = ["user.control", "user"];

    static SystemdTestEnvironment()
    {
        if (OperatingSystem.IsLinux())
        {
            // Workloads and helpers the tests kill (the JIT builds next to the tests) would leave the runtime's diagnostic endpoints in
            // /tmp; the processes this test process starts from now on run without them (its own endpoints are set up already).
            Environment.SetEnvironmentVariable("DOTNET_EnableDiagnostics", "0");
        }
    }

    /// <summary>True when a systemd user manager runs for this user (its private socket exists) and <c>systemctl</c> is installed.</summary>
    public static bool UserManagerAvailable => OperatingSystem.IsLinux() && PrivateSocket() is not null
        && (File.Exists("/usr/bin/systemctl") || File.Exists("/bin/systemctl"));

    /// <summary>The controllers delegated to the user manager (<c>cgroup.controllers</c> of <c>user@&lt;uid&gt;.service</c>).</summary>
    public static IReadOnlySet<string> Controllers => s_controllers.Value;

    /// <summary>True when the Linux platform enforces (a user manager with cpu, memory and pids delegated): the node is READY, not DEGRADED.</summary>
    public static bool FullyEnforced => UserManagerAvailable && Controllers.Contains("cpu") && Controllers.Contains("memory") && Controllers.Contains("pids");

    /// <summary>The reason a test that needs enforcing units skips, or null when it can run.</summary>
    public static string? SkipReason => !OperatingSystem.IsLinux()
        ? "Linux transient units."
        : !UserManagerAvailable
            ? "requires-user-manager: no systemd user manager runs for this user."
            : !FullyEnforced ? $"requires-delegation: the user manager delegates only '{string.Join(' ', Controllers)}' (cpu, memory and pids are needed)." : null;

    /// <summary>A new test slice name.</summary>
    public static string NewSlice() => "arcforges-test-" + Guid.NewGuid().ToString("N")[..12] + ".slice";

    /// <summary>The unit name of an attempt.</summary>
    public static string AttemptUnit(string attemptName) => "arcforges-a-" + attemptName + ".service";

    /// <summary>The user manager's private socket, or null.</summary>
    public static string? PrivateSocket()
    {
        var runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        if (string.IsNullOrEmpty(runtime))
        {
            return null;
        }

        var socket = Path.Combine(runtime, "systemd", "private");
        return File.Exists(socket) ? socket : null;
    }

    /// <summary>Runs <c>systemctl --user &lt;args&gt;</c> (bounded to 30 s); returns (exit code, standard output).</summary>
    public static (int ExitCode, string Output) Systemctl(params string[] arguments)
    {
        var start = new ProcessStartInfo("systemctl") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        start.ArgumentList.Add("--user");
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromSeconds(30)))
        {
            process.Kill();
            throw new TimeoutException("systemctl --user " + string.Join(' ', arguments) + " did not finish within 30 s.");
        }

        return (process.ExitCode, output.Result + error.Result);
    }

    /// <summary>A unit property (<c>systemctl --user show -P</c>), or empty.</summary>
    public static string Property(string unit, string property) => Systemctl("show", "-P", property, unit).Output.Trim();

    /// <summary>
    /// A unit property that must be set: a failed <c>systemctl</c> or an empty value fails the test with the unit's state
    /// (<see cref="Describe"/>) and <paramref name="context"/> (what the test knows, such as its task's result).
    /// </summary>
    public static string RequiredProperty(string unit, string property, string? context = null)
    {
        var (exitCode, output) = Systemctl("show", "-P", property, unit);
        var value = output.Trim();
        if (exitCode != 0 || value.Length == 0)
        {
            Xunit.Assert.Fail($"{property} of {unit} is empty (systemctl exit {exitCode.ToString(CultureInfo.InvariantCulture)}: '{value}'); {Describe(unit)}"
                + (context is null ? string.Empty : "; " + context));
        }

        return value;
    }

    /// <summary>The state of a unit for a failure message: its load, active and sub states, result, cgroup and main process.</summary>
    public static string Describe(string unit)
    {
        var (exitCode, output) = Systemctl("show", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "Result", "-p", "ControlGroup", "-p", "MainPID",
            "-p", "NeedDaemonReload", "-p", "InvocationID", unit);
        return $"{unit} (systemctl exit {exitCode.ToString(CultureInfo.InvariantCulture)}): {string.Join("; ", output.Split('\n', StringSplitOptions.RemoveEmptyEntries))}";
    }

    /// <summary>The cgroup directory of a loaded unit, or null.</summary>
    public static string? CgroupDirectory(string unit) =>
        Property(unit, "ControlGroup") is { Length: > 0 } cgroup ? "/sys/fs/cgroup" + cgroup : null;

    /// <summary>
    /// Removes what a test's node created in the user manager: every attempt unit of <paramref name="attempts"/> (reported when still
    /// active: an attempt the test left running), stopped and reset; the slice (stopped; its runtime drop-ins removed); and the extra units
    /// the test installed. Returns the leftovers found. The shared parents (<c>arcforges-test.slice</c>, <c>arcforges.slice</c>) stay: tests
    /// run in parallel, and stopping a parent would stop the slice of a test that starts at that moment (an empty slice runs nothing).
    /// </summary>
    public static List<string> Cleanup(string slice, IEnumerable<string> attempts, IEnumerable<string>? extraUnits = null)
    {
        var leftovers = new List<string>();
        if (!OperatingSystem.IsLinux() || !UserManagerAvailable)
        {
            return leftovers;
        }

        // A frozen cgroup must be thawed before anything in it is killed: the manager spawns ExecStop into the cgroup once the main process is
        // gone, and a spawn into a frozen cgroup blocks the whole user manager until the cgroup is thawed.
        if (CgroupDirectory(slice) is { } frozenSlice && Directory.Exists(frozenSlice))
        {
            foreach (var freeze in Directory.EnumerateFiles(frozenSlice, "cgroup.freeze", SearchOption.AllDirectories))
            {
                if (File.ReadAllText(freeze).Trim() == "1")
                {
                    leftovers.Add($"frozen cgroup {Path.GetDirectoryName(freeze)}");
                    using var handle = File.OpenHandle(freeze, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                    RandomAccess.Write(handle, "0"u8, 0);
                }
            }
        }

        foreach (var unit in attempts.Select(AttemptUnit))
        {
            var state = Property(unit, "ActiveState");
            for (var wait = 0; wait < 100 && state is "deactivating"; wait++)
            {
                // ExecStop and ExecStopPost are still running (the exit record may already be written): let them finish.
                Thread.Sleep(100);
                state = Property(unit, "ActiveState");
            }

            if (state is "active" or "activating" or "deactivating" or "reloading")
            {
                leftovers.Add($"unit {unit} ({state})");
                Systemctl("kill", "--kill-whom=all", "--signal=KILL", unit);
                Systemctl("stop", unit);
            }

            Systemctl("reset-failed", unit);
        }

        foreach (var unit in extraUnits ?? [])
        {
            Systemctl("stop", unit);
            Systemctl("reset-failed", unit);
        }

        if (CgroupDirectory(slice) is { } sliceDirectory && Directory.Exists(sliceDirectory))
        {
            foreach (var procs in Directory.EnumerateFiles(sliceDirectory, "cgroup.procs", SearchOption.AllDirectories))
            {
                var pids = File.ReadAllText(procs).Split('\n', StringSplitOptions.RemoveEmptyEntries);

                // A node killed during its startup leaves its enforcement probe (sleep 3, RuntimeMaxSec 3 s) to end by itself.
                if (pids.Length > 0 && !Path.GetFileName(Path.GetDirectoryName(procs)!).StartsWith("arcforges-probe-", StringComparison.Ordinal))
                {
                    leftovers.Add($"processes {string.Join(' ', pids)} in {Path.GetDirectoryName(procs)}");
                }
            }
        }

        Systemctl("stop", slice);
        Systemctl("reset-failed", slice);
        var runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        if (!string.IsNullOrEmpty(runtime))
        {
            // No daemon-reload: the stopped slice is unloaded once unreferenced and its name is never used again. A reload stalls the
            // manager for every test running beside this one (a concurrent node connecting to it, or starting an attempt unit).
            foreach (var directory in DropInRoots.Select(kind => Path.Combine(runtime, "systemd", kind, slice + ".d")))
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
        }

        return leftovers;
    }

    private static HashSet<string> ReadControllers()
    {
        var controllers = new HashSet<string>(StringComparer.Ordinal);
        if (!OperatingSystem.IsLinux())
        {
            return controllers;
        }

        try
        {
            var uid = File.ReadAllLines("/proc/self/status").First(line => line.StartsWith("Uid:", StringComparison.Ordinal))
                .Split('\t', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)[1];
            var path = string.Create(CultureInfo.InvariantCulture, $"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers");
            if (File.Exists(path))
            {
                controllers.UnionWith(File.ReadAllText(path).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
        }

        return controllers;
    }
}
