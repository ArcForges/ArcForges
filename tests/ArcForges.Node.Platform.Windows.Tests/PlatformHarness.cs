// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>The executables under test: <c>ARCFORGES_HOST_PATH</c> / <c>ARCFORGES_TESTLOAD_PATH</c>, or the JIT builds next to the tests.</summary>
internal static class TestPrograms
{
    public static string Host { get; } = Binary("ARCFORGES_HOST_PATH", "arcforges");

    public static string TestLoad { get; } = Binary("ARCFORGES_TESTLOAD_PATH", "arcforges-testload");

    private static string Binary(string variable, string name)
    {
        if (Environment.GetEnvironmentVariable(variable) is { Length: > 0 } configured)
        {
            return Path.IsPathFullyQualified(configured) && File.Exists(configured)
                ? configured
                : throw new FileNotFoundException($"{variable} must be the absolute path of an existing {name} executable.", configured);
        }

        var path = Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? name + ".exe" : name);
        return File.Exists(path) ? path : throw new FileNotFoundException($"{name} is missing next to the tests.", path);
    }
}

/// <summary>
/// A real Windows execution platform for one test: its own node name (so job names never collide), root job and data root. It launches
/// attempts through real holders and, when disposed, terminates every attempt job, acknowledges the holders, waits for them to exit,
/// and fails the test when a holder or any process it saw in a job is still running (16 section 4).
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed partial class PlatformHarness : IDisposable
{
    private readonly List<WindowsAttemptHandle> _handles = [];
    private readonly HashSet<ArcForges.Tests.ProcessIdentity> _seen = [];

    private PlatformHarness(string root, RootLimits limits)
    {
        Root = root;
        DataRoot = Path.Combine(root, "data");
        Directory.CreateDirectory(DataRoot);
        NodeName = "t" + Guid.NewGuid().ToString("N")[..20];
        Platform = new WindowsExecutionPlatform();
        Platform.Start(NodeName, limits, TestPrograms.Host);
    }

    public string Root { get; }

    public string DataRoot { get; }

    public string NodeName { get; }

    public WindowsExecutionPlatform Platform { get; }

    /// <summary>Generous root limits (half the machine's CPU, 16 GiB commit) unless a test sets its own.</summary>
    public static PlatformHarness Start(RootLimits? limits = null) =>
        new(Directory.CreateTempSubdirectory("arcforges-platform-").FullName, limits ?? new RootLimits(5_000, 16L << 30, 16L << 30));

    public AttemptFiles Files(out string name)
    {
        name = "a" + Guid.NewGuid().ToString("N")[..24];
        return new AttemptFiles(DataRoot, name);
    }

    /// <summary>Launches <paramref name="argv"/> (resolved like the node does) in a new attempt.</summary>
    public WindowsAttemptHandle Launch(IReadOnlyList<string> argv, ContainerLimits? limits = null, IReadOnlyList<StepSpec>? launchSteps = null,
        IReadOnlyList<StepSpec>? endSteps = null, bool killWithNode = false, string? workingDirectory = null, int leftoverGraceMs = 5_000,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        var files = Files(out _);
        var env = environment ?? Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(entry => (string)entry.Key, entry => (string?)entry.Value ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        var cwd = workingDirectory ?? Root;
        var prepared = Platform.Prepare(new CommandRequest { Argv = argv, WorkingDirectory = cwd, Environment = env, TempDirectory = files.TempDirectory });
        var handle = (WindowsAttemptHandle)Platform.Launch(new AttemptLaunch
        {
            NodeName = NodeName,
            Files = files,
            Command = prepared,
            Environment = [.. env.Select(pair => pair.Key + "=" + pair.Value)],
            WorkingDirectory = cwd,
            Limits = limits ?? new ContainerLimits(),
            KillWithNode = killWithNode,
            LaunchSteps = launchSteps ?? [],
            EndSteps = endSteps ?? [],
            LeftoverGraceMs = leftoverGraceMs,
        });
        _handles.Add(handle);
        return handle;
    }

    /// <summary>A step that runs <paramref name="argv"/> (an absolute program).</summary>
    public static StepSpec Step(string name, params string[] argv) => new()
    {
        Name = name,
        Application = argv[0],
        CommandLine = WindowsCommandLine.Build(argv),
        TimeoutMs = 30_000,
    };

    /// <summary>Waits for the attempt's exit record (bounded).</summary>
    public ExitRecord WaitExit(WindowsAttemptHandle handle, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < timeout)
        {
            Track(handle);
            if (handle.TryReadExit() is { } exit)
            {
                return exit;
            }

            Thread.Sleep(50);
        }

        throw new TimeoutException($"No exit record for {handle.Files.AttemptName} within {timeout.TotalSeconds:0} s.");
    }

    /// <summary>Remembers the processes of an attempt's job, so a leftover is found at the end.</summary>
    public void Track(WindowsAttemptHandle handle)
    {
        try
        {
            foreach (var process in handle.Processes())
            {
                if (ArcForges.Tests.ProcessIdentity.Capture(process.Pid) is { } identity)
                {
                    _seen.Add(identity);
                }
            }
        }
        catch (ObjectDisposedException)
        {
        }
    }

    /// <summary>Waits for <paramref name="condition"/> (bounded).</summary>
    public static void WaitFor(Func<bool> condition, TimeSpan timeout, string what)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > timeout)
            {
                throw new TimeoutException($"Timed out after {timeout.TotalSeconds:0.#} s waiting for {what}.");
            }

            Thread.Sleep(20);
        }
    }

    /// <summary>
    /// The lines of a marker file written by <c>arcforges-testload signal</c>: (event, pid, unix ms). Only records ended by their newline
    /// count: a read concurrent with an append never takes a partly written line (such as <c>close 1234 </c>) for a record.
    /// </summary>
    public static List<(string Event, int Pid, long At)> Marker(string path)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        var text = reader.ReadToEnd();
        return [.. text[..(text.LastIndexOf('\n') + 1)].Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split(' '))
            .Where(parts => parts.Length == 3)
            .Select(parts => (parts[0], int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture), long.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture)))];
    }

    /// <summary>Reads a file another process still writes (the attempt's output files are shared for reading and writing).</summary>
    public static string ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>The identity of an attempt's root process (it was alive at its recorded start).</summary>
    public static ArcForges.Tests.ProcessIdentity Identity(RootProcess root) => ArcForges.Tests.ProcessIdentity.CreatedNoLaterThan(root.Pid, root.StartTime);

    /// <summary>The identity of a process this test started.</summary>
    public static ArcForges.Tests.ProcessIdentity Identity(LaunchedProcess process) =>
        ArcForges.Tests.ProcessIdentity.CreatedNoLaterThan(process.ProcessId, ProcessInfo.FromFileTime(process.CreationFileTime));

    /// <summary>The processes that wrote <paramref name="eventName"/> lines to a marker, each identified by its first such line.</summary>
    public static List<ArcForges.Tests.ProcessIdentity> MarkerProcesses(string marker, string eventName) =>
        [.. Marker(marker).Where(line => line.Event == eventName).GroupBy(line => line.Pid)
            .Select(group => ArcForges.Tests.ProcessIdentity.CreatedNoLaterThan(group.Key, group.Min(line => line.At)))];

    public void Dispose()
    {
        var leftovers = new List<string>();
        try
        {
            foreach (var handle in _handles)
            {
                Track(handle);
                try
                {
                    handle.Terminate();
                }
                catch (ObjectDisposedException)
                {
                }
            }

            foreach (var handle in _handles)
            {
                handle.Acknowledge();
                if (handle.Holder is { } holder)
                {
                    _seen.Add(ArcForges.Tests.ProcessIdentity.CreatedNoLaterThan(holder.ProcessId, ProcessInfo.FromFileTime(holder.CreationFileTime)));
                    if (!holder.WaitForExit(TimeSpan.FromSeconds(15)))
                    {
                        leftovers.Add($"holder {holder.ProcessId}");
                        holder.Kill(1);
                    }
                }

                handle.Dispose();
            }

            Platform.Dispose();
            var deadline = Stopwatch.StartNew();
            while (_seen.Any(process => process.IsRunning()) && deadline.Elapsed < TimeSpan.FromSeconds(10))
            {
                Thread.Sleep(50);
            }

            // Recorded by identity: a process that reused a recorded ID is neither reported nor killed.
            foreach (var process in _seen.Where(process => process.IsRunning()))
            {
                leftovers.Add(process.ToString());
                process.Kill();
            }
        }
        finally
        {
            for (var tries = 0; tries < 20; tries++)
            {
                try
                {
                    Directory.Delete(Root, recursive: true);
                    break;
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    Thread.Sleep(100);
                }
            }
        }

        ArcForges.Tests.Leftovers.Report(leftovers);
    }

    /// <summary>True when this process runs with an elevated token (the evidence records whether a job test ran non-elevated).</summary>
    public static bool IsElevated()
    {
        // Under UAC a non-elevated administrator's filtered token is not in the Administrators role.
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    /// <summary>Sets this process's error mode, which the processes it creates inherit; returns the previous mode.</summary>
    [LibraryImport("kernel32.dll")]
    internal static partial uint SetErrorMode(uint mode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsProcessInJob(nint process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool result);
}
