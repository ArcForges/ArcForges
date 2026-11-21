// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;
using Microsoft.Win32.SafeHandles;

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

    /// <summary>Launches <paramref name="argv"/> with an explicit fixture program in a new attempt.</summary>
    public WindowsAttemptHandle Launch(IReadOnlyList<string> argv, ContainerLimits? limits = null, IReadOnlyList<StepSpec>? launchSteps = null,
        IReadOnlyList<StepSpec>? endSteps = null, bool killWithNode = false, string? workingDirectory = null, int leftoverGraceMs = 5_000,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        var files = Files(out _);
        var env = environment ?? Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(entry => (string)entry.Key, entry => (string?)entry.Value ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        var cwd = workingDirectory ?? Root;
        if (argv.Count == 0 || !Path.IsPathFullyQualified(argv[0]))
        {
            throw new ArgumentException("The fixture program must have an absolute path.", nameof(argv));
        }

        var program = argv[0];
        var application = program;
        var batch = WindowsProgramResolver.IsBatch(program);
        if (batch)
        {
            var shell = WindowsProgramResolver.Value(env, "ComSpec");
            application = shell is not null && File.Exists(shell)
                ? shell
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        }

        var spec = new HolderSpec
        {
            AttemptId = files.AttemptName,
            Application = application,
            CommandLine = batch ? WindowsCommandLine.BuildBatch(application, program, argv) : WindowsCommandLine.Build(argv),
            Environment = [.. env.Select(pair => pair.Key + "=" + pair.Value)],
            WorkingDirectory = cwd,
            LaunchSteps = [.. (launchSteps ?? [])],
            EndSteps = [.. (endSteps ?? [])],
            LeftoverGraceMs = leftoverGraceMs,
            AttemptDirectory = files.Directory,
        };
        var handle = LaunchFixtureAttempt(files, spec, limits ?? new ContainerLimits(), killWithNode);
        _handles.Add(handle);
        return handle;
    }

    private WindowsAttemptHandle LaunchFixtureAttempt(AttemptFiles files, HolderSpec spec, ContainerLimits limits, bool killWithNode)
    {
        var root = Platform.RootJob ?? throw new InvalidOperationException("The platform has not started.");
        Directory.CreateDirectory(files.Directory);
        Directory.CreateDirectory(files.TempDirectory);
        var job = JobObject.Create(WindowsExecutionPlatform.JobName(NodeName, files.AttemptName));
        WindowsAttemptHandle? handle = null;
        SafeFileHandle? stdout = null, stderr = null;
        SafeHandle? stdin = null;
        try
        {
            job.SetLimits(limits.CommitLimitBytes, limits.ActiveProcessLimit, killOnClose: killWithNode,
                priorityClass: WindowsExecutionPlatform.AttemptPriorityClass);
            if (limits.CommitLimitBytes > 0)
            {
                job.SetMemoryNotification(limits.CommitNotificationBytes > 0 ? limits.CommitNotificationBytes : limits.CommitLimitBytes);
            }

            if (limits.CpuRateCap is { } cap)
            {
                job.SetCpuHardCap(cap);
            }
            else
            {
                job.SetCpuWeight(limits.CpuWeight);
            }

            stdout = File.OpenHandle(files.StdoutPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            stderr = File.OpenHandle(files.StderrPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            stdin = ProcessLauncher.OpenNull(write: false);
            handle = Platform.CreateAttemptHandle(job, files, root: null);
            Platform.ObserveAttemptJob(handle, clearFirst: false);
            if (killWithNode)
            {
                StartDirect(handle, spec, root, job, stdin, stdout, stderr);
                stdout = null;
                stderr = null;
            }
            else
            {
                StartHolder(handle, spec, root, job, stdin, stdout, stderr);
            }

            return handle;
        }
        catch
        {
            if (handle is not null)
            {
                Platform.Forget(handle.CompletionKey);
            }

            job.Terminate(AttemptRunner.TerminatedExitCode);
            handle?.Dispose();
            job.Dispose();
            throw;
        }
        finally
        {
            stdin?.Dispose();
            stdout?.Dispose();
            stderr?.Dispose();
        }
    }

    private void StartHolder(WindowsAttemptHandle handle, HolderSpec spec, JobObject root, JobObject job, SafeHandle stdin, SafeHandle stdout, SafeHandle stderr)
    {
        var ack = Native.CreateEvent(0, manualReset: true, initialState: false, WindowsExecutionPlatform.AckName(NodeName, handle.Files.AttemptName));
        if (ack.IsInvalid)
        {
            var error = Native.LastError;
            ack.Dispose();
            throw new Win32Exception(error, "CreateEvent(ack) failed.");
        }

        handle.Ack = ack;
        var attributes = new Native.SecurityAttributes { Length = Marshal.SizeOf<Native.SecurityAttributes>() };
        if (!Native.CreatePipe(out var specRead, out var specWrite, ref attributes, 64 * 1024))
        {
            throw new Win32Exception(Native.LastError, "CreatePipe(spec) failed.");
        }

        if (!Native.CreatePipe(out var reportRead, out var reportWrite, ref attributes, 16 * 1024))
        {
            var error = Native.LastError;
            Native.CloseHandle(specRead);
            Native.CloseHandle(specWrite);
            throw new Win32Exception(error, "CreatePipe(report) failed.");
        }

        using var specReadHandle = new SafeKernelHandle(specRead, ownsHandle: true);
        using var reportWriteHandle = new SafeKernelHandle(reportWrite, ownsHandle: true);
        var reportStream = new FileStream(new SafeFileHandle(reportRead, ownsHandle: true), FileAccess.Read, 1, isAsync: false);
        var specStream = new FileStream(new SafeFileHandle(specWrite, ownsHandle: true), FileAccess.Write, 1, isAsync: false);
        var inheritable = new List<nint>();
        try
        {
            using var nulError = ProcessLauncher.OpenNull(write: true);
            nint Copy(SafeHandle source)
            {
                var copy = ProcessLauncher.InheritableCopy(source);
                inheritable.Add(copy);
                return copy;
            }

            var arguments = new List<string>
            {
                TestPrograms.Host, "node", "exec-wrap", "--attempt", handle.Files.AttemptName,
                "--job", Text(Copy(job.Handle)), "--root-job", Text(Copy(root.Handle)),
                "--stdin", Text(Copy(stdin)), "--stdout", Text(Copy(stdout)), "--stderr", Text(Copy(stderr)),
                "--ack", Text(Copy(ack)),
            };
            var holder = ProcessLauncher.Start(new LaunchOptions
            {
                Application = TestPrograms.Host,
                CommandLine = WindowsCommandLine.Build(arguments),
                WorkingDirectory = Path.GetDirectoryName(TestPrograms.Host),
                Flags = Native.DetachedProcess,
                StdInput = specReadHandle,
                StdOutput = reportWriteHandle,
                StdError = nulError,
                InheritableHandles = inheritable,
            });
            holder.Resume();
            handle.Holder = holder;
        }
        catch
        {
            reportStream.Dispose();
            specStream.Dispose();
            throw;
        }
        finally
        {
            foreach (var copy in inheritable)
            {
                Native.CloseHandle(copy);
            }
        }

        handle.ReadReports(reportStream);
        try
        {
            specStream.Write(Encoding.UTF8.GetBytes(spec.ToJson()));
        }
        finally
        {
            specStream.Dispose();
        }
    }

    private static void StartDirect(WindowsAttemptHandle handle, HolderSpec spec, JobObject root, JobObject job, SafeHandle stdin, SafeFileHandle stdout,
        SafeFileHandle stderr)
    {
        // The fixture is the holder. The runner keeps its own stdio handles, and the job has KILL_ON_JOB_CLOSE.
        var stdinCopy = new SafeKernelHandle(ProcessLauncher.InheritableCopy(stdin), ownsHandle: true);
        var thread = new Thread(() =>
        {
            try
            {
                var runner = new AttemptRunner(spec, root, job, stdinCopy, stdout, stderr, handle.OnReport);
                runner.Run(guard: false);
            }
            catch (ObjectDisposedException)
            {
                // The node closed the job (kill-on-close ended the attempt): nothing is left to record.
            }
            catch (Exception exception) when (exception is Win32Exception or IOException or UnauthorizedAccessException)
            {
                handle.OnReport(new HolderReport { Event = "spawn_failed", Error = exception.Message });
            }
            finally
            {
                stdinCopy.Dispose();
                stdout.Dispose();
                stderr.Dispose();
            }
        })
        {
            IsBackground = true,
            Name = "arcforges-attempt-" + spec.AttemptId,
        };
        thread.Start();
    }

    private static string Text(nint handle) => ((long)handle).ToString(CultureInfo.InvariantCulture);

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
    public static void WaitFor(Func<bool> condition, TimeSpan timeout, string what) => WaitFor(condition, timeout, () => what);

    /// <summary>Waits for <paramref name="condition"/> (bounded); <paramref name="what"/> is read only when the wait fails.</summary>
    public static void WaitFor(Func<bool> condition, TimeSpan timeout, Func<string> what)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > timeout)
            {
                throw new TimeoutException($"Timed out after {timeout.TotalSeconds:0.#} s waiting for {what()}.");
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
        return [.. text[..(text.LastIndexOf('\n', StringComparison.Ordinal) + 1)].Split('\n', StringSplitOptions.RemoveEmptyEntries)
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

    /// <summary>The class names of the top-level windows (visible or hidden) of process <paramref name="pid"/>.</summary>
    public static List<string> WindowClasses(int pid) =>
        [.. GuiWindows.TopLevelWindows().Where(window => window.ProcessId == pid).Select(window => ClassName(window.Window))];

    private static unsafe string ClassName(nint window)
    {
        var name = stackalloc char[256];
        return new string(name, 0, GetClassName(window, name, 256));
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

    [LibraryImport("user32.dll", EntryPoint = "GetClassNameW")]
    private static unsafe partial int GetClassName(nint window, char* name, int length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsProcessInJob(nint process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool result);
}
