// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Platform.Linux;

/// <summary>
/// An attempt run as a plain child process of the node (AD-0005 Linux section 4: no systemd user manager, observe only). The node starts
/// <c>arcforges node exec-launch</c> in a new process group with the attempt's streams and exact environment (launch steps, then
/// <c>execve</c> of the command); on the root's exit it runs the end steps, waits <c>leftover_grace</c> for the group, kills what is left
/// and writes <c>exit.json</c> itself. Nothing is enforced; the exit status is lost when the node stops first (the attempt is then
/// <c>LOST</c>).
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class DirectAttemptHandle : IAttemptHandle
{
    private readonly AttemptLaunch _launch;
    private readonly TaskCompletionSource<RootProcess?> _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private RootProcess? _root;
    private volatile bool _exited;

    private DirectAttemptHandle(AttemptLaunch launch, Stream? stdinWriter)
    {
        _launch = launch;
        StdinWriter = stdinWriter;
    }

    /// <inheritdoc />
    public event Action? Changed;

    /// <inheritdoc />
    public string ContainerName => "pgid:" + (_root?.Pid.ToString(CultureInfo.InvariantCulture) ?? "?");

    /// <inheritdoc />
    public RootProcess? Root => Volatile.Read(ref _root);

    /// <inheritdoc />
    public Task<RootProcess?> Started => _started.Task;

    /// <inheritdoc />
    public Stream? StdinWriter { get; }

    /// <inheritdoc />
    public bool RootRunning => !_exited;

    /// <inheritdoc />
    public bool MemoryLimitHit => false;

    /// <summary>Starts the attempt.</summary>
    internal static DirectAttemptHandle Start(LinuxExecutionPlatform platform, AttemptLaunch launch)
    {
        var files = launch.Files;
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
            }

            List<string> argv =
            [
                platform.Helper, "node", "exec-launch", "--attempt", files.AttemptName, "--dir", files.Directory, "--cwd", launch.WorkingDirectory,
                "--program", launch.Command.Application, "--nofile", LinuxExecutionPlatform.DefaultNoFileSoft.ToString(CultureInfo.InvariantCulture),
            ];
            List<string> environment = [.. launch.Environment];
            if (platform.HelperRuntime is { } runtime && !environment.Any(entry => entry.StartsWith("DOTNET_ROOT=", StringComparison.Ordinal)))
            {
                // A framework-dependent helper (the JIT build of the tests) gets DOTNET_ROOT for itself only.
                environment.Add("DOTNET_ROOT=" + runtime);
                argv.AddRange(["--unset", "DOTNET_ROOT"]);
            }

            if (platform.HelperRuntime is not null && !environment.Any(entry => entry.StartsWith(LinuxExecutionPlatform.DiagnosticsVariable + "=", StringComparison.Ordinal)))
            {
                // Nor its diagnostic endpoints, which would outlive it in the temporary directory once it becomes the command.
                environment.Add(LinuxExecutionPlatform.DiagnosticsVariable + "=0");
                argv.AddRange(["--unset", LinuxExecutionPlatform.DiagnosticsVariable]);
            }

            argv.Add("--");
            argv.AddRange(launch.Command.Argv);
            var pid = Libc.Spawn(platform.Helper, argv, environment,
                ((int)(stdin?.DangerousGetHandle() ?? -1), (int)stdout.DangerousGetHandle(), (int)stderr.DangerousGetHandle()), null, newProcessGroup: true);
            var handle = new DirectAttemptHandle(launch, writer);
            var start = ProcFs.StartOf(pid)?.Start ?? DateTimeOffset.UtcNow;
            handle._root = new RootProcess(pid, start);
            handle._started.TrySetResult(handle._root);
            var thread = new Thread(handle.Wait) { IsBackground = true, Name = "arcforges-attempt-" + files.AttemptName };
            thread.Start();
            writer = null;
            return handle;
        }
        finally
        {
            stdout?.Dispose();
            stderr?.Dispose();
            stdin?.Dispose();
            writer?.Dispose();
        }
    }

    /// <inheritdoc />
    public ExitRecord? TryReadExit() => ExitRecord.TryRead(_launch.Files.ExitPath);

    /// <inheritdoc />
    public LaunchRecord? TryReadLaunchFailure() => LaunchRecord.TryRead(_launch.Files.LaunchPath);

    /// <inheritdoc />
    public IReadOnlyList<ContainerProcess> Processes() => [.. Group().Select(pid => new ContainerProcess(pid, ProcFs.Image(pid)))];

    /// <inheritdoc />
    public ContainerAccounting Accounting() => new(0, 0, 0, 0, 0, Group().Count, []);

    /// <inheritdoc />
    public void Terminate() => Signal(Libc.SigKill);

    /// <inheritdoc />
    public GracefulOutcome RequestGracefulStop() => RequestGracefulStop(null);

    /// <inheritdoc />
    public GracefulOutcome RequestGracefulStop(string? stopSignal)
    {
        var signal = LinuxRecords.SignalNumber(stopSignal) is > 0 and var number ? number : Libc.SigTerm;
        return Signal(signal) ? new GracefulOutcome(true, 0, null) : new GracefulOutcome(false, 0, "the process group is gone");
    }

    /// <inheritdoc />
    public IReadOnlyList<EscapedProcess> ScanEscaped() => [];

    /// <inheritdoc />
    public IReadOnlyList<string> TerminateEscaped() => [];

    /// <inheritdoc />
    public void Acknowledge()
    {
    }

    /// <inheritdoc />
    public void Dispose()
    {
        StdinWriter?.Dispose();
        _started.TrySetResult(Root);
    }

    private bool Signal(int signal) => _root is { } root && Libc.Kill(-root.Pid, signal) == 0;

    private List<int> Group()
    {
        if (_root is not { } root)
        {
            return [];
        }

        var members = new List<int>();
        foreach (var pid in ProcFs.AllProcesses())
        {
            if (ProcFs.Stat(pid) is { } stat && stat.ProcessGroup == root.Pid && stat.State is not ('Z' or 'X'))
            {
                members.Add(pid);
            }
        }

        return members;
    }

    private void Wait()
    {
        var pid = _root!.Pid;
        var status = Libc.Wait(pid, Timeout.InfiniteTimeSpan) ?? -1;
        _exited = true;
        Changed?.Invoke();
        var files = _launch.Files;
        var budget = Stopwatch.StartNew();
        foreach (var step in _launch.EndSteps)
        {
            var remaining = TimeSpan.FromSeconds(10) - budget.Elapsed;
            if (remaining <= TimeSpan.Zero)
            {
                break;
            }

            StepRunner.Run(step, _launch.Environment, _launch.WorkingDirectory, TimeSpan.FromMilliseconds(Math.Min(step.TimeoutMs, remaining.TotalMilliseconds)));
        }

        var grace = Stopwatch.StartNew();
        var left = Group();
        while (left.Count > 0 && grace.ElapsedMilliseconds < _launch.LeftoverGraceMs)
        {
            Thread.Sleep(50);
            left = Group();
        }

        var leftovers = left.Select(ProcFs.Image).ToList();
        Signal(Libc.SigKill);
        try
        {
            HelperFiles.WriteAtomically(files.ExitPath, LinuxRecords.FromWaitStatus(files.AttemptName, status, leftovers, DateTimeOffset.UtcNow).ToJson());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The node finalizes it as incomplete when no record appears.
        }

        Changed?.Invoke();
    }
}
