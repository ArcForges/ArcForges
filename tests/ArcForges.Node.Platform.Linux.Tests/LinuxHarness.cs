// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using ArcForges.Tests;

namespace ArcForges.Node.Platform.Linux.Tests;

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
/// A real Linux execution platform for one test: its own node name, data root and slice (<c>arcforges-test-&lt;id&gt;.slice</c>, 16 section
/// 4). It launches attempts as real transient units and, when disposed, stops every unit it launched and the slice, removes the slice's
/// runtime drop-ins, and fails the test when a unit or a process of the slice was still running.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class LinuxHarness : IDisposable
{
    /// <summary>The conventional soft open-file limit passed to attempts (the kernel default a login shell has).</summary>
    private const ulong DefaultNoFileSoft = 1024;

    /// <summary>
    /// Added to <c>TimeoutStopSec</c> beyond the end-step budget and <c>leftover_grace</c>: the <c>exec-stop</c> role's own start and the
    /// write of <c>stop.json</c>, so systemd never stops the role while it records the leftovers.
    /// </summary>
    private const int StopRecordMarginMs = 5_000;

    /// <summary>The .NET runtime's switch for its diagnostic endpoints (framework-dependent helpers only).</summary>
    private const string DiagnosticsVariable = "DOTNET_EnableDiagnostics";

    private readonly List<string> _attempts = [];
    private readonly List<string> _startGates = [];
    private readonly List<LinuxExecutionPlatform> _platforms = [];
    private readonly List<IAttemptHandle> _handles = [];
    private readonly IReadOnlyList<string> _extraUnitEnvironment;

    private LinuxHarness(string root, string slice, RootLimits limits, LinuxPlatformOptions? options, IReadOnlyList<string> extraUnitEnvironment)
    {
        Root = root;
        DataRoot = Path.Combine(root, "data");
        Directory.CreateDirectory(DataRoot);
        Slice = slice;
        Limits = limits;
        NodeName = "t" + Guid.NewGuid().ToString("N")[..20];
        Options = options ?? new LinuxPlatformOptions { Slice = slice };
        _extraUnitEnvironment = extraUnitEnvironment;
        try
        {
            Platform = NewPlatform();
            if (options is null)
            {
                Assert.True(Platform.UnitMode, "The platform did not reach the user manager: " + Platform.ManagerUnavailableReason);
            }
        }
        catch
        {
            // The test never gets the harness to dispose: remove what it created already.
            Release();
            throw;
        }
    }

    public string Root { get; }

    public string DataRoot { get; }

    public string Slice { get; }

    public string NodeName { get; }

    public RootLimits Limits { get; }

    public LinuxPlatformOptions Options { get; }

    public LinuxExecutionPlatform Platform { get; }

    /// <summary>Generous root limits (half the machine's CPU, 8 GiB, no swap) unless a test sets its own.</summary>
    public static LinuxHarness Start(RootLimits? limits = null, Func<string, LinuxPlatformOptions>? options = null,
        IReadOnlyList<string>? extraUnitEnvironment = null)
    {
        var slice = SystemdTestEnvironment.NewSlice();
        return new LinuxHarness(Directory.CreateTempSubdirectory("arcforges-linux-").FullName, slice,
            limits ?? new RootLimits(5_000, 12L << 30, 8L << 30) { HardMemoryBytes = 8L << 30, SwapAllowanceBytes = 0 }, options?.Invoke(slice), extraUnitEnvironment ?? []);
    }

    /// <summary>A second platform over the same slice and data root (a restarted node).</summary>
    public LinuxExecutionPlatform NewPlatform()
    {
        var platform = new LinuxExecutionPlatform(Options);
        _platforms.Add(platform);
        platform.Start(NodeName, Limits, TestPrograms.Host);
        return platform;
    }

    public AttemptFiles Files(out string name)
    {
        name = "a" + Guid.NewGuid().ToString("N")[..24];
        _attempts.Add(name);
        return new AttemptFiles(DataRoot, name);
    }

    /// <summary>Creates a fixture-owned unit, then attaches through the retained recovery path.</summary>
    public IAttemptHandle Launch(IReadOnlyList<string> argv, ContainerLimits? limits = null, IReadOnlyList<StepSpec>? launchSteps = null,
        IReadOnlyList<StepSpec>? endSteps = null, string? workingDirectory = null, int leftoverGraceMs = 5_000, IReadOnlyList<string>? environment = null,
        bool discardOutput = false, AttemptFiles? files = null)
    {
        files ??= Files(out _);
        var launch = FixtureLaunch(argv, files, limits, launchSteps, endSteps, workingDirectory, leftoverGraceMs, environment, discardOutput);
        var manager = Platform.Manager;
        var gate = "arcforges-test-gate-" + files.AttemptName + ".service";
        var release = Path.Combine(Root, files.AttemptName + ".start");
        var gateCommand = new ExecCommand("/bin/sh",
            ["/bin/sh", "-c", "while [ ! -e \"$1\" ]; do sleep 0.025; done", "sh", release], false);

        // Attach while the attempt is still queued, even for a command that could finish before the next D-Bus read.
        // The gate is a separate fixture unit, so its processes never enter the attempt's cgroup or resource accounting.
        _startGates.Add(gate);
        manager.StartTransientUnit(gate,
        [
            new("Slice", Slice),
            new("Type", "oneshot"),
            new("TimeoutStartUSec", 30_000_000UL),
            new("ExecStartEx", new[] { gateCommand }),
        ]);
        try
        {
            StartFixtureUnit(launch, after: gate);
            var recovered = Assert.IsType<LinuxAttemptHandle>(Platform.Reopen(NodeName, files, null, stopping: true));
            _handles.Add(recovered);
            Assert.False(recovered.Started.IsCompleted, "The native fixture job must remain queued until recovery is attached.");
            return recovered;
        }
        finally
        {
            File.WriteAllText(release, string.Empty);
        }
    }

    /// <summary>Creates a fixture unit already ordered after the caller's separate native test gate.</summary>
    public void Queue(IReadOnlyList<string> argv, AttemptFiles files) => StartFixtureUnit(FixtureLaunch(argv, files));

    private FixtureAttempt FixtureLaunch(IReadOnlyList<string> argv, AttemptFiles files, ContainerLimits? limits = null,
        IReadOnlyList<StepSpec>? launchSteps = null, IReadOnlyList<StepSpec>? endSteps = null, string? workingDirectory = null,
        int leftoverGraceMs = 5_000, IReadOnlyList<string>? environment = null, bool discardOutput = false) => new()
        {
            Files = files,
            Application = FixtureApplication(argv[0]),
            Argv = argv,
            Environment = environment ?? DefaultEnvironment(),
            WorkingDirectory = workingDirectory ?? Root,
            Limits = limits ?? new ContainerLimits(),
            LaunchSteps = launchSteps ?? [],
            EndSteps = endSteps ?? [],
            LeftoverGraceMs = leftoverGraceMs,
            DiscardOutput = discardOutput,
        };

    private void StartFixtureUnit(FixtureAttempt launch, string? after = null)
    {
        var manager = Platform.Manager;
        var files = launch.Files;
        Directory.CreateDirectory(files.Directory);
        Directory.CreateDirectory(files.TempDirectory);
        HelperFiles.WriteAtomically(files.StepsPath, new StepsFile
        {
            AttemptId = files.AttemptName,
            LaunchSteps = [.. launch.LaunchSteps],
            EndSteps = [.. launch.EndSteps],
            LeftoverGraceMs = launch.LeftoverGraceMs,
            EnvironmentNames = [.. launch.Environment.Select(entry => entry[..Math.Max(0, entry.IndexOf('=', StringComparison.Ordinal))]).Distinct(StringComparer.Ordinal)],
        }.ToJson());

        using var stdin = Libc.Open("/dev/null", write: false);
        using var stdout = Libc.Open(launch.DiscardOutput ? "/dev/null" : files.StdoutPath, write: true);
        using var stderr = Libc.Open(launch.DiscardOutput ? "/dev/null" : files.StderrPath, write: true);
        var properties = FixtureUnitProperties(launch, manager.ManagerEnvironment(), stdin, stdout, stderr);
        if (after is not null)
        {
            properties.Add(new("After", new[] { after }));
        }

        manager.StartTransientUnit(LinuxExecutionPlatform.UnitName(files.AttemptName), properties);
    }

    private List<UnitProperty> FixtureUnitProperties(FixtureAttempt launch, string[] managerEnvironment, SafeHandle stdin, SafeHandle stdout, SafeHandle stderr)
    {
        var files = launch.Files;
        var limits = launch.Limits;
        var resolved = launch.Environment.Select(entry => entry[..Math.Max(0, entry.IndexOf('=', StringComparison.Ordinal))]).ToHashSet(StringComparer.Ordinal);
        var nofileHard = Libc.GetRLimit(Libc.RlimitNofile, out var nofile) == 0 ? nofile.Maximum : 524_288UL;
        var nofileSoft = Math.Min(DefaultNoFileSoft, nofileHard);
        List<string> start =
        [
            Platform.Helper, "node", "exec-launch", "--attempt", files.AttemptName, "--dir", files.Directory, "--cwd", launch.WorkingDirectory,
            "--program", launch.Application, "--nofile", nofileSoft.ToString(CultureInfo.InvariantCulture),
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
        start.AddRange(launch.Argv);
        var properties = new List<UnitProperty>
        {
            new("Description", "ArcForges attempt " + files.AttemptName),
            new("Slice", Slice),
            new("Type", "exec"),
            new("ExecStartEx", (IReadOnlyList<ExecCommand>)[HelperCommand(start, false, helperDiagnosticsOff)]),
            new("ExecStopEx", (IReadOnlyList<ExecCommand>)[HelperCommand([Platform.Helper, "node", "exec-stop", "--attempt", files.AttemptName, "--dir", files.Directory], true,
                helperDiagnosticsOff)]),
            new("ExecStopPostEx", (IReadOnlyList<ExecCommand>)[HelperCommand([Platform.Helper, "node", "exit-record", "--attempt", files.AttemptName, "--dir", files.Directory], false,
                helperDiagnosticsOff)]),
            // Every exit status and signal is a success of the unit, so ExecStop (the end steps) runs after any exit; the attempt's result
            // is taken from $EXIT_CODE and $EXIT_STATUS by exit-record (04 section 3).
            new("SuccessExitStatus", new ExitStatusSet([.. Enumerable.Range(1, 255)],
                [.. Enumerable.Range(1, 31), .. Enumerable.Range(Libc.SigRtMin, Libc.SigRtMax - Libc.SigRtMin + 1)])),
            new("WorkingDirectory", "-" + launch.WorkingDirectory),
            new("Environment", (string[])[.. UnitEnvironment(launch.Environment), .. _extraUnitEnvironment]),
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
        if (Platform.Hardening is { } hardening)
        {
            // AD-0007 section 8: only after the probe read it back as applied; each unit is read back again after its start.
            properties.AddRange(hardening);
        }

        foreach (var (resource, name) in (ReadOnlySpan<(int, string)>)[(Libc.RlimitCore, "LimitCORE"), (Libc.RlimitStack, "LimitSTACK")])
        {
            if (Libc.GetRLimit(resource, out var limit) == 0)
            {
                properties.Add(new(name, limit.Maximum));
                properties.Add(new(name + "Soft", limit.Current));
            }
        }

        if (Platform.Controllers.Contains("cpu"))
        {
            properties.Add(new("CPUWeight", (ulong)LinuxExecutionPlatform.CpuWeight(limits.CpuWeight)));
            if (limits.CpuRateCap is { } cap)
            {
                properties.Add(new("CPUQuotaPerSecUSec", (ulong)cap * (ulong)Platform.Capacity.LogicalProcessors * 100UL));
            }
        }

        if (Platform.Controllers.Contains("memory"))
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

        if (Platform.Controllers.Contains("pids"))
        {
            properties.Add(new("TasksMax", (ulong)(limits.ActiveProcessLimit ?? limits.TasksMax)));
        }

        return properties;
    }

    /// <summary>
    /// A helper command line; a framework-dependent helper is started through <c>env DOTNET_ROOT=...</c>, and without the runtime's
    /// diagnostic endpoints (<c>DOTNET_EnableDiagnostics=0</c>, unless the attempt sets it), so a helper that becomes the command
    /// (<c>execve</c>) or is killed leaves no IPC socket behind in the temporary directory.
    /// </summary>
    private ExecCommand HelperCommand(List<string> argv, bool ignoreFailure, bool diagnosticsOff) => HelperRuntime is { } runtime && File.Exists("/usr/bin/env")
        ? new ExecCommand("/usr/bin/env", ["env", "DOTNET_ROOT=" + runtime, .. diagnosticsOff ? (string[])[DiagnosticsVariable + "=0"] : [], .. argv], ignoreFailure)
        : new ExecCommand(Platform.Helper, argv, ignoreFailure);

    /// <summary>
    /// The .NET location a framework-dependent helper needs (the JIT build of the tests: an <c>arcforges.dll</c> beside it), or null for
    /// the Native AOT executable, which needs nothing.
    /// </summary>
    private string? HelperRuntime => File.Exists(Path.ChangeExtension(Platform.Helper, ".dll")) ? Environment.GetEnvironmentVariable("DOTNET_ROOT") : null;

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

    /// <summary>The environment of the test process as <c>NAME=value</c> entries.</summary>
    public static List<string> DefaultEnvironment() =>
        [.. Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>().Select(entry => (string)entry.Key + "=" + (string?)entry.Value)];

    /// <summary>A step that runs the explicit fixture command.</summary>
    public static StepSpec Step(string name, int timeoutMs, params string[] argv) => new()
    {
        Name = name,
        Application = FixtureApplication(argv[0]),
        Argv = [.. argv],
        TimeoutMs = timeoutMs,
    };

    private static string FixtureApplication(string program) => program switch
    {
        "sh" => "/bin/sh",
        "sleep" => "/bin/sleep",
        _ when Path.IsPathFullyQualified(program) => program,
        _ => throw new ArgumentException("A fixture command requires an absolute executable path.", nameof(program)),
    };

    /// <summary>Waits for the attempt's exit record (bounded), refreshing the handle as the node's enforcement loop does.</summary>
    public static ExitRecord WaitExit(IAttemptHandle handle, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < timeout)
        {
            handle.Refresh();
            if (handle.TryReadExit() is { } exit)
            {
                return exit;
            }

            Thread.Sleep(50);
        }

        throw new TimeoutException($"No exit record within {timeout.TotalSeconds:0} s.");
    }

    /// <summary>Waits for <paramref name="condition"/> (bounded).</summary>
    public static void WaitFor(Func<bool> condition, TimeSpan timeout, string what)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(watch.Elapsed < timeout, $"Timed out after {timeout.TotalSeconds:0.#} s waiting for {what}.");
            Thread.Sleep(25);
        }
    }

    /// <summary>A cgroup file of a directory, without the line break.</summary>
    public static string Read(string directory, string file) => File.ReadAllText(Path.Combine(directory, file)).TrimEnd('\n');

    public void Dispose()
    {
        foreach (var handle in _handles.OfType<LinuxAttemptHandle>().Where(handle => handle.LastLimitStop is not null))
        {
            TestContext.Current.TestOutputHelper?.WriteLine($"{handle.Unit}: {handle.LastLimitStop!.Describe()}");
        }

        var leftovers = Release();
        Leftovers.Report(leftovers);
    }

    private List<string> Release()
    {
        foreach (var handle in _handles)
        {
            handle.Dispose();
        }

        foreach (var platform in _platforms)
        {
            platform.Dispose();
        }

        var leftovers = SystemdTestEnvironment.Cleanup(Slice, _attempts, _startGates);
        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            leftovers.Add($"files under {Root} ({exception.Message})");
        }

        return leftovers;
    }

    private sealed class FixtureAttempt
    {
        public required AttemptFiles Files { get; init; }
        public required string Application { get; init; }
        public required IReadOnlyList<string> Argv { get; init; }
        public required IReadOnlyList<string> Environment { get; init; }
        public required string WorkingDirectory { get; init; }
        public required ContainerLimits Limits { get; init; }
        public required IReadOnlyList<StepSpec> LaunchSteps { get; init; }
        public required IReadOnlyList<StepSpec> EndSteps { get; init; }
        public required int LeftoverGraceMs { get; init; }
        public required bool DiscardOutput { get; init; }
    }
}
