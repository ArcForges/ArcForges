// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
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
    private readonly List<string> _attempts = [];
    private readonly List<LinuxExecutionPlatform> _platforms = [];
    private readonly List<IAttemptHandle> _handles = [];

    private LinuxHarness(string root, string slice, RootLimits limits, LinuxPlatformOptions? options)
    {
        Root = root;
        DataRoot = Path.Combine(root, "data");
        Directory.CreateDirectory(DataRoot);
        Slice = slice;
        Limits = limits;
        NodeName = "t" + Guid.NewGuid().ToString("N")[..20];
        Options = options ?? new LinuxPlatformOptions { Slice = slice };
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
    public static LinuxHarness Start(RootLimits? limits = null, Func<string, LinuxPlatformOptions>? options = null)
    {
        var slice = SystemdTestEnvironment.NewSlice();
        return new LinuxHarness(Directory.CreateTempSubdirectory("arcforges-linux-").FullName, slice,
            limits ?? new RootLimits(5_000, 12L << 30, 8L << 30) { HardMemoryBytes = 8L << 30, SwapAllowanceBytes = 0 }, options?.Invoke(slice));
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

    /// <summary>Launches <paramref name="argv"/> (resolved like the node does) in a new attempt unit.</summary>
    public IAttemptHandle Launch(IReadOnlyList<string> argv, ContainerLimits? limits = null, IReadOnlyList<StepSpec>? launchSteps = null,
        IReadOnlyList<StepSpec>? endSteps = null, string? workingDirectory = null, int leftoverGraceMs = 5_000, IReadOnlyList<string>? environment = null,
        LinuxExecutionPlatform? platform = null, bool discardOutput = false, AttemptFiles? files = null)
    {
        files ??= Files(out _);
        var env = environment ?? DefaultEnvironment();
        var cwd = workingDirectory ?? Root;
        var dictionary = env.Select(entry => entry.Split('=', 2)).ToDictionary(parts => parts[0], parts => parts.Length > 1 ? parts[1] : string.Empty, StringComparer.Ordinal);
        var prepared = (platform ?? Platform).Prepare(new CommandRequest { Argv = argv, WorkingDirectory = cwd, Environment = dictionary, TempDirectory = files.TempDirectory });
        return Track((platform ?? Platform).Launch(new AttemptLaunch
        {
            NodeName = NodeName,
            Files = files,
            Command = prepared,
            Environment = env,
            WorkingDirectory = cwd,
            Limits = limits ?? new ContainerLimits(),
            LaunchSteps = launchSteps ?? [],
            EndSteps = endSteps ?? [],
            LeftoverGraceMs = leftoverGraceMs,
            DiscardOutput = discardOutput,
        }));
    }

    private IAttemptHandle Track(IAttemptHandle handle)
    {
        _handles.Add(handle);
        return handle;
    }

    /// <summary>The environment of the test process as <c>NAME=value</c> entries.</summary>
    public static List<string> DefaultEnvironment() =>
        [.. Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>().Select(entry => (string)entry.Key + "=" + (string?)entry.Value)];

    /// <summary>A step that runs <paramref name="argv"/> (<c>argv[0]</c> resolved on <c>PATH</c>).</summary>
    public static StepSpec Step(string name, int timeoutMs, params string[] argv) => new()
    {
        Name = name,
        Application = LinuxCommands.Resolve(argv[0], "/", new Dictionary<string, string> { ["PATH"] = "/usr/bin:/bin" }) ?? argv[0],
        Argv = [.. argv],
        TimeoutMs = timeoutMs,
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

        var leftovers = SystemdTestEnvironment.Cleanup(Slice, _attempts);
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
}
