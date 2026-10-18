// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;

namespace ArcForges.Tools.Tests;

/// <summary>
/// The script side of the OS secret-store guard (ArcForges-Design 16-testing-strategy section 1, items 1 and 4): a stray
/// <c>ARCFORGES_OS_SECRET_STORE_TESTS</c> never reaches a routine suite. The real <c>eng/test.ps1</c> (Windows) or <c>eng/test.sh</c>
/// (Linux) is started with the opt-in already in its environment and runs one routine probe, the store tests'
/// <c>ThisRoutineTestProcessDeniesTheOsStoresThroughItsRuntimeConfiguration</c>, which fails at once if it sees the variable and
/// otherwise shows that the tripwire refuses the store: so the script removed it and the access is refused. The probe's project
/// reaches no OS secret store in any case: it asserts the variable's absence before anything else, and its refused calls make no OS
/// call even without the tripwire. The pre-push step table (<c>eng/verify_steps.py</c>) refuses to load at all with the opt-in set.
/// The opt-in is set only in those child processes' environments, never in this process.
/// </summary>
public sealed class OsSecretStoreOptInScriptTests
{
    private const string OptIn = "ARCFORGES_OS_SECRET_STORE_TESTS";
    private const string Probe = "ArcForges.Node.Store.Tests.OsSecretStoreGuardTests.ThisRoutineTestProcessDeniesTheOsStoresThroughItsRuntimeConfiguration";

    public static bool OnWindows => OperatingSystem.IsWindows();

    public static bool OnLinux => OperatingSystem.IsLinux();

    private static string Configuration => new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;

    [Fact(Timeout = 300_000, Skip = "eng/test.ps1 is the Windows suite runner.", SkipUnless = nameof(OnWindows))]
    [Trait("tool", "pwsh")]
    public async Task TestPs1RemovesAStrayOptInBeforeARoutineSuiteRuns()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var pwsh = Require("pwsh.exe", "pwsh");
        var run = await RunAsync(pwsh, ["-NoProfile", "-NonInteractive", "-File", Path.Combine(RepositoryRoot(), "eng", "test.ps1"),
            "-Suite", "store", "-NoBuild", "-Parallel", "1", "-Configuration", Configuration, "--", "--filter-method", Probe], optIn: true);

        Assert.True(run.ExitCode == 0, run.Output);
        Assert.Contains("test.ps1: removed " + OptIn + " from the environment", run.Output, StringComparison.Ordinal);
        Assert.Contains("Suites passed: store", run.Output, StringComparison.Ordinal);
    }

    [Fact(Timeout = 300_000, Skip = "eng/test.sh is the Linux suite runner.", SkipUnless = nameof(OnLinux))]
    public async Task TestShRemovesAStrayOptInBeforeARoutineSuiteRuns()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var bash = Require("bash", "bash");
        var run = await RunAsync(bash, [Path.Combine(RepositoryRoot(), "eng", "test.sh"), "--suite", "store", "--no-build", "--parallel", "1",
            "--configuration", Configuration, "--", "--filter-method", Probe], optIn: true);

        Assert.True(run.ExitCode == 0, run.Output);
        Assert.Contains("test.sh: removed " + OptIn + " from the environment", run.Output, StringComparison.Ordinal);
        Assert.Contains("Suites passed: store", run.Output, StringComparison.Ordinal);
    }

    [Fact(Timeout = 120_000)]
    [Trait("tool", "python")]
    public async Task ThePrePushStepTableRefusesToLoadWithTheOptInAndNeverRunsTheTier()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var python = Require(OperatingSystem.IsWindows() ? "python.exe" : "python3", "python");
        // eng/verify.py executes the committed step table with an injected Step; the same here, in an isolated interpreter.
        const string Loader = """
            import sys, types
            module = types.ModuleType("verify_steps")
            module.__dict__["Step"] = lambda step_id, host, cmd, **options: (step_id, cmd)
            try:
                exec(compile(open(sys.argv[1], encoding="utf-8").read(), "eng/verify_steps.py", "exec"), module.__dict__)
            except SystemExit as refused:
                print(refused.code)
                sys.exit(5)
            for step_id, cmd in module.STEPS:
                print(step_id, cmd if isinstance(cmd, str) else " ".join(cmd))
            """;
        var table = Path.Combine(RepositoryRoot(), "eng", "verify_steps.py");

        var refused = await RunAsync(python, ["-I", "-c", Loader, table], optIn: true);
        Assert.True(refused.ExitCode == 5, refused.Output);
        Assert.StartsWith("arcforges-verify: FAIL " + OptIn + " is set", refused.Output.TrimStart(), StringComparison.Ordinal);
        Assert.Contains("refuses to run", refused.Output, StringComparison.Ordinal);

        var loaded = await RunAsync(python, ["-I", "-c", Loader, table], optIn: false);
        Assert.True(loaded.ExitCode == 0, loaded.Output);
        Assert.Contains("win-ci ", loaded.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("OsSecretStoreTier", loaded.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("os_secret_store_tier", loaded.Output, StringComparison.Ordinal);
    }

    private static async Task<(int ExitCode, string Output)> RunAsync(string executable, string[] arguments, bool optIn)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = RepositoryRoot(),
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        if (optIn)
        {
            start.Environment[OptIn] = "1";
        }
        else
        {
            start.Environment.Remove(OptIn);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var error = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(240));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }

        return (process.ExitCode, await output + await error);
    }

    private static string Require(string file, string tool)
    {
        var found = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(directory => Path.Combine(directory, file)).FirstOrDefault(File.Exists);
        Assert.SkipWhen(found is null, tool + " is not installed (not found on PATH).");
        return found!;
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "ArcForges.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new DirectoryNotFoundException("The repository root (ArcForges.slnx) was not found above the test output.");
    }
}
