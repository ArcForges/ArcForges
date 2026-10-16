// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace ArcForges.Tools.Tests;

/// <summary>
/// <c>eng/compare-startup.ps1</c>, the startup gate, run with the real <c>pwsh</c> and <c>arcforges-bench</c>: the base commit's CLI
/// (<c>-BaselineExecutable</c>, built on the same machine) and the current CLI are measured here, interleaved, and the result names where
/// the baseline came from; a missing baseline fails the step with its reason instead of passing.
/// <c>arcforges-testload</c> stands in for both CLIs (the measured command is a parameter).
/// </summary>
[Trait("tool", "pwsh")]
public sealed class CompareStartupScriptTests
{
    private static string Rid => (OperatingSystem.IsWindows() ? "win-" : "linux-") + (System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64 ? "arm64" : "x64");

    [Fact(Timeout = 120_000)]
    public async Task ALocalBaselineExecutableIsMeasuredInterleavedOnThisMachine()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var pwsh = RequirePwsh();
        using var directory = new TemporaryDirectory();
        var run = await RunScriptAsync(pwsh, directory.Path, ["-BaselineExecutable", ToolProcess.TestLoad]);

        Assert.True(run.ExitCode == 0, run.Output);
        var comparison = Comparison(directory.Path);
        Assert.Equal("interleaved-same-runner", comparison.GetProperty("method").GetString());
        Assert.Equal("pass", comparison.GetProperty("status").GetString());
        Assert.Equal(4, comparison.GetProperty("current").GetProperty("samplesMs").GetArrayLength());
        Assert.Equal(4, comparison.GetProperty("baseline").GetProperty("samplesMs").GetArrayLength());
        Assert.True(comparison.TryGetProperty("baselineP95Ms", out _));
        Assert.True(comparison.TryGetProperty("currentP95Ms", out _));
        Assert.Contains("measured on this machine", comparison.GetProperty("baselineSource").GetString(), StringComparison.Ordinal);
    }

    [Fact(Timeout = 120_000)]
    public async Task TheNamedBaselineSourceIsRecorded()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var pwsh = RequirePwsh();
        using var directory = new TemporaryDirectory();
        const string Source = "base commit 0123abcd, built and measured on this runner";
        var run = await RunScriptAsync(pwsh, directory.Path, ["-BaselineExecutable", ToolProcess.TestLoad, "-BaselineSource", Source]);

        Assert.True(run.ExitCode == 0, run.Output);
        Assert.Equal(Source, Comparison(directory.Path).GetProperty("baselineSource").GetString());
    }

    [Fact(Timeout = 120_000)]
    public async Task AMissingBaselineExecutableFailsTheStep()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var pwsh = RequirePwsh();
        using var directory = new TemporaryDirectory();
        var missing = Path.Combine(directory.Path, "no-such-arcforges" + (OperatingSystem.IsWindows() ? ".exe" : string.Empty));

        var run = await RunScriptAsync(pwsh, directory.Path, ["-BaselineExecutable", missing]);

        Assert.NotEqual(0, run.ExitCode);
        AssertFailureReason(run.Output, "-BaselineExecutable " + missing + " is missing.");
        Assert.False(File.Exists(Path.Combine(directory.Path, "startup-comparison.json")));
    }

    /// <summary>
    /// The step failed with <paramref name="reason"/> on one plain line of its own (<c>compare-startup: ...</c>), unaffected by the error
    /// view, colour and console width; the reason must not be split or decorated.
    /// </summary>
    private static void AssertFailureReason(string output, string reason)
    {
        var lines = output.Split('\n').Select(line => line.TrimEnd('\r')).ToList();
        Assert.True(lines.Any(line => line.StartsWith("compare-startup: ", StringComparison.Ordinal) && line.Contains(reason, StringComparison.Ordinal)),
            $"No 'compare-startup:' line with \"{reason}\" in:\n{output}");
    }

    private static string RequirePwsh()
    {
        var name = OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh";
        var found = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(directory => Path.Combine(directory, name)).FirstOrDefault(File.Exists);
        Assert.SkipWhen(found is null, "pwsh is not installed (not found on PATH).");
        return found!;
    }

    private static JsonElement Comparison(string results)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(results, "startup-comparison.json")));
        return document.RootElement.Clone();
    }

    private static async Task<(int ExitCode, string Output)> RunScriptAsync(string pwsh, string results, string[] extra)
    {
        var script = Path.Combine(RepositoryRoot(), "eng", "compare-startup.ps1");
        var start = new ProcessStartInfo(pwsh)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        // -Command, so -Arguments is a real array (the measured command: testload cpu --iterations 1).
        static string Quote(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
        // The Linux runner's view: ConciseView errors (script position first, wrapped at the console width) and a narrow console.
        var invocation = new StringBuilder("$ErrorView = 'ConciseView'; & ").Append(Quote(script));
        foreach (var argument in (string[])["-RuntimeIdentifier", Rid, "-ResultsDirectory", results, "-Bench", ToolProcess.Bench,
            "-CurrentExecutable", ToolProcess.TestLoad, "-Runs", "4", "-NoiseFloorMs", "60000", "-Name", "testload cpu", .. extra])
        {
            invocation.Append(' ').Append(argument.StartsWith('-') ? argument : Quote(argument));
        }

        invocation.Append(" -Arguments @('cpu', '--iterations', '1'); exit $LASTEXITCODE");
        foreach (var argument in (string[])["-NoProfile", "-NonInteractive", "-Command", invocation.ToString()])
        {
            start.ArgumentList.Add(argument);
        }

        start.Environment["COLUMNS"] = "60";

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var error = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(90));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }

        return (process.ExitCode, await output + await error);
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "eng", "compare-startup.ps1")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("The repository root (eng/compare-startup.ps1) was not found above the test binaries.");
    }
}
