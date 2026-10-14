// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace ArcForges.Tools.Tests;

internal sealed record ToolRun(int ExitCode, byte[] StandardOutput, string StandardError)
{
    public string OutputText => Encoding.UTF8.GetString(StandardOutput);

    public JsonElement Json() => JsonDocument.Parse(StandardOutput).RootElement.Clone();
}

/// <summary>Runs the real tool executables: the JIT build next to the tests, or a published binary named by environment variable.</summary>
internal static class ToolProcess
{
    public static string TestLoad => Resolve("ARCFORGES_TESTLOAD_PATH", "arcforges-testload");

    public static string Bench => Resolve("ARCFORGES_BENCH_PATH", "arcforges-bench");

    public static Task<ToolRun> RunAsync(string executable, IEnumerable<string> arguments, CancellationToken cancellationToken) =>
        Start(executable, arguments, cancellationToken).Completion;

    /// <summary>Starts the tool and returns its process (for observing it while it runs) and its completion.</summary>
    public static (int ProcessId, Task<ToolRun> Completion) Start(string executable, IEnumerable<string> arguments, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        var process = Process.Start(start)!;
        return (process.Id, CompleteAsync(process, cancellationToken));
    }

    private static async Task<ToolRun> CompleteAsync(Process process, CancellationToken cancellationToken)
    {
        using var owned = process;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));
        try
        {
            using var output = new MemoryStream();
            var copy = process.StandardOutput.BaseStream.CopyToAsync(output, timeout.Token);
            var error = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
            await copy;
            return new ToolRun(process.ExitCode, output.ToArray(), await error);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
    }

    private static string Resolve(string variable, string name)
    {
        var configured = Environment.GetEnvironmentVariable(variable);
        if (!string.IsNullOrEmpty(configured))
        {
            // Test applications run in their output directory, so a relative path would be ambiguous.
            return Path.IsPathFullyQualified(configured) && File.Exists(configured)
                ? configured
                : throw new FileNotFoundException($"{variable} must be the absolute path of an existing {name} executable.", configured);
        }

        var path = Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? name + ".exe" : name);
        return File.Exists(path) ? path : throw new FileNotFoundException($"The {name} executable is missing next to the tests.", path);
    }
}
