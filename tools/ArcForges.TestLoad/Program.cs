// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;

namespace ArcForges.TestLoad;

internal static class ExitCodes
{
    public const int Success = 0;
    public const int Failure = 1;
    public const int Usage = 2;
}

internal static class Program
{
    internal const string Usage = """
        arcforges-testload: deterministic synthetic workloads (same parameters, same bytes and digest).

        usage: arcforges-testload <scenario> [--option value ...]

        scenarios:
          cpu       --threads N (1)  --iterations N per thread (100000000)  --seed N (1)
          mem-ramp  --target-mb MiB (256)  --step-mb MiB (64)  --step-ms ms (0)  --hold-ms ms (0)  --seed N (1)
          output    --bytes N (1048576)  --line-bytes N (100)  --stream stdout|stderr|both|none (stdout)  --seed N (1)
          fork      --width N (2)  --depth N (2)  --hold-ms ms (0)  --seed N (1)  [--fail-node id]
                    (--fail-node: the node with that id, e.g. 0.1, exits with 1 at once; a fault for tests)

        Every scenario accepts --report <file>. The JSON report goes to that file; without it,
        cpu, mem-ramp, fork and `output --stream none` print it on standard output.
        Exit codes: 0 success, 1 failure, 2 invalid command line.
        """;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            await Console.Out.WriteAsync(Usage).ConfigureAwait(false);
            return args.Length == 0 ? ExitCodes.Usage : ExitCodes.Success;
        }

        try
        {
            var options = ScenarioOptions.Parse(args[1..]);
            var report = args[0] switch
            {
                "cpu" => CpuScenario.Run(options),
                "mem-ramp" => MemoryRampScenario.Run(options),
                "output" => OutputScenario.Run(options),
                "fork" => await ForkScenario.RunAsync(options).ConfigureAwait(false),
                _ => throw new UsageException($"Unknown scenario '{args[0]}'."),
            };
            await WriteReportAsync(report, options.GetUnrecorded("report")).ConfigureAwait(false);
            return ExitCodes.Success;
        }
        catch (UsageException exception)
        {
            await Console.Error.WriteLineAsync($"arcforges-testload: {exception.Message}").ConfigureAwait(false);
            await Console.Error.WriteLineAsync("Run 'arcforges-testload --help' for the scenarios.").ConfigureAwait(false);
            return ExitCodes.Usage;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException
            or OperationCanceledException or JsonException)
        {
            await Console.Error.WriteLineAsync($"arcforges-testload: {exception.Message}").ConfigureAwait(false);
            return ExitCodes.Failure;
        }
    }

    private static async Task WriteReportAsync(ScenarioReport report, string? path)
    {
        var json = JsonSerializer.Serialize(report, TestLoadJsonContext.Default.ScenarioReport);
        if (path is not null)
        {
            await File.WriteAllTextAsync(path, json + "\n").ConfigureAwait(false);
        }
        else if (report.Scenario != "output" || report.Parameters["stream"] == "none")
        {
            await Console.Out.WriteLineAsync(json).ConfigureAwait(false);
        }
    }
}
