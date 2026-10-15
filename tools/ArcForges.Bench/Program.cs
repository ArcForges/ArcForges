// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;

namespace ArcForges.Bench;

internal static class ExitCodes
{
    public const int Success = 0;
    public const int Failure = 1;
    public const int Usage = 2;
}

internal static class Program
{
    internal const string Usage = """
        arcforges-bench: performance benchmarks of 15-performance-targets (JSON results).

        usage:
          arcforges-bench size --path <file|directory> (--target <name> | --max-mb N [--name label]) [--output file]
              targets: arcforges (file, 45 MB), arcforges-supervisor (file, 4 MB),
                       arcforges-desktop (directory without the native Skia library, 60 MB)
          arcforges-bench startup --exe <path> [--arg value ...] [--runs N (50)] [--warmup N (1)]
              [--expect-exit code (0)] [--timeout-ms ms per run (30000)] [--max-p50-ms ms] [--max-p95-ms ms]
              [--name label] [--output file]
          arcforges-bench compare-startup --baseline-exe <path> --current-exe <path> [--arg value ...] [--runs N (50)] [--warmup N (1)]
              [--expect-exit code (0)] [--timeout-ms ms per run (30000)] [--name label] [--baseline-source text]
              [--max-regression-percent N (25)] [--noise-floor-ms ms (5)] [--output file]
              measures both executables on this machine, interleaved (the CI gate)
          arcforges-bench compare-startup --current <startup.json> (--baseline <startup.json> | --reason text)
              [--baseline-source text] [--max-regression-percent N (25)] [--noise-floor-ms ms (5)] [--output file]
              compares two saved results (meaningful only from the same machine), or records one without a baseline
              a regression is a p50 increase above both the percentage and the noise floor
          arcforges-bench store-growth --environment <captured environment JSON> [--environment ...] [--attempts N (10000)]
              [--seed N (1)] [--max-mb-per-10000 MB (50)] [--data-root <new directory, kept>] [--acks true|false (false)]
              [--name label] [--output file]
              synthetic attempts through the node store's submit path; the database must stay within the limit,
              scaled to the attempt count (node-store.md section 4); --acks prints "ack <command id>" per committed submission

        1 MB = 1,000,000 bytes; debug symbols are never counted.
        Exit codes: 0 within limits, 1 over a limit or failed, 2 invalid command line.
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
            string json;
            bool pass;
            BenchOptions options;
            switch (args[0])
            {
                case "size":
                    options = BenchOptions.Parse(args[1..]);
                    var size = SizeBenchmark.Run(options);
                    (json, pass) = (JsonSerializer.Serialize(size, BenchJsonContext.Default.SizeResult), size.Pass);
                    break;
                case "startup":
                    options = BenchOptions.Parse(args[1..], "arg");
                    var startup = await StartupBenchmark.RunAsync(options).ConfigureAwait(false);
                    (json, pass) = (JsonSerializer.Serialize(startup, BenchJsonContext.Default.StartupResult), startup.Pass);
                    break;
                case "store-growth":
                    options = BenchOptions.Parse(args[1..], "environment");
                    var growth = StoreGrowthBenchmark.Run(options, Console.Out);
                    (json, pass) = (JsonSerializer.Serialize(growth, BenchJsonContext.Default.StoreGrowthResult), growth.Pass);
                    break;
                case "compare-startup":
                    options = BenchOptions.Parse(args[1..], "arg");
                    var comparison = await StartupComparison.RunAsync(options).ConfigureAwait(false);
                    (json, pass) = (JsonSerializer.Serialize(comparison, BenchJsonContext.Default.StartupComparisonResult), comparison.Pass);
                    break;
                default:
                    throw new UsageException($"Unknown benchmark '{args[0]}'.");
            }

            var output = options.GetString("output");
            if (output is not null)
            {
                await File.WriteAllTextAsync(output, json + "\n").ConfigureAwait(false);
            }

            await Console.Out.WriteLineAsync(json).ConfigureAwait(false);
            if (!pass)
            {
                await Console.Error.WriteLineAsync($"arcforges-bench: {args[0]} is over its limit.").ConfigureAwait(false);
            }

            return pass ? ExitCodes.Success : ExitCodes.Failure;
        }
        catch (UsageException exception)
        {
            await Console.Error.WriteLineAsync($"arcforges-bench: {exception.Message}").ConfigureAwait(false);
            await Console.Error.WriteLineAsync("Run 'arcforges-bench --help' for usage.").ConfigureAwait(false);
            return ExitCodes.Usage;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException
            or JsonException or System.ComponentModel.Win32Exception)
        {
            await Console.Error.WriteLineAsync($"arcforges-bench: {exception.Message}").ConfigureAwait(false);
            return ExitCodes.Failure;
        }
    }
}
