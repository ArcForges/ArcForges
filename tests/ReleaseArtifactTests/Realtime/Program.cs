// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace RealtimeAotProbe;

/// <summary>Runs the named offline checks and reports every failure.</summary>
internal sealed class SelfTestRunner
{
    private readonly List<(string Name, Func<Task> Body)> _cases = [];

    public int Count => _cases.Count;

    public void Add(string name, Func<Task> body) => _cases.Add((name, body));

    [SuppressMessage("Design", "CA1031", Justification = "A self-test boundary reports every check failure, whatever its type, and turns it into a failing exit code.")]
    public async Task<int> RunAsync(TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(output);
        int failed = 0;
        foreach ((string name, Func<Task> body) in _cases)
        {
            try
            {
                await body().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                failed++;
                await output.WriteLineAsync(ex is SelfTestException ? $"FAIL: {name}: {ex.Message}" : $"FAIL: {name}: {ex}").ConfigureAwait(false);
            }
        }

        await output.WriteLineAsync(failed == 0
            ? $"PASS: {_cases.Count} offline checks of the realtime client logic, the generated contract codecs and the binary gRPC-Web transport."
            : $"FAIL: {failed} of {_cases.Count} offline checks failed.").ConfigureAwait(false);
        return failed == 0 ? 0 : 1;
    }
}

internal static class Program
{
    private const string SelfTestFlag = "--self-test";

    // A managed run has RealtimeAotProbe.dll beside it; a Native AOT image does not. The line only reports which one ran.
    private static bool IsNativeImage() => !File.Exists(Path.Combine(AppContext.BaseDirectory, "RealtimeAotProbe.dll"));

    public static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        TextWriter output = Console.Out;
        await output.WriteLineAsync("Runtime: " + (IsNativeImage() ? "Native AOT image" : "managed JIT (not an AOT result)")).ConfigureAwait(false);
        if (args.Length == 0 || (args.Length == 1 && args[0] == SelfTestFlag))
        {
            var runner = new SelfTestRunner();
            SelfTestPure.Register(runner);
            SelfTestWire.Register(runner);
            SelfTestStreams.Register(runner);
            SelfTestReaders.Register(runner);
            return await runner.RunAsync(output).ConfigureAwait(false);
        }

        if (args[0] == "--live")
        {
            LiveOptions options;
            try
            {
                options = LiveOptions.Parse(args, Environment.GetEnvironmentVariable);
            }
            catch (ArgumentException ex)
            {
                await Console.Error.WriteLineAsync(ex.Message).ConfigureAwait(false);
                return 2;
            }

            using var cancel = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancel.Cancel();
            };
            await output.WriteLineAsync("LIVE run against a deployed ingress; this is an explicit local opt-in and its result is whatever is printed below.").ConfigureAwait(false);
            return await LiveRun.RunAsync(options, output, cancel.Token).ConfigureAwait(false);
        }

        await Console.Error.WriteLineAsync("Usage: RealtimeAotProbe [--self-test] | --live <base-url> --subscription <key> [--output-task <uuid>] [--mode watch|poll] [--seconds n]").ConfigureAwait(false);
        return 2;
    }
}
