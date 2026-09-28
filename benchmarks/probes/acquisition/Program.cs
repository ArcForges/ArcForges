// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;

namespace ArcForges.AcquisitionProbe;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Contains("--help", StringComparer.Ordinal))
        {
            Console.WriteLine("Usage: dotnet run --project benchmarks/probes/acquisition/AcquisitionProbe.csproj -c Release -- [--self-test] [--evidence <path>]");
            return 0;
        }

        string? evidencePath = ReadOption(args, "--evidence");
        using CancellationTokenSource cancellation = new();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        try
        {
            SustainedRunEvidence sustained = await TcpLoopbackScenarios.RunAcceptanceAsync(cancellation.Token).ConfigureAwait(false);
            OverrunEvidence overrun = await TcpLoopbackScenarios.RunOverrunAsync(cancellation.Token).ConfigureAwait(false);
            DisconnectEvidence disconnect = await TcpLoopbackScenarios.RunDisconnectAsync(cancellation.Token).ConfigureAwait(false);
            PauseEvidence pause = await TcpLoopbackScenarios.RunPauseAsync(cancellation.Token).ConfigureAwait(false);

            AcquisitionAcceptanceEvidence evidence = new(
                sustained,
                overrun,
                disconnect,
                pause,
                DateTimeOffset.UtcNow);
            string json = JsonSerializer.Serialize(evidence, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(json);

            if (!string.IsNullOrWhiteSpace(evidencePath))
            {
                string fullPath = Path.GetFullPath(evidencePath);
                Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
                await File.WriteAllTextAsync(fullPath, json + Environment.NewLine, cancellation.Token).ConfigureAwait(false);
                Console.WriteLine($"Evidence written: {fullPath}");
            }

            Console.WriteLine("PASS NAT.03: sustained localhost TCP acquisition, bounded ring, downsampling, overrun accounting, explicit disconnect gap, and recording while view paused.");
            return 0;
        }
        catch (OperationCanceledException)
        {
            await Console.Error.WriteLineAsync("NAT.03 acceptance probe cancelled.").ConfigureAwait(false);
            return 130;
        }
        catch (Exception exception)
        {
            await Console.Error.WriteLineAsync($"NAT.03 acceptance probe failed: {exception}").ConfigureAwait(false);
            return 1;
        }
    }

    private static string? ReadOption(string[] args, string name)
    {
        int index = Array.IndexOf(args, name);
        if (index < 0)
        {
            return null;
        }

        if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
        {
            throw new ArgumentException($"Option {name} requires a value.", nameof(args));
        }

        return args[index + 1];
    }
}

internal sealed record AcquisitionAcceptanceEvidence(
    SustainedRunEvidence SustainedRun,
    OverrunEvidence InducedOverrun,
    DisconnectEvidence InducedDisconnect,
    PauseEvidence PauseWhileRecording,
    DateTimeOffset RecordedAtUtc);
