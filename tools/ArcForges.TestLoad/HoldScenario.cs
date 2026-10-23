// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace ArcForges.TestLoad;

/// <summary>
/// <c>hold</c> (both platforms): a process that waits, the input of the ordering, dependency, key and readiness tests of the scheduler
/// (03 section 4; 04 section 8). It records <c>start &lt;pid&gt; &lt;unix ms&gt;</c> and, before it exits, <c>end &lt;pid&gt; &lt;unix ms&gt;</c>
/// in the <c>marker</c> file; after <c>ready-after-ms</c> it prints <c>ready-line</c> on standard output, listens on
/// <c>127.0.0.1:port</c> and creates <c>file</c> (each when given), records <c>ready &lt;pid&gt; &lt;unix ms&gt;</c>, then holds for <c>hold-ms</c> and exits with <c>exit-code</c>.
/// With <c>until-file</c> it holds until that file exists instead (polled every 20 ms; <c>hold-ms</c> then bounds the hold), so a test releases
/// it rather than racing a wall-clock window.
/// </summary>
internal static class HoldScenario
{
    public const long MaxHoldMs = 24L * 60 * 60 * 1000;

    public static ScenarioReport Run(ScenarioOptions options)
    {
        var holdMs = options.GetInt64("hold-ms", 1000, 0, MaxHoldMs);
        var readyAfterMs = options.GetInt64("ready-after-ms", 0, 0, MaxHoldMs);
        var port = (int)options.GetInt64("port", 0, 0, 65_535);
        var exitCode = (int)options.GetInt64("exit-code", 0, 0, 255);
        var readyLine = options.GetOptional("ready-line");
        var file = options.GetUnrecorded("file");
        var marker = options.GetUnrecorded("marker");
        var untilFile = options.GetUnrecorded("until-file");
        options.GetUnrecorded("report");
        options.EnsureAllUsed();

        var stopwatch = Stopwatch.StartNew();
        Mark(marker, "start");
        Thread.Sleep(TimeSpan.FromMilliseconds(readyAfterMs));
        TcpListener? listener = null;
        if (port > 0)
        {
            listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
        }

        if (file is not null)
        {
            File.WriteAllText(file, "ready");
        }

        if (readyLine is not null)
        {
            Console.Out.WriteLine(readyLine);
            Console.Out.Flush();
        }

        Mark(marker, "ready");
        if (untilFile is null)
        {
            Thread.Sleep(TimeSpan.FromMilliseconds(holdMs));
        }
        else
        {
            var held = Stopwatch.StartNew();
            while (!File.Exists(untilFile) && held.ElapsedMilliseconds < holdMs)
            {
                Thread.Sleep(20);
            }
        }
        listener?.Stop();
        Mark(marker, "end");
        if (exitCode != 0)
        {
            Environment.Exit(exitCode);
        }

        using var digest = Deterministic.StartDigest(options.Canonical("hold"));
        return new ScenarioReport
        {
            Scenario = "hold",
            Parameters = options.Parameters,
            Digest = Deterministic.Hex(digest.GetHashAndReset()),
            Results = new Dictionary<string, long>(StringComparer.Ordinal) { ["holdMs"] = holdMs },
            Measured = Measurements.Collect(stopwatch),
        };
    }

    private static void Mark(string? marker, string what)
    {
        if (marker is null)
        {
            return;
        }

        var line = string.Create(CultureInfo.InvariantCulture, $"{what} {Environment.ProcessId} {DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}\n");
        using var stream = new FileStream(marker, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        stream.Write(System.Text.Encoding.UTF8.GetBytes(line));
    }
}
