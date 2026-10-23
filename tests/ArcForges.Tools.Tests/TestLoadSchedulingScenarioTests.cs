// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace ArcForges.Tools.Tests;

/// <summary>
/// The real arcforges-testload <c>hold</c> and <c>probe</c> scenarios (the inputs of the scheduler tests and of the headroom target of
/// 15 section 4): <c>hold</c> records start, readiness and end, signals readiness by a line, a listening port and a file, and exits with
/// its code; <c>probe</c> counts its periods and missed deadlines and reports the completion latencies.
/// </summary>
public sealed class TestLoadSchedulingScenarioTests
{
    [Fact(Timeout = 60_000)]
    public async Task HoldRecordsItsWindowAndSignalsReadinessEveryWay()
    {
        using var directory = new TemporaryDirectory();
        var marker = Path.Combine(directory.Path, "marker.txt");
        var flag = Path.Combine(directory.Path, "ready.flag");
        int port;
        using (var free = new TcpListener(IPAddress.Loopback, 0))
        {
            free.Start();
            port = ((IPEndPoint)free.LocalEndpoint).Port;
        }

        var run = ToolProcess.RunAsync(ToolProcess.TestLoad,
            ["hold", "--hold-ms", "1500", "--ready-after-ms", "300", "--ready-line", "service ready", "--port", port.ToString(CultureInfo.InvariantCulture),
                "--file", flag, "--exit-code", "7", "--marker", marker], TestContext.Current.CancellationToken);

        // While it holds, the port accepts a connection and the file exists.
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (!File.Exists(flag))
        {
            Assert.True(DateTime.UtcNow < deadline, "the readiness file was not created");
            await Task.Delay(25, TestContext.Current.CancellationToken);
        }

        using (var client = new TcpClient())
        {
            await client.ConnectAsync(IPAddress.Loopback, port, TestContext.Current.CancellationToken);
            Assert.True(client.Connected);
        }

        var result = await run;
        Assert.Equal(7, result.ExitCode);
        Assert.Contains("service ready", Encoding.UTF8.GetString(result.StandardOutput), StringComparison.Ordinal);
        var lines = File.ReadAllLines(marker).Select(line => line.Split(' ')).ToList();
        Assert.Equal(["start", "ready", "end"], lines.Select(parts => parts[0]));
        var times = lines.Select(parts => long.Parse(parts[2], CultureInfo.InvariantCulture)).ToList();
        Assert.True(times[1] - times[0] >= 250, $"ready {times[1] - times[0]} ms after the start");
        Assert.True(times[2] - times[1] >= 1_400, $"held {times[2] - times[1]} ms after readiness");
        Assert.All(lines, parts => Assert.Equal(lines[0][1], parts[1]));
    }

    [Fact(Timeout = 60_000)]
    public async Task HoldWithAnUntilFileHoldsUntilTheFileExists()
    {
        using var directory = new TemporaryDirectory();
        var marker = Path.Combine(directory.Path, "marker.txt");
        var release = Path.Combine(directory.Path, "release.flag");
        var run = ToolProcess.RunAsync(ToolProcess.TestLoad, ["hold", "--hold-ms", "30000", "--until-file", release, "--marker", marker],
            TestContext.Current.CancellationToken);
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (!File.Exists(marker) || !File.ReadAllText(marker).Contains("ready", StringComparison.Ordinal))
        {
            Assert.True(DateTime.UtcNow < deadline, "the hold did not become ready");
            await Task.Delay(25, TestContext.Current.CancellationToken);
        }

        // It holds while the file is absent (the 30 s hold-ms is only its bound), and ends once the file exists.
        await Task.Delay(1_000, TestContext.Current.CancellationToken);
        Assert.False(run.IsCompleted, "the hold ended before its release file existed");
        await File.WriteAllTextAsync(release, "go", TestContext.Current.CancellationToken);
        var result = await run.WaitAsync(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal(["start", "ready", "end"], File.ReadAllLines(marker).Select(line => line.Split(' ')[0]));
    }

    [Fact(Timeout = 60_000)]
    public async Task ProbeCountsItsPeriodsAndMissedDeadlines()
    {
        using var directory = new TemporaryDirectory();
        var report = Path.Combine(directory.Path, "probe.json");
        var run = await ToolProcess.RunAsync(ToolProcess.TestLoad,
            ["probe", "--period-ms", "100", "--deadline-ms", "10", "--work-us", "500", "--duration-ms", "1500", "--report", report], TestContext.Current.CancellationToken);
        Assert.Equal(0, run.ExitCode);
        using var written = JsonDocument.Parse(await File.ReadAllBytesAsync(report, TestContext.Current.CancellationToken));
        var root = written.RootElement;
        Assert.Equal("probe", root.GetProperty("scenario").GetString());
        Assert.Equal(15, root.GetProperty("results").GetProperty("periods").GetInt64());
        Assert.InRange(root.GetProperty("results").GetProperty("misses").GetInt64(), 0, 15);
        var measured = root.GetProperty("measured");
        Assert.True(measured.GetProperty("p50Us").GetInt64() >= 250, $"each period runs its calibrated work (p50 {measured.GetProperty("p50Us").GetInt64()} us for 500 us of work)");
        Assert.True(measured.GetProperty("maxUs").GetInt64() >= measured.GetProperty("p99Us").GetInt64());
        Assert.True(measured.GetProperty("p99Us").GetInt64() >= measured.GetProperty("p50Us").GetInt64());
    }

    [Theory(Timeout = 60_000)]
    [InlineData("probe", "--period-ms", "100", "--deadline-ms", "200")]
    [InlineData("probe", "--period-ms", "5")]
    [InlineData("hold", "--exit-code", "300")]
    [InlineData("hold", "--unknown", "1")]
    public async Task InvalidOptionsExitWithTwo(params string[] arguments)
    {
        var run = await ToolProcess.RunAsync(ToolProcess.TestLoad, arguments, TestContext.Current.CancellationToken);
        Assert.Equal(2, run.ExitCode);
    }
}
