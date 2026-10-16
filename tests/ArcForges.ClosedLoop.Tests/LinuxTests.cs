// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using ArcForges.Client;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// Linux platform behaviour with real processes (env=linux-real): the owner-only socket directory and socket, the 0700 data root,
/// and the development systemd user unit (13 section 3.4): auto-start through <c>systemctl --user start</c>, readiness through
/// <c>sd_notify</c>, restart after a crash, and no restart after a requested stop. The unit is installed only for the test, in the
/// runtime unit directory (<c>$XDG_RUNTIME_DIR/systemd/user</c>), and removed afterwards; nothing is enabled.
/// </summary>
[Trait("env", "linux-real")]
[UnsupportedOSPlatform("windows")]
public sealed class LinuxTests
{
    private const UnixFileMode GroupOrOther = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    [Fact(Timeout = 120_000)]
    public async Task TheSocketAndTheDataRootAreOwnerOnly()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix sockets and modes.");
        await using var node = TestNode.Create();
        await node.StartNodeAsync();

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(Path.GetDirectoryName(node.Endpoint)!));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(node.Endpoint) & ~(UnixFileMode)0xF000);
        Assert.Equal((UnixFileMode)0, File.GetUnixFileMode(node.DataRoot) & GroupOrOther);
        Assert.Equal((UnixFileMode)0, File.GetUnixFileMode(Path.Combine(node.DataRoot, "run")) & GroupOrOther);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(node.DataRoot, "node.lock")));
    }

    [Fact(Timeout = 180_000)]
    public async Task TheUserUnitAutoStartsTheNodeAndRestartsItAfterACrash()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(OperatingSystem.IsWindows(), "systemd user units.");
        Assert.SkipUnless(Linux.UserManagerAvailable(), "requires-user-manager: no systemd user manager runs for this user.");
        await using var node = TestNode.Create();
        var unit = "arcforges-node-test-" + Guid.NewGuid().ToString("N")[..10] + ".service";
        var unitDirectory = Path.Combine(Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR")!, "systemd", "user");
        var unitFile = Path.Combine(unitDirectory, unit);
        Directory.CreateDirectory(unitDirectory);
        var template = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Procedures", "arcforges-node.service"));
        var variables = node.Environment.Where(pair => pair.Value is not null).Select(pair => (pair.Key, Value: pair.Value!)).ToList();
        if (Environment.GetEnvironmentVariable("DOTNET_ROOT") is { Length: > 0 } dotnetRoot)
        {
            // The JIT build's apphost finds the runtime through DOTNET_ROOT; the user manager's environment may not have it.
            variables.Add(("DOTNET_ROOT", dotnetRoot));
        }

        var environment = string.Join("\n", variables.Select(pair => $"Environment=\"{pair.Key}={pair.Value}\""));
        File.WriteAllText(unitFile, template
            .Replace("@ARCFORGES@ node run --systemd", $"{TestNode.Host} node run --systemd {NodeLocations.TestModeOption}", StringComparison.Ordinal)
            .Replace("[Service]\n", "[Service]\n" + environment + "\n", StringComparison.Ordinal));
        node.Environment[NodeLocations.NodeUnitVariable] = unit;
        try
        {
            // No daemon-reload: the manager loads the new unit on its first use (a reload stalls the manager for the tests beside this one).
            var status = await node.CliAsync("status", "--json");
            Assert.True(status.ExitCode == 0, status.ToString());
            Assert.True(status.Json().GetProperty("autoStarted").GetBoolean());
            var first = await MainPidAsync(unit);
            Assert.Equal(first, node.NodePid());
            Assert.Equal("active", (await SystemctlAsync("is-active", unit)).Output.Trim());
            Assert.Contains("\"systemd\":true", File.ReadAllText(node.NodeLog), StringComparison.Ordinal);

            // A crash (SIGKILL): Restart=on-failure, RestartSec=2.
            using (var crashed = Process.GetProcessById(first))
            {
                crashed.Kill();
            }

            await TestNode.WaitAsync(async () => await MainPidAsync(unit) is var pid && pid != 0 && pid != first, TimeSpan.FromSeconds(30), "systemd to restart the node");
            await node.WaitReadyAsync();
            Assert.Equal("active", (await SystemctlAsync("is-active", unit)).Output.Trim());

            // A requested stop exits 0: systemd does not restart it.
            Assert.Equal(0, (await node.CliAsync("node", "stop")).ExitCode);
            await TestNode.WaitAsync(async () => (await SystemctlAsync("is-active", unit)).Output.Trim() is "inactive", TimeSpan.FromSeconds(30),
                "the unit to become inactive");
            // A deliberate hold longer than RestartSec (2 s): the absence of a restart cannot be awaited.
            await Task.Delay(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
            Assert.Equal("inactive", (await SystemctlAsync("is-active", unit)).Output.Trim());
        }
        finally
        {
            await SystemctlAsync("stop", unit);
            File.Delete(unitFile);
            await SystemctlAsync("reset-failed", unit);
        }
    }

    private static async Task<int> MainPidAsync(string unit)
    {
        var run = await SystemctlAsync("show", "--property=MainPID", "--value", unit);
        return int.TryParse(run.Output.Trim(), out var pid) ? pid : 0;
    }

    private static async Task<ProcessRun> SystemctlAsync(params string[] arguments)
    {
        var start = new ProcessStartInfo("systemctl") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        start.ArgumentList.Add("--user");
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        return await TestNode.CompleteAsync(process, TimeSpan.FromSeconds(30));
    }
}
