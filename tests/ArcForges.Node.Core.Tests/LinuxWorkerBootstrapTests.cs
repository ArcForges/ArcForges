// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using ArcForges.Client;

namespace ArcForges.Node.Core.Tests;

/// <summary>The actual Host CLI rejects the retired Linux file worker commands.</summary>
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class LinuxWorkerBootstrapTests
{
    [Theory(Timeout = 30_000)]
    [InlineData("file-effect-worker", false)]
    [InlineData("file-effect-worker", true)]
    [InlineData("file-effect-selftest", false)]
    [InlineData("file-effect-selftest", true)]
    public async Task TheHostRejectsRetiredFileWorkerCommands(string command, bool testMode)
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux file worker commands.");
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        var host = Path.Combine(AppContext.BaseDirectory, "arcforges");
        Assert.True(File.Exists(host));
        var start = new ProcessStartInfo(host)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("node");
        start.ArgumentList.Add(command);
        if (testMode)
        {
            start.ArgumentList.Add(NodeLocations.TestModeOption);
        }

        using var child = Process.Start(start) ?? throw new InvalidOperationException("Could not start the owned Host process.");
        try
        {
            child.StandardInput.Close();
            var output = child.StandardOutput.ReadToEndAsync(ct);
            var error = child.StandardError.ReadToEndAsync(ct);
            await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.Equal(2, child.ExitCode);
            Assert.Empty(await output);
            Assert.Contains(command, await error, StringComparison.Ordinal);
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill();
                Assert.True(child.WaitForExit(10_000), "The owned Host process did not exit after termination.");
            }
        }
    }
}
