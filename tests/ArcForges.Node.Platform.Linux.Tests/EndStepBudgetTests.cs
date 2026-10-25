// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using ArcForges.Tests;

namespace ArcForges.Node.Platform.Linux.Tests;

/// <summary>The real unit and observe-only child paths share one ten-second end-step budget.</summary>
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class EndStepBudgetTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(60);

    [Theory(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [InlineData(true, -1)]
    [InlineData(true, 0)]
    [InlineData(true, -2)]
    [InlineData(true, 30_000)]
    [InlineData(false, -1)]
    [InlineData(false, 0)]
    [InlineData(false, -2)]
    [InlineData(false, 30_000)]
    public void EndStepsShareTheirTotalBudgetForNonpositiveAndLongTimeouts(bool unit, int timeoutMs)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux units and observe-only children.");
        if (unit)
        {
            Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        }

        using var harness = unit ? LinuxHarness.Start() : LinuxHarness.Start(options: slice => new LinuxPlatformOptions
        {
            Slice = slice,
            ManagerAddress = "unix:path=/nonexistent/arcforges-test-bus",
        });
        Assert.Equal(unit, harness.Platform.UnitMode);
        var files = harness.Files(out _);
        var firstMarker = Path.Combine(harness.Root, "first-end.pid");
        var secondMarker = Path.Combine(harness.Root, "second-end.pid");
        var lateMarker = Path.Combine(harness.Root, "late-end.txt");
        const string hold = """echo $$ > "$1"; exec sleep 15;""";
        const string mark = """echo ran > "$1";""";
        var handle = harness.Launch(["/bin/sh", "-c", "exit 0"], files: files, leftoverGraceMs: 0, endSteps:
        [
            LinuxHarness.Step("consume-budget", 4_000, "/bin/sh", "-c", hold, "sh", firstMarker),
            LinuxHarness.Step("remaining-budget", timeoutMs, "/bin/sh", "-c", hold, "sh", secondMarker),
            LinuxHarness.Step("must-not-start", 1_000, "/bin/sh", "-c", mark, "sh", lateMarker),
        ]);
        var children = new List<ArcForges.Tests.ProcessIdentity>();
        try
        {
            LinuxHarness.WaitFor(() => ReadPid(firstMarker) is not null, Bound, "the first real end step");
            var firstPid = Assert.IsType<int>(ReadPid(firstMarker));
            children.Add(Assert.IsType<ArcForges.Tests.ProcessIdentity>(ArcForges.Tests.ProcessIdentity.Capture(firstPid)));
            var elapsed = Stopwatch.StartNew();
            var completionBound = TimeSpan.FromSeconds(12); // Ten-second shared budget plus scheduling/recording slack.
            LinuxHarness.WaitFor(() => ReadPid(secondMarker) is not null || handle.TryReadExit() is not null,
                completionBound, "the second end step or an incorrectly early completion");
            var secondPid = Assert.IsType<int>(ReadPid(secondMarker));
            children.Add(Assert.IsType<ArcForges.Tests.ProcessIdentity>(ArcForges.Tests.ProcessIdentity.Capture(secondPid)));
            var remaining = completionBound - elapsed.Elapsed;
            Assert.True(remaining > TimeSpan.Zero, "The second step already exceeded the total end-step budget.");
            var exit = LinuxHarness.WaitExit(handle, remaining);
            Assert.True(elapsed.Elapsed >= TimeSpan.FromSeconds(8), "A nonpositive timeout must let the second step use the remaining budget.");
            Assert.True(elapsed.Elapsed < completionBound, $"The end steps took {elapsed.Elapsed}; the shared budget is 10 seconds.");
            Assert.Equal(("exited", 0, "success"), (exit.ExitCodeKind, exit.ExitStatus, exit.ServiceResult));
            Assert.Equal(unit ? "exit-record" : "node", exit.RecordedBy);
            Assert.Null(LaunchRecord.TryRead(files.LaunchPath));
            Assert.False(File.Exists(lateMarker), "No later end step may start after the total budget is consumed.");
            if (unit)
            {
                var stop = StopRecord.TryRead(files.StopPath);
                Assert.NotNull(stop);
                Assert.Equal(["timed_out", "timed_out", "skipped"], stop.EndSteps.Select(step => step.Outcome));
            }
        }
        finally
        {
            // The before-fix direct path may wait on its real 15-second child beyond the assertion bound. Let those exact children
            // finish and be reaped; never touch the user's systemd manager or another process group.
            LinuxHarness.WaitFor(() => children.All(child => !child.IsRunning()), Bound, "the fixture's end-step children to exit");
        }
    }

    private static int? ReadPid(string path)
    {
        try
        {
            return File.Exists(path) && int.TryParse(File.ReadAllText(path), NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid) ? pid : null;
        }
        catch (IOException)
        {
            return null;
        }
    }
}
