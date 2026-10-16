// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// F-N03 (console part; L-18; architecture 04 section 6 step 1): the graceful phase through the <c>arcforges node signal</c> helper on
/// Windows 11. The root process runs with <c>CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP</c> under its holder; the helper attaches to its
/// windowless console and generates CTRL_BREAK_EVENT for its process group. Descendants with their own process group or console do not
/// receive it; GUI processes get WM_CLOSE on their (hidden) top-level windows; a failed attach is reported; and the forced phase ends
/// whatever is left. The workloads are <c>arcforges-testload signal</c> trees; every window is hidden and created inside the attempt. The
/// windowless supervisor at logon (H-15) is the user's end-to-end check and is not part of these tests.
/// </summary>
[Trait("env", "windows-real")]
[Collection(SerialPlatformTests.Name)]
[SupportedOSPlatform("windows")]
public sealed class SignalTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(30);

    [Fact(Timeout = 120_000)]
    public async Task CtrlBreakReachesTheRootsProcessGroupThroughTheHelper()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows console control events and the node signal helper.");
        using var harness = PlatformHarness.Start();
        var marker = Path.Combine(harness.Root, "marker.txt");
        var handle = harness.Launch([TestPrograms.TestLoad, "signal", "--hold-ms", "60000", "--child", "same", "--marker", marker]);
        await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        PlatformHarness.WaitFor(() => Ready(marker).Count == 2, Bound, "the root and its same-group child");

        var signalled = DateTimeOffset.UtcNow;
        var outcome = handle.RequestGracefulStop();
        Assert.True(outcome.ConsoleSignalled, outcome.Reason);
        Assert.Null(outcome.Reason);

        // Both processes of the group received the event and ended on their own, well within the default grace period.
        PlatformHarness.WaitFor(() => Events(marker, "break").Count == 2, TimeSpan.FromSeconds(5), "CTRL_BREAK in both processes");
        var exit = harness.WaitExit(handle, TimeSpan.FromSeconds(10));
        Assert.Equal(3, exit.ExitStatus);
        Assert.Empty(exit.LeftoversTerminated);
        Assert.True(DateTimeOffset.Parse(exit.RecordedAt, System.Globalization.CultureInfo.InvariantCulture) - signalled < TimeSpan.FromSeconds(10));
    }

    [Theory(Timeout = 120_000)]
    [InlineData("group")]
    [InlineData("console")]
    public async Task ADescendantWithItsOwnGroupOrConsoleMissesTheEventAndIsForced(string child)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows console control events and the node signal helper.");
        using var harness = PlatformHarness.Start();
        var marker = Path.Combine(harness.Root, "marker.txt");
        var handle = harness.Launch([TestPrograms.TestLoad, "signal", "--hold-ms", "60000", "--child", child, "--marker", marker]);
        await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        PlatformHarness.WaitFor(() => Ready(marker).Count == 2, Bound, "the root and its child");
        var rootPid = handle.Root!.Pid;
        var childProcess = Ready(marker).Single(process => process.Pid != rootPid);

        var outcome = handle.RequestGracefulStop();
        Assert.True(outcome.ConsoleSignalled, outcome.Reason);
        PlatformHarness.WaitFor(() => Events(marker, "break").Contains(rootPid), TimeSpan.FromSeconds(5), "CTRL_BREAK in the root");
        await Task.Delay(1_000, TestContext.Current.CancellationToken);
        Assert.DoesNotContain(childProcess.Pid, Events(marker, "break"));
        Assert.True(childProcess.IsRunning(), $"The {child} child ignores the root's group event and keeps running.");

        // The forced phase ends the whole job either way.
        handle.Terminate();
        PlatformHarness.WaitFor(() => handle.Job.Accounting().ActiveProcesses == 0, TimeSpan.FromSeconds(5), "the job to be empty");
        Assert.False(childProcess.IsRunning());
    }

    [Fact(Timeout = 120_000)]
    public async Task AGuiProcessInTheTreeGetsWmCloseOnItsHiddenWindow()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows console control events and the node signal helper.");
        using var harness = PlatformHarness.Start();
        var marker = Path.Combine(harness.Root, "marker.txt");
        var handle = harness.Launch([TestPrograms.TestLoad, "signal", "--hold-ms", "60000", "--child", "window", "--marker", marker]);
        await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        PlatformHarness.WaitFor(() => Ready(marker).Count == 2, Bound, "the root and its window child");
        var rootPid = handle.Root!.Pid;
        var childProcess = Ready(marker).Single(process => process.Pid != rootPid);
        PlatformHarness.WaitFor(() => GuiWindows.TopLevelWindows().Any(window => window.ProcessId == childProcess.Pid), Bound, "the child's hidden window");
        Assert.DoesNotContain(GuiWindows.TopLevelWindows(), window => window.ProcessId == childProcess.Pid && IsWindowVisible(window.Window));

        var outcome = handle.RequestGracefulStop();
        Assert.True(outcome.ConsoleSignalled, outcome.Reason);
        Assert.True(outcome.WindowsClosed >= 1, "WM_CLOSE was posted to the child's window.");
        PlatformHarness.WaitFor(() => Events(marker, "close").Contains(childProcess.Pid), TimeSpan.FromSeconds(5), "WM_CLOSE in the window child");
        PlatformHarness.WaitFor(() => !childProcess.IsRunning(), TimeSpan.FromSeconds(5), "the window child to exit");
        Assert.DoesNotContain(childProcess.Pid, Events(marker, "break"));
        harness.WaitExit(handle, Bound);
    }

    [Fact(Timeout = 120_000)]
    public async Task AFailedAttachIsReportedAndTheForcedPhaseEndsTheTree()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows console control events and the node signal helper.");
        using var harness = PlatformHarness.Start();
        var marker = Path.Combine(harness.Root, "marker.txt");

        // The root gives up its console, as a non-console program has none.
        var handle = harness.Launch([TestPrograms.TestLoad, "signal", "--hold-ms", "60000", "--free-console", "1", "--marker", marker]);
        await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        PlatformHarness.WaitFor(() => Ready(marker).Count == 1, Bound, "the root");
        var outcome = handle.RequestGracefulStop();
        Assert.False(outcome.ConsoleSignalled);
        Assert.Contains("could not attach", outcome.Reason, StringComparison.Ordinal);
        Assert.True(PlatformHarness.Identity(handle.Root!).IsRunning());
        handle.Terminate();
        Assert.Equal((int)AttemptRunner.TerminatedExitCode, harness.WaitExit(handle, Bound).ExitStatus);
    }

    [Fact(Timeout = 120_000)]
    public async Task AnExitedRootIsReportedAndItsLeftoversAreForced()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows console control events and the node signal helper.");
        using var harness = PlatformHarness.Start();
        var marker = Path.Combine(harness.Root, "marker.txt");
        var handle = harness.Launch([TestPrograms.TestLoad, "signal", "--hold-ms", "500", "--child", "group", "--child-hold-ms", "60000", "--marker", marker],
            leftoverGraceMs: 30_000);
        await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        var rootProcess = PlatformHarness.Identity(handle.Root!);
        PlatformHarness.WaitFor(() => !rootProcess.IsRunning(), Bound, "the root to exit");
        var outcome = handle.RequestGracefulStop();
        Assert.False(outcome.ConsoleSignalled);
        Assert.Equal("the root process exited", outcome.Reason);
        handle.Terminate();
        var exit = harness.WaitExit(handle, Bound);
        Assert.Equal(0, exit.ExitStatus);
    }

    [Fact(Timeout = 120_000)]
    public async Task ATreeThatIgnoresTheGracefulSignalIsTerminatedByTheForcedPhase()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows console control events and the node signal helper.");
        using var harness = PlatformHarness.Start();
        var marker = Path.Combine(harness.Root, "marker.txt");
        var handle = harness.Launch([TestPrograms.TestLoad, "signal", "--hold-ms", "60000", "--on-break", "ignore", "--child", "same", "--marker", marker]);
        await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        PlatformHarness.WaitFor(() => Ready(marker).Count == 2, Bound, "the tree");
        var pids = Ready(marker);
        Assert.True(handle.RequestGracefulStop().ConsoleSignalled);
        PlatformHarness.WaitFor(() => Events(marker, "break").Count == 2, TimeSpan.FromSeconds(5),
            "both to see the event: " + PlatformHarness.ReadShared(marker).ReplaceLineEndings(" | "));
        await Task.Delay(500, TestContext.Current.CancellationToken);
        Assert.All(pids, process => Assert.True(process.IsRunning()));
        handle.Terminate();
        PlatformHarness.WaitFor(() => handle.Job.Accounting().ActiveProcesses == 0, TimeSpan.FromSeconds(5), "the job to be empty");
        Assert.All(pids, process => Assert.False(process.IsRunning()));
    }

    private static List<ArcForges.Tests.ProcessIdentity> Ready(string marker) => PlatformHarness.MarkerProcesses(marker, "ready");

    private static List<int> Events(string marker, string name) => [.. PlatformHarness.Marker(marker).Where(line => line.Event == name).Select(line => line.Pid)];

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(nint window);
}
