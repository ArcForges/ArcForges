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
/// windowless supervisor at logon (H-15) is the user's end-to-end check and is not part of these tests. Every wait for an expected event
/// has the generous <see cref="Bound"/> (16 section 4: generous timeouts only on the failure path); the one timing contract, ending
/// within the default grace period, is asserted by an exclusive test.
/// </summary>
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class SignalTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(30);

    // isolation=exclusive: the tree must end on the event within the default grace period (cancel_grace 10 s, 04 section 6 step 2),
    // a timing contract.
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
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
        PlatformHarness.WaitFor(() => Events(marker, "break").Count == 2, Bound, "CTRL_BREAK in both processes");
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
        PlatformHarness.WaitFor(() => Events(marker, "break").Contains(rootPid), Bound, "CTRL_BREAK in the root");

        // A deliberate hold: the child still has not seen the event 1 s after the root did (an absence cannot be awaited).
        await Task.Delay(1_000, TestContext.Current.CancellationToken);
        Assert.DoesNotContain(childProcess.Pid, Events(marker, "break"));
        Assert.True(childProcess.IsRunning(), $"The {child} child ignores the root's group event and keeps running.");

        // The forced phase ends the whole job either way.
        handle.Terminate();
        PlatformHarness.WaitFor(() => handle.Job.Accounting().ActiveProcesses == 0, Bound, "the job to be empty");
        Assert.False(childProcess.IsRunning());
    }

    [Fact(Timeout = 120_000)]
    public async Task AGuiProcessInTheTreeGetsWmCloseOnItsHiddenWindow()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows console control events and the node signal helper.");
        using var harness = PlatformHarness.Start();
        var marker = Path.Combine(harness.Root, "marker.txt");
        // The root ends on the event; the leftover grace (04 section 3) gives the window child as long as the waits below.
        var handle = harness.Launch([TestPrograms.TestLoad, "signal", "--hold-ms", "60000", "--child", "window", "--marker", marker],
            leftoverGraceMs: (int)Bound.TotalMilliseconds);
        await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        PlatformHarness.WaitFor(() => Ready(marker).Count == 2 || Events(marker, "window-failed").Count > 0, Bound, "the root and its window child");
        Assert.True(Events(marker, "window-failed").Count == 0,
            "The window child could not create its hidden window: " + PlatformHarness.ReadShared(marker).ReplaceLineEndings(" | "));
        var rootPid = handle.Root!.Pid;
        var childProcess = Ready(marker).Single(process => process.Pid != rootPid);

        // The child's own window, by its class: while CreateWindowEx runs, the thread's Default IME window can be the process's only
        // top-level window.
        var windowClass = "ArcForgesTestLoadHidden" + childProcess.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture);
        PlatformHarness.WaitFor(() => PlatformHarness.WindowClasses(childProcess.Pid).Contains(windowClass), Bound,
            () => $"the child's hidden window {windowClass} (its windows: {string.Join(", ", PlatformHarness.WindowClasses(childProcess.Pid))})");
        Assert.DoesNotContain(GuiWindows.TopLevelWindows(), window => window.ProcessId == childProcess.Pid && IsWindowVisible(window.Window));
        // Its handle is taken while it runs (GetProcessById holds none): the failure description can read its exit code after it exited,
        // and a reused ID is never taken for it.
        using var child = System.Diagnostics.Process.GetProcessById(childProcess.Pid);
        _ = child.SafeHandle;
        var windowsBefore = string.Join(", ", PlatformHarness.WindowClasses(childProcess.Pid));

        var outcome = handle.RequestGracefulStop();
        Assert.True(outcome.ConsoleSignalled, outcome.Reason);
        Assert.True(outcome.WindowsClosed >= 1, "WM_CLOSE was posted to the child's window.");
        PlatformHarness.WaitFor(() => Events(marker, "close").Contains(childProcess.Pid), Bound,
            () => $"WM_CLOSE in the window child (the stop: {outcome.WindowsClosed} window(s) closed, reason {outcome.Reason ?? "none"}; "
                + $"the child's windows before the stop: {windowsBefore}; now: {string.Join(", ", PlatformHarness.WindowClasses(childProcess.Pid))}; "
                + $"the child {(child.HasExited ? "exited with " + child.ExitCode : "still runs")}; "
                + $"marker: {PlatformHarness.ReadShared(marker).ReplaceLineEndings(" | ")})");
        PlatformHarness.WaitFor(() => !childProcess.IsRunning(), Bound, "the window child to exit");
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
        PlatformHarness.WaitFor(() => Events(marker, "break").Count == 2, Bound,
            "both to see the event: " + PlatformHarness.ReadShared(marker).ReplaceLineEndings(" | "));

        // A deliberate hold: both still run 500 ms after the event they ignore (their survival cannot be awaited).
        await Task.Delay(500, TestContext.Current.CancellationToken);
        Assert.All(pids, process => Assert.True(process.IsRunning()));
        handle.Terminate();
        PlatformHarness.WaitFor(() => handle.Job.Accounting().ActiveProcesses == 0, Bound, "the job to be empty");
        Assert.All(pids, process => Assert.False(process.IsRunning()));
    }

    private static List<ArcForges.Tests.ProcessIdentity> Ready(string marker) => PlatformHarness.MarkerProcesses(marker, "ready");

    private static List<int> Events(string marker, string name) => [.. PlatformHarness.Marker(marker).Where(line => line.Event == name).Select(line => line.Pid)];

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(nint window);
}
