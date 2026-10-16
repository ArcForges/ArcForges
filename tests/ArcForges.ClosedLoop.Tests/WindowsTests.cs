// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ArcForges.Client;
using ArcForges.Supervisor;
using Microsoft.Win32;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// Windows platform behaviour with real processes (env=windows-real): the node pipe's same-user access list and remote refusal
/// (R-SEC-001, 11 section 2), the readiness event, and the supervisor (AD-0003 section 1; 02 section 2 Crash): GUI subsystem, the
/// HKCU Run autostart mechanism under a test key, crash restart with backoff and the crash-loop stop.
/// </summary>
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed partial class WindowsTests
{
    private static string Supervisor => Path.Combine(Path.GetDirectoryName(TestNode.Host)!, "arcforges-supervisor.exe");

    [Fact(Timeout = 120_000)]
    public async Task ThePipeAdmitsOnlyThisUser()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows named pipes.");
        await using var node = TestNode.Create();
        await node.StartNodeAsync();

        using (var pipe = new NamedPipeClientStream(".", node.Endpoint, PipeDirection.InOut, PipeOptions.None))
        {
            pipe.Connect(5000);
            var security = pipe.GetAccessControl();
            var user = WindowsIdentity.GetCurrent().User!;
            Assert.Equal(user, security.GetOwner(typeof(SecurityIdentifier)));
            Assert.True(security.AreAccessRulesProtected);
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToList();
            var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            Assert.Contains(rules, rule => rule.IdentityReference == network && rule.AccessControlType == AccessControlType.Deny);
            Assert.Contains(rules, rule => rule.IdentityReference == user && rule.AccessControlType == AccessControlType.Allow
                && rule.PipeAccessRights.HasFlag(PipeAccessRights.ReadWrite));
            Assert.All(rules.Where(rule => rule.AccessControlType == AccessControlType.Allow),
                rule => Assert.Contains(rule.IdentityReference, (IdentityReference[])[user, system]));
            Assert.All(rules, rule => Assert.False(rule.IsInherited));
        }

        // PIPE_REJECT_REMOTE_CLIENTS: the loopback redirector path is a remote client and is refused.
        using var remote = new NamedPipeClientStream("127.0.0.1", node.Endpoint, PipeDirection.InOut, PipeOptions.None);
        Assert.ThrowsAny<Exception>(() => remote.Connect(3000));

        // The node still serves its own user afterwards.
        Assert.Equal(0, (await node.CliAsync("node", "info")).ExitCode);
    }

    [Fact(Timeout = 120_000)]
    public async Task TheReadyEventIsSetOnlyWhileTheNodeServes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows readiness event.");
        await using var node = TestNode.Create();
        var name = NodeLocations.NodeReadyEventName(NodeLocations.InstanceKeyFor(node.Endpoint));
        Assert.False(EventWaitHandle.TryOpenExisting(name, out _));

        using var process = await node.StartNodeAsync();
        Assert.True(EventWaitHandle.TryOpenExisting(name, out var ready));
        using (ready)
        {
            Assert.True(ready!.WaitOne(0));
            await node.StopNodeAsync();
            Assert.True(process.WaitForExit(TimeSpan.FromSeconds(15)));
            Assert.False(ready.WaitOne(0));
        }
    }

    [Fact(Timeout = 60_000)]
    public void TheSupervisorIsAGuiSubsystemExecutable()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows supervisor.");

        // PE optional header Subsystem: 2 = IMAGE_SUBSYSTEM_WINDOWS_GUI (no console window at logon); arcforges.exe is a console program.
        Assert.Equal(2, Subsystem(Supervisor));
        Assert.Equal(3, Subsystem(TestNode.Host));
    }

    [Fact(Timeout = 120_000)]
    public async Task TheRegisteredAutostartCommandStartsTheSupervisorWhichStartsTheNodeWithoutAWindow()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The HKCU Run autostart registration.");
        var realRun = Snapshot(AutostartRegistration.RunKey);
        var testRoot = @"Software\ArcForges-Test\" + Guid.NewGuid().ToString("N");
        var testKey = testRoot + @"\Run";
        await using var node = TestNode.Create();
        try
        {
            // The installer's registration, under a test key (13 section 3.1 test isolation), never the user's Run key.
            AutostartRegistration.Register(Supervisor, testKey);
            var command = AutostartRegistration.Read(testKey);
            Assert.Equal("\"" + Supervisor + "\"", command);
            using (var key = Registry.CurrentUser.OpenSubKey(testKey))
            {
                Assert.Equal(RegistryValueKind.String, key!.GetValueKind(AutostartRegistration.ValueName));
            }

            // Start the registered command line, nothing else. This proves the value the installer writes starts the supervisor; it is not a
            // logon: the user's real Run key is never written here, and the start at logon stays the human-attended check H-15.
            using var supervisor = node.Start(command!.Trim('"'), [NodeLocations.TestModeOption]);
            await node.WaitReadyAsync();
            var nodePid = node.NodePid();
            Assert.Empty(VisibleWindows(supervisor.Id));
            Assert.Empty(VisibleWindows(nodePid));
            using (var nodeProcess = Process.GetProcessById(nodePid))
            {
                Assert.Equal(IntPtr.Zero, nodeProcess.MainWindowHandle);
            }

            await node.StopNodeAsync();
            Assert.True(supervisor.WaitForExit(TimeSpan.FromSeconds(15)));
            Assert.Equal(0, supervisor.ExitCode);
            Assert.True(AutostartRegistration.Unregister(testKey));
            Assert.Null(AutostartRegistration.Read(testKey));
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(testRoot, throwOnMissingSubKey: false);
            using (var parent = Registry.CurrentUser.OpenSubKey(@"Software\ArcForges-Test"))
            {
                if (parent is { SubKeyCount: 0, ValueCount: 0 })
                {
                    Registry.CurrentUser.DeleteSubKey(@"Software\ArcForges-Test", throwOnMissingSubKey: false);
                }
            }
        }

        Assert.Equal(realRun, Snapshot(AutostartRegistration.RunKey));
    }

    [Fact(Timeout = 180_000)]
    public async Task TheSupervisorRestartsACrashedNodeAfterItsBackoff()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows supervisor.");
        await using var node = TestNode.Create();
        using var supervisor = node.Start(Supervisor, [NodeLocations.TestModeOption]);
        await node.WaitReadyAsync();
        var first = node.NodePid();

        using (var crashed = Process.GetProcessById(first))
        {
            var killedAt = Stopwatch.StartNew();
            crashed.Kill();
            await TestNode.WaitAsync(() => node.Descriptor() is { } descriptor && descriptor.ProcessId != first && descriptor.ProcessIsAlive(),
                TimeSpan.FromSeconds(30), "the restarted node");
            Assert.True(killedAt.Elapsed >= TimeSpan.FromSeconds(1.9), $"restarted after {killedAt.Elapsed}, before the 2 s backoff");
        }

        await node.WaitReadyAsync();
        var log = File.ReadAllText(node.SupervisorLog);
        Assert.Contains("node.crashed exitCode=", log, StringComparison.Ordinal);
        Assert.Contains("restartInMs=2000", log, StringComparison.Ordinal);
        await node.StopNodeAsync();
        Assert.True(supervisor.WaitForExit(TimeSpan.FromSeconds(15)));
        Assert.Equal(0, supervisor.ExitCode);
    }

    [Fact(Timeout = 240_000)]
    public async Task AfterFiveCrashesInTenMinutesTheSupervisorStopsAndRecordsTheCrashLoop()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows supervisor.");
        await using var node = TestNode.Create();
        using var supervisor = node.Start(Supervisor, [NodeLocations.TestModeOption]);
        var killed = new HashSet<int>();
        for (var crash = 1; crash <= 5; crash++)
        {
            await node.WaitReadyAsync();
            var pid = node.NodePid();
            Assert.DoesNotContain(pid, killed);
            killed.Add(pid);
            using var process = Process.GetProcessById(pid);
            process.Kill();
            process.WaitForExit(TimeSpan.FromSeconds(10));
        }

        Assert.True(supervisor.WaitForExit(TimeSpan.FromSeconds(30)));
        Assert.Equal(1, supervisor.ExitCode);
        var log = File.ReadAllText(node.SupervisorLog);
        Assert.Contains("node_crash_loop crashes=5", log, StringComparison.Ordinal);
        foreach (var delay in (string[])["restartInMs=2000", "restartInMs=5000", "restartInMs=10000"])
        {
            Assert.Contains(delay, log, StringComparison.Ordinal);
        }

        // The next client auto-start tries again (02 section 2): a new supervisor starts a node. Inside a job without breakaway the
        // client refuses auto-start by design, so this last step is reported as skipped with that reason, never passed silently.
        var sandbox = NodeAutoStart.WindowsSandboxReason(out _);
        Assert.SkipWhen(sandbox is not null, $"The crash loop was verified; the re-auto-start step needs a shell outside a job without breakaway ({sandbox}).");
        var status = await node.CliAsync("status", "--json");
        Assert.True(status.ExitCode == 0, status.ToString());
        Assert.True(status.Json().GetProperty("autoStarted").GetBoolean());
    }

    private static int Subsystem(string path)
    {
        using var stream = File.OpenRead(path);
        using var reader = new BinaryReader(stream);
        stream.Position = 0x3C;
        var header = reader.ReadInt32();
        stream.Position = header + 4 + 20 + 68;
        return reader.ReadUInt16();
    }

    private static Dictionary<string, string?> Snapshot(string keyPath)
    {
        using var key = Registry.CurrentUser.OpenSubKey(keyPath);
        return key?.GetValueNames().ToDictionary(name => name, name => key.GetValue(name)?.ToString(), StringComparer.OrdinalIgnoreCase) ?? [];
    }

    [SupportedOSPlatform("windows")]
    private static List<nint> VisibleWindows(int processId)
    {
        var windows = new List<nint>();
        EnumWindows((window, _) =>
        {
            GetWindowThreadProcessId(window, out var owner);
            if (owner == (uint)processId && IsWindowVisible(window))
            {
                windows.Add(window);
            }

            return true;
        }, 0);
        return windows;
    }

    private delegate bool EnumWindowsCallback(nint window, nint parameter);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EnumWindows(EnumWindowsCallback callback, nint parameter);

    [LibraryImport("user32.dll")]
    private static partial uint GetWindowThreadProcessId(nint window, out uint processId);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsWindowVisible(nint window);
}
