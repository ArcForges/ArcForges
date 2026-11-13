// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real owned child identity and lifetime observations; not a helper-effect or crash recovery proof.</summary>
[SupportedOSPlatform("linux")]
[Trait("feature", "file-guard-helper")]
[Trait("env", "linux-real")]
public sealed class LinuxOwnedProcessIdentityTests
{
    [Fact(Timeout = 30_000)]
    public async Task OwnedChildIdentityRemainsAliveUntilItActuallyExitsAndIsReaped()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux procfs and PID namespace identity.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        var info = new ProcessStartInfo("python3")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add("import sys; print('READY', flush=True); sys.stdin.readline()");
        using var child = Process.Start(info) ?? throw new InvalidOperationException("Could not start owned child.");
        try
        {
            Assert.Equal("READY", await child.StandardOutput.ReadLineAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), ct));
            var identity = LinuxOwnedProcessIdentity.CaptureChild(child);
            Assert.Equal(child.Id, identity.ProcessId);
            Assert.True(identity.StartTicks > 0);
            Assert.True(LinuxExecutableIdentity.MatchesCurrent(Environment.ProcessId));
            Assert.False(LinuxExecutableIdentity.MatchesCurrent(child.Id));
            Assert.False(LinuxExecutableIdentity.MatchesCurrent(0));
            Assert.Equal(LinuxProcessObservation.Alive, identity.Observe());
            Assert.Equal(LinuxProcessObservation.Unknown, (identity with { ProcessId = 0 }).Observe());
            Assert.Equal(LinuxProcessObservation.Unknown, (identity with { BootId = Guid.NewGuid() }).Observe());
            var differentNamespace = identity.PidNamespace == "pid:[1]" ? "pid:[2]" : "pid:[1]";
            Assert.Equal(LinuxProcessObservation.Unknown, (identity with { PidNamespace = differentNamespace }).Observe());
            // A different start stamp for the same PID is a different process identity, not proof about a real reboot.
            Assert.Equal(LinuxProcessObservation.Ended, (identity with { StartTicks = identity.StartTicks + 1 }).Observe());
            using var current = Process.GetCurrentProcess();
            Assert.Throws<InvalidOperationException>(() => LinuxOwnedProcessIdentity.CaptureChild(current));
            await child.StandardInput.WriteLineAsync("exit");
            await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.Equal(0, child.ExitCode);
            Assert.Equal(LinuxProcessObservation.Ended, identity.Observe());
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill();
                Assert.True(child.WaitForExit(10_000), "The owned child did not exit after termination.");
            }
        }
    }
}
