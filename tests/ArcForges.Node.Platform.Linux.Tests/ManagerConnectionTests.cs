// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using ArcForges.Tests;

namespace ArcForges.Node.Platform.Linux.Tests;

/// <summary>
/// The connection to the user manager is reliable: on the manager's private socket Tmds.DBus.Protocol's connection setup stalled in about
/// one connection in four (systemd 257, WSL2 Debian), so the platform connects through the user bus; this test connects repeatedly.
/// </summary>
[Trait("env", "linux-real")]
[Collection(SerialLinuxTests.Name)]
[SupportedOSPlatform("linux")]
public sealed class ManagerConnectionTests
{
    [Fact(Timeout = 120_000)]
    public void ConnectionsToTheUserManagerNeverStall()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        var failures = new List<string>();
        var slowest = 0L;
        for (var index = 0; index < 50; index++)
        {
            var watch = Stopwatch.StartNew();
            try
            {
                using var manager = SystemdManager.Connect(SystemdManager.DefaultAddress()!, TimeSpan.FromSeconds(5));
                Assert.NotEmpty(manager.Version);
                Assert.NotEmpty(manager.ManagerEnvironment());
            }
            catch (TimeoutException exception)
            {
                failures.Add($"{index}: {exception.Message}");
            }

            slowest = Math.Max(slowest, watch.ElapsedMilliseconds);
        }

        TestContext.Current.TestOutputHelper?.WriteLine($"slowest connection {slowest} ms");
        Assert.True(failures.Count == 0, string.Join("; ", failures));
        Assert.True(slowest < 1_000, $"The slowest connection took {slowest} ms.");
    }
}
