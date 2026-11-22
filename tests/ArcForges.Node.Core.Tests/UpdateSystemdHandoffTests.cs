// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Node.Core.Updates;
using ArcForges.Tests;

namespace ArcForges.Node.Core.Tests;

[Trait("env", "linux-real")]
public sealed class UpdateSystemdHandoffTests
{
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task OriginalUserServiceCannotStartWhileTheExactPersistentHandoffIsArmed()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux systemd user manager required.");
            return;
        }
        Assert.SkipUnless(SystemdTestEnvironment.UserManagerAvailable, "requires-user-manager");
        var ct = TestContext.Current.CancellationToken;
        var directory = Directory.CreateTempSubdirectory("arcforges-update-systemd-");
        string app = Path.Combine(directory.FullName, "app");
        string selected = Path.Combine(app, "versions", new string('a', 64));
        Directory.CreateDirectory(app, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Directory.CreateDirectory(selected);
        File.CreateSymbolicLink(Path.Combine(app, "current"), "versions/" + new string('a', 64));
        string launched = Path.Combine(directory.FullName, "previous-launched");
        string executable = Path.Combine(selected, "arcforges");
        File.WriteAllText(executable, "#!/bin/sh\nprintf started > '" + launched + "'\n");
        File.SetUnixFileMode(executable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        string unit = "arcforges-update-test-" + Guid.NewGuid().ToString("N") + ".service";
        string unitPath = SystemdTestEnvironment.InstallUnitFile(unit,
            "[Service]\nType=oneshot\nExecStart=" + Path.Combine(app, "current", "arcforges") + " node run --systemd --test-mode\n");
        string? previousUnit = Environment.GetEnvironmentVariable(NodeLocations.NodeUnitVariable);
        string? previousEndpoint = Environment.GetEnvironmentVariable(NodeLocations.EndpointVariable);
        Environment.SetEnvironmentVariable(NodeLocations.NodeUnitVariable, unit);
        Environment.SetEnvironmentVariable(NodeLocations.EndpointVariable, Path.Combine(directory.FullName, "node.sock"));
        try
        {
            Assert.Equal(0, SystemdTestEnvironment.Systemctl("start", "--", unit).ExitCode);
            Assert.True(File.Exists(launched));
            File.Delete(launched);

            var operation = Guid.NewGuid();
            await NodeUpdateSystemdHandoff.AcquireAsync(app, operation, testMode: true, ct);
            await NodeUpdateSystemdHandoff.RequireArmedAsync(app, operation, testMode: true, ct);
            var wrongRelease = NodeUpdateSystemdHandoff.ReleaseAsync(app, Guid.NewGuid(), testMode: true, ct);
            await Assert.ThrowsAsync<IOException>(() => wrongRelease);
            Assert.Equal(0, SystemdTestEnvironment.Systemctl("start", "--", unit).ExitCode);
            Assert.Equal("no", SystemdTestEnvironment.RequiredProperty(unit, "ConditionResult"));
            Assert.False(File.Exists(launched));

            // Read the guard from disk again after the user manager reloads its exact unit fragment.
            Assert.Equal(0, SystemdTestEnvironment.Systemctl("daemon-reload").ExitCode);
            await NodeUpdateSystemdHandoff.AcquireAsync(app, operation, testMode: true, ct);
            Assert.Equal(0, SystemdTestEnvironment.Systemctl("start", "--", unit).ExitCode);
            Assert.Equal("no", SystemdTestEnvironment.RequiredProperty(unit, "ConditionResult"));
            Assert.False(File.Exists(launched));

            await NodeUpdateSystemdHandoff.ReleaseAsync(app, operation, testMode: true, ct);
            await NodeUpdateSystemdHandoff.ReleaseAsync(app, operation, testMode: true, ct);
            Assert.Equal(0, SystemdTestEnvironment.Systemctl("start", "--", unit).ExitCode);
            Assert.True(File.Exists(launched));
        }
        finally
        {
            Environment.SetEnvironmentVariable(NodeLocations.NodeUnitVariable, previousUnit);
            Environment.SetEnvironmentVariable(NodeLocations.EndpointVariable, previousEndpoint);
            _ = SystemdTestEnvironment.Systemctl("stop", "--", unit);
            File.Delete(unitPath);
            string dropIn = unitPath + ".d";
            if (Directory.Exists(dropIn))
            {
                File.Delete(Path.Combine(dropIn, "90-arcforges-native-update.conf"));
                Directory.Delete(dropIn);
            }
            _ = SystemdTestEnvironment.Systemctl("reset-failed", "--", unit);
            directory.Delete(recursive: true);
        }
    }
}
