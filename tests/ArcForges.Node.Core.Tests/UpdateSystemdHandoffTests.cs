// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Client;
using ArcForges.Node.Core.Updates;
using ArcForges.Tests;

namespace ArcForges.Node.Core.Tests;

[Trait("env", "linux-real")]
public sealed class UpdateSystemdHandoffTests
{
    [Theory(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [InlineData("75", false)]
    [InlineData("75", true)]
    [InlineData("1", false)]
    [InlineData("2", false)]
    [InlineData("75 SIGTERM", false)]
    public async Task ManagedServiceRechecksThePersistentHandoffOnAutomaticRestart(string successStatus, bool legacyGuard)
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux systemd user manager required.");
            return;
        }
        Assert.SkipUnless(SystemdTestEnvironment.UserManagerAvailable, "requires-user-manager");
        var ct = TestContext.Current.CancellationToken;
        var directory = Directory.CreateTempSubdirectory("arcforges-update-systemd-");
        string app = Path.Combine(directory.FullName, "app $ARCFORGES_GUARD_TEST");
        string marker = Path.Combine(app, ".native-update-systemd-block");
        string selected = Path.Combine(app, "versions", new string('a', 64));
        Directory.CreateDirectory(app, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Directory.CreateDirectory(selected);
        File.CreateSymbolicLink(Path.Combine(app, "current"), "versions/" + new string('a', 64));
        string launched = Path.Combine(directory.FullName, "launch-pids");
        string executable = Path.Combine(selected, "arcforges");
        File.WriteAllText(executable, "#!/bin/sh\nprintf '%s\\n' \"$$\" >> '" + launched + "'\nexec /usr/bin/sleep 120\n");
        File.SetUnixFileMode(executable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        string unit = "arcforges-update-test-" + Guid.NewGuid().ToString("N") + ".service";
        string unitPath = SystemdTestEnvironment.InstallUnitFile(unit,
            "[Service]\nType=exec\nRestart=on-failure\nRestartSec=200ms\nSuccessExitStatus=" + successStatus +
            "\nExecStart=:\"" + Path.Combine(app, "current", "arcforges") + "\" node run --systemd --test-mode\n");
        string target = Path.GetFileNameWithoutExtension(unit) + "-hold.target";
        // Keep the scoped inactive service loaded so its real automatic restart result remains observable.
        string targetPath = SystemdTestEnvironment.InstallUnitFile(target, "[Unit]\nWants=" + unit + "\n");
        string dropIn = unitPath + ".d";
        string? previousUnit = Environment.GetEnvironmentVariable(NodeLocations.NodeUnitVariable);
        string? previousEndpoint = Environment.GetEnvironmentVariable(NodeLocations.EndpointVariable);
        Environment.SetEnvironmentVariable(NodeLocations.NodeUnitVariable, unit);
        Environment.SetEnvironmentVariable(NodeLocations.EndpointVariable, Path.Combine(directory.FullName, "node.sock"));
        try
        {
            Assert.Equal(0, SystemdTestEnvironment.Systemctl("start", "--", target).ExitCode);
            await WaitForAsync(() => File.Exists(launched) && File.ReadAllLines(launched).Length == 1, unit, ct);
            string firstPid = SystemdTestEnvironment.RequiredProperty(unit, "MainPID");
            Assert.Equal(firstPid, Assert.Single(File.ReadAllLines(launched)));
            var operation = Guid.NewGuid();
            if (successStatus != "75")
            {
                var error = await Assert.ThrowsAsync<IOException>(() =>
                    NodeUpdateSystemdHandoff.AcquireAsync(app, operation, testMode: true, ct));
                Assert.Equal("native_update_systemd_handoff_unit_exec_condition_exit_unconfirmed", error.Message);
                Assert.False(File.Exists(marker));
                Assert.False(Directory.Exists(dropIn));
                return;
            }

            if (legacyGuard)
            {
                Directory.CreateDirectory(dropIn, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                File.WriteAllText(Path.Combine(dropIn, "90-arcforges-native-update.conf"),
                    "[Unit]\nConditionPathExists=!" + marker + "\n");
                File.WriteAllText(marker, operation.ToString("D") + "\n");
                Assert.Equal(0, SystemdTestEnvironment.Systemctl("daemon-reload").ExitCode);
                await NodeUpdateSystemdHandoff.RequireArmedAsync(app, operation, testMode: true, ct);
                Assert.Equal(operation.ToString("D") + "\n", File.ReadAllText(marker));
            }
            else
            {
                await NodeUpdateSystemdHandoff.AcquireAsync(app, operation, testMode: true, ct);
            }
            await NodeUpdateSystemdHandoff.RequireArmedAsync(app, operation, testMode: true, ct);
            var wrongRelease = NodeUpdateSystemdHandoff.ReleaseAsync(app, Guid.NewGuid(), testMode: true, ct);
            await Assert.ThrowsAsync<IOException>(() => wrongRelease);

            // SIGKILL of this unique fixture's main makes the manager schedule a genuine automatic restart.
            Assert.Equal(0, SystemdTestEnvironment.Systemctl("kill", "--kill-whom=main", "--signal=KILL", "--", unit).ExitCode);
            await WaitForAsync(() => SystemdTestEnvironment.Property(unit, "NRestarts") == "1" &&
                SystemdTestEnvironment.Property(unit, "ActiveState") == "inactive", unit, ct);
            Assert.Equal("exec-condition", SystemdTestEnvironment.RequiredProperty(unit, "Result"));
            Assert.Equal("0", SystemdTestEnvironment.RequiredProperty(unit, "MainPID"));
            Assert.Equal(firstPid, Assert.Single(File.ReadAllLines(launched)));

            Assert.Equal(0, SystemdTestEnvironment.Systemctl("start", "--", unit).ExitCode);
            Assert.Equal("no", SystemdTestEnvironment.RequiredProperty(unit, "ConditionResult"));

            // Read the guard from disk again after the user manager reloads its exact unit fragment.
            Assert.Equal(0, SystemdTestEnvironment.Systemctl("daemon-reload").ExitCode);
            await NodeUpdateSystemdHandoff.AcquireAsync(app, operation, testMode: true, ct);
            Assert.Equal(0, SystemdTestEnvironment.Systemctl("start", "--", unit).ExitCode);
            Assert.Equal("no", SystemdTestEnvironment.RequiredProperty(unit, "ConditionResult"));
            Assert.Equal(firstPid, Assert.Single(File.ReadAllLines(launched)));

            await NodeUpdateSystemdHandoff.ReleaseAsync(app, operation, testMode: true, ct);
            await NodeUpdateSystemdHandoff.ReleaseAsync(app, operation, testMode: true, ct);
            Assert.Equal(0, SystemdTestEnvironment.Systemctl("start", "--", unit).ExitCode);
            await WaitForAsync(() => File.ReadAllLines(launched).Length == 2, unit, ct);
            string resumed = SystemdTestEnvironment.RequiredProperty(unit, "MainPID");
            Assert.NotEqual(firstPid, resumed);
            Assert.Equal(resumed, File.ReadAllLines(launched)[1]);
        }
        finally
        {
            Environment.SetEnvironmentVariable(NodeLocations.NodeUnitVariable, previousUnit);
            Environment.SetEnvironmentVariable(NodeLocations.EndpointVariable, previousEndpoint);
            _ = SystemdTestEnvironment.Systemctl("stop", "--", unit);
            _ = SystemdTestEnvironment.Systemctl("stop", "--", target);
            File.Delete(unitPath);
            File.Delete(targetPath);
            if (Directory.Exists(dropIn))
            {
                File.Delete(Path.Combine(dropIn, "90-arcforges-native-update.conf"));
                Directory.Delete(dropIn);
            }
            _ = SystemdTestEnvironment.Systemctl("reset-failed", "--", unit);
            directory.Delete(recursive: true);
        }
    }

    private static async Task WaitForAsync(Func<bool> ready, string unit, CancellationToken ct)
    {
        var deadline = Stopwatch.StartNew();
        while (!ready())
        {
            if (deadline.Elapsed >= TimeSpan.FromSeconds(12))
                Assert.Fail(SystemdTestEnvironment.Describe(unit));
            await Task.Delay(100, ct);
        }
    }
}
