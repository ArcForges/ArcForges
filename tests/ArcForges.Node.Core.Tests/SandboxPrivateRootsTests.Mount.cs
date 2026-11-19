// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Node.Core.Sandboxes;

namespace ArcForges.Node.Core.Tests;

public sealed partial class SandboxPrivateRootsTests
{
    private const string MountFixtureRoot = "ARCFORGES_TEST_SANDBOX_MOUNT_ROOT";
    private const string MountFixtureIdentity = "ARCFORGES_TEST_SANDBOX_MOUNT_IDENTITY";

    [Fact(Timeout = 45_000)]
    [Trait("env", "linux-real")]
    public async Task LinuxRefusesRealSameFilesystemBindMount()
    {
        var cancel = TestContext.Current.CancellationToken;
        cancel.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux bind-mount and namespace semantics.");
        if (Environment.GetEnvironmentVariable(MountFixtureRoot) is { } mountedRoot)
        {
            var identity = Environment.GetEnvironmentVariable(MountFixtureIdentity);
            Assert.NotNull(identity);
            var roots = new SandboxPrivateRoots(mountedRoot);
            var error = Assert.Throws<SandboxPrivateRootException>(() => roots.Inspect(SandboxId, identity));
            Assert.Equal("native_18", error.Reason); // EXDEV from RESOLVE_NO_XDEV
            return;
        }

        using var fixture = new SandboxRootFixture();
        var created = new SandboxPrivateRoots(fixture.DataRoot).Provision(SandboxId);
        var outside = Directory.CreateDirectory(Path.Combine(fixture.Path, "outside")).FullName;
        var sentinel = Path.Combine(outside, "sentinel.txt");
        File.WriteAllText(sentinel, "foreign mount contents");
        var target = Path.Combine(fixture.Root(SandboxId), "data");
        var assembly = typeof(SandboxPrivateRootsTests).Assembly;
        var test = $"{typeof(SandboxPrivateRootsTests).FullName}.{nameof(LinuxRefusesRealSameFilesystemBindMount)}";
        var start = new ProcessStartInfo("unshare",
            ["--user", "--map-root-user", "--mount", "--propagation", "private", "--", "/bin/sh", "-c",
                "mount --bind -- \"$1\" \"$2\" && exec dotnet \"$3\" -method \"$4\" -parallelMode none",
                "sandbox-mount-fixture", outside, target, assembly.Location, test])
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.Environment[MountFixtureRoot] = fixture.DataRoot;
        start.Environment[MountFixtureIdentity] = created.Identity;

        using var child = Process.Start(start) ?? throw new InvalidOperationException("The private mount fixture did not start.");
        var output = child.StandardOutput.ReadToEndAsync(cancel);
        var errorOutput = child.StandardError.ReadToEndAsync(cancel);
        try
        {
            await child.WaitForExitAsync(cancel).WaitAsync(TimeSpan.FromSeconds(30), cancel);
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill(entireProcessTree: true);
                Assert.True(child.WaitForExit(5_000), "The owned mount fixture did not exit.");
            }
        }

        Assert.True(child.ExitCode == 0, $"{await output}\n{await errorOutput}");
        Assert.Equal("foreign mount contents", File.ReadAllText(sentinel));
        Assert.False(File.Exists(Path.Combine(target, "sentinel.txt")));
    }
}
