// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.AccessControl;
using System.Security.Principal;
using ArcForges.Node.Core.Sandboxes;

namespace ArcForges.Node.Core.Tests;

public sealed partial class SandboxPrivateRootsTests
{
    private const string SandboxId = "0123456789abcdef0123456789abcdef";
    private const string OtherId = "a123456789abcdef0123456789abcdef";
    private static readonly string[] WritableNames = ["home", "config", "cache", "tmp", "work", "data"];

    [Fact(Timeout = 30_000)]
    public void ControlPathsCanBeProvisionedAndRecheckedBeforeTheFirstSandbox()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new SandboxRootFixture();
        var roots = new SandboxPrivateRoots(fixture.DataRoot);
        Assert.Throws<SandboxPrivateRootException>(roots.ValidateControlPaths);
        roots.PrepareControlPaths();
        roots.ValidateControlPaths();
        roots.PrepareControlPaths();
        Assert.True(Directory.Exists(Path.Combine(fixture.DataRoot, "control")));
        Assert.False(Directory.Exists(Path.Combine(fixture.DataRoot, "sandboxes")));
    }

    [Fact(Timeout = 30_000)]
    public void ActiveApplicationInstallationCannotBecomeADataRoot()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var roots = new SandboxPrivateRoots(AppContext.BaseDirectory);
        Assert.Equal("private_data_root_overlaps_installation",
            Assert.Throws<SandboxPrivateRootException>(roots.ValidateControlPaths).Reason);
    }

    [Fact(Timeout = 30_000)]
    public void ProvisionAndReopenPreserveTheOwnedDataAndNeverAdoptTheSameName()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new SandboxRootFixture();
        var roots = new SandboxPrivateRoots(fixture.DataRoot);
        var created = roots.Provision(SandboxId);
        Assert.Equal($"sandboxes/{SandboxId}", created.RelativePath);
        var path = fixture.Root(SandboxId);
        var data = Path.Combine(path, "data", "persist.txt");
        using (var lease = roots.Inspect(SandboxId, created.Identity))
        {
            Assert.Equal(path, lease.RootPath);
            Assert.Equal(WritableNames.Select(name => Path.Combine(path, name)),
                lease.WritablePaths);
            Assert.True(Directory.Exists(Path.Combine(path, "logs")));
            File.WriteAllText(data, "persistent marker");
        }

        var rebuilt = new SandboxPrivateRoots(fixture.DataRoot);
        using (var lease = rebuilt.Inspect(SandboxId, created.Identity))
        {
            Assert.Equal("persistent marker", File.ReadAllText(data));
        }

        var refusal = Assert.Throws<SandboxPrivateRootException>(() => roots.Provision(SandboxId));
        Assert.Equal("private_root_already_exists", refusal.Reason);
        Assert.Null(refusal.PartialRoot);
        Assert.Equal("persistent marker", File.ReadAllText(data));
    }

    [Fact(Timeout = 30_000)]
    public void ExistingManifestCannotAuthorizeAReplacementRoot()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new SandboxRootFixture();
        var roots = new SandboxPrivateRoots(fixture.DataRoot);
        var created = roots.Provision(SandboxId);
        var replacement = roots.Provision(OtherId);
        var path = fixture.Root(SandboxId);
        var moved = path + "-moved";
        var outside = fixture.Root(OtherId);
        var sentinel = Path.Combine(outside, "data", "other.txt");
        File.WriteAllText(sentinel, "other owner data");
        Directory.Move(path, moved);
        Directory.Move(outside, path);

        var refusal = Assert.Throws<SandboxPrivateRootException>(() => roots.Inspect(SandboxId, created.Identity));
        Assert.Equal("private_root_identity_changed", refusal.Reason);
        Assert.Equal("private_root_identity_invalid",
            Assert.Throws<SandboxPrivateRootException>(() => roots.Inspect(SandboxId, replacement.Identity)).Reason);
        Assert.Equal("other owner data", File.ReadAllText(Path.Combine(path, "data", "other.txt")));
        Assert.True(Directory.Exists(moved));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "windows-real")]
    public void WindowsRefusesWidenedAclAndRealJunction()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Windows DACL and junction semantics.");
            return;
        }

        using var fixture = new SandboxRootFixture();
        var roots = new SandboxPrivateRoots(fixture.DataRoot);
        var created = roots.Provision(SandboxId);
        var work = Path.Combine(fixture.Root(SandboxId), "work");
        var info = new DirectoryInfo(work);
        var security = info.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        info.SetAccessControl(security);
        Assert.Equal("private_root_permissions",
            Assert.Throws<SandboxPrivateRootException>(() => roots.Inspect(SandboxId, created.Identity)).Reason);

        var outside = Directory.CreateDirectory(Path.Combine(fixture.Path, "outside")).FullName;
        var sentinel = Path.Combine(outside, "sentinel.txt");
        File.WriteAllText(sentinel, "foreign");
        Directory.Move(work, work + "-original");
        WindowsReferenceObservationTests.CreateJunction(work, outside);
        try
        {
            Assert.Throws<SandboxPrivateRootException>(() => roots.Inspect(SandboxId, created.Identity));
            Assert.Equal("foreign", File.ReadAllText(sentinel));
        }
        finally
        {
            Directory.Delete(work);
        }
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "windows-real")]
    public void WindowsExclusiveCreateUsesTheNativeParentCaseMode()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows native case semantics.");
        using var fixture = new SandboxRootFixture();
        var roots = new SandboxPrivateRoots(fixture.DataRoot);
        _ = roots.Provision(SandboxId);
        var name = OtherId.ToUpperInvariant();
        var upper = Directory.CreateDirectory(fixture.Root(name)).FullName;
        var sentinel = Path.Combine(upper, "foreign.txt");
        File.WriteAllText(sentinel, "untracked");
        if (Directory.Exists(fixture.Root(OtherId)))
        {
            Assert.Equal("private_root_already_exists",
                Assert.Throws<SandboxPrivateRootException>(() => roots.Provision(OtherId)).Reason);
        }
        else
        {
            var created = roots.Provision(OtherId);
            using var lease = roots.Inspect(OtherId, created.Identity);
            Assert.Equal(fixture.Root(OtherId), lease.RootPath);
        }

        Assert.Equal("untracked", File.ReadAllText(sentinel));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LinuxRefusesWidenedModeAndRealSymlink()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux ownership, mode and symlink semantics.");
            return;
        }

        using var fixture = new SandboxRootFixture();
        var roots = new SandboxPrivateRoots(fixture.DataRoot);
        var created = roots.Provision(SandboxId);
        var work = Path.Combine(fixture.Root(SandboxId), "work");
        Assert.Equal(SandboxRootFixture.PrivateMode, File.GetUnixFileMode(work));
        File.SetUnixFileMode(work, SandboxRootFixture.PrivateMode | UnixFileMode.GroupRead);
        Assert.Equal("private_root_permissions",
            Assert.Throws<SandboxPrivateRootException>(() => roots.Inspect(SandboxId, created.Identity)).Reason);

        var outside = Directory.CreateDirectory(Path.Combine(fixture.Path, "outside")).FullName;
        var sentinel = Path.Combine(outside, "sentinel.txt");
        File.WriteAllText(sentinel, "foreign");
        Directory.Move(work, work + "-original");
        Directory.CreateSymbolicLink(work, outside);
        try
        {
            Assert.Throws<SandboxPrivateRootException>(() => roots.Inspect(SandboxId, created.Identity));
            Assert.Equal("foreign", File.ReadAllText(sentinel));
        }
        finally
        {
            Directory.Delete(work);
        }
    }

    private sealed class SandboxRootFixture : IDisposable
    {
        internal const UnixFileMode PrivateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

        internal SandboxRootFixture()
        {
            Path = Directory.CreateTempSubdirectory("arcforges-sandbox-root-").FullName;
            DataRoot = System.IO.Path.Combine(Path, "node-data");
            if (OperatingSystem.IsWindows())
            {
                using var principal = WindowsIdentity.GetCurrent();
                var owner = principal.User ?? throw new InvalidOperationException("The test principal has no user SID.");
                var access = new DirectorySecurity();
                access.SetOwner(owner);
                access.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                access.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
                new DirectoryInfo(DataRoot).Create(access);
            }
            else
            {
                Directory.CreateDirectory(DataRoot, PrivateMode);
            }
        }

        internal string Path { get; }

        internal string DataRoot { get; }

        internal string Root(string sandboxId) => System.IO.Path.Combine(DataRoot, "sandboxes", sandboxId);

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
