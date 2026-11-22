// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using ArcForges.Node.Core.Platform;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ClosedLoop.Tests;

[Trait("env", "windows-real")]
[Trait("isolation", "exclusive")]
public sealed partial class WindowsDeleteRundownTests
{
    private static readonly string[] OriginalEntries = ["cache", "remaining.bin"];

    [Fact(Timeout = 15_000, DisableParallelization = true)]
    public async Task ExistingDeletePendingDirectoryMustSettleWithinTheOriginalRundownBound()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Windows NTFS deletion rundown.");
            return;
        }

        var token = TestContext.Current.CancellationToken;
        var fixture = Directory.CreateTempSubdirectory("arcforges-delete-rundown-");
        try
        {
            var cache = CreateObservedDirectory(fixture);
            var quarantine = cache.Parent!.FullName;
            using var root = WorkspacePath.OpenRoot(quarantine);
            var originals = MxcRunServiceTests.CaptureWindowsDeleteRundownDirectories(quarantine, token);
            using (var held = OpenFixtureDirectory(cache.FullName, 0x00110080, 7, 0, 3, 0x02200000, 0))
            {
                Assert.False(held.IsInvalid, new Win32Exception(Marshal.GetLastPInvokeError()).Message);
                Assert.True(originals[cache.Name].SameObject(WorkspacePath.Identity(held)));
                byte delete = 1;
                Assert.True(SetFixtureDisposition(held, 4, ref delete, sizeof(byte)),
                    new Win32Exception(Marshal.GetLastPInvokeError()).Message);
                Assert.True(MxcRunServiceTests.IsOriginalWindowsDeleteRundownPending(root, cache.Name, originals));

                var error = await Record.ExceptionAsync(() => MxcRunServiceTests.RequireInterruptedDeleteTreeAsync(
                    MxcRunServiceTests.DeleteDuringRemoval, Path.Combine(fixture.FullName, "original"), quarantine,
                    root.RootIdentity, OriginalEntries, waitForClosedHandles: true, token, originals));
                Assert.Contains("still reports STATUS_DELETE_PENDING", Assert.IsType<Xunit.Sdk.TrueException>(error).Message);
            }

            var settled = await MxcRunServiceTests.RequireInterruptedDeleteTreeAsync(
                MxcRunServiceTests.DeleteDuringRemoval, Path.Combine(fixture.FullName, "original"), quarantine,
                root.RootIdentity, OriginalEntries, waitForClosedHandles: true, token, originals);
            Assert.Equal("remaining.bin", Assert.Single(settled));
            Assert.True(root.InspectRemovalAbsent(cache.Name));
        }
        finally
        {
            fixture.Delete(recursive: true);
        }
    }

    [Fact(Timeout = 15_000, DisableParallelization = true)]
    public async Task DescendantAclDenialStillPropagates()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Windows NTFS deletion rundown.");
            return;
        }

        var token = TestContext.Current.CancellationToken;
        var fixture = Directory.CreateTempSubdirectory("arcforges-delete-rundown-");
        try
        {
            var cache = CreateObservedDirectory(fixture);
            var quarantine = cache.Parent!.FullName;
            using var root = WorkspacePath.OpenRoot(quarantine);
            var originals = MxcRunServiceTests.CaptureWindowsDeleteRundownDirectories(quarantine, token);
            using var principal = WindowsIdentity.GetCurrent();
            var owner = Assert.IsType<SecurityIdentifier>(principal.User);
            var deniedAcl = cache.GetAccessControl(AccessControlSections.Access);
            var deny = new FileSystemAccessRule(owner, FileSystemRights.ListDirectory, AccessControlType.Deny);
            deniedAcl.AddAccessRule(deny);
            cache.SetAccessControl(deniedAcl);
            try
            {
                Assert.False(MxcRunServiceTests.IsOriginalWindowsDeleteRundownPending(root, cache.Name, originals));
                var refusal = await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                    MxcRunServiceTests.RequireInterruptedDeleteTreeAsync(MxcRunServiceTests.DeleteDuringRemoval,
                        Path.Combine(fixture.FullName, "original"), quarantine, root.RootIdentity,
                        OriginalEntries, waitForClosedHandles: true, token, originals));
                Assert.Contains(cache.Name, refusal.Message, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                deniedAcl.RemoveAccessRuleSpecific(deny);
                cache.SetAccessControl(deniedAcl);
            }

            Assert.Empty(cache.EnumerateFileSystemInfos());
            Assert.Equal("retained", File.ReadAllText(Path.Combine(quarantine, "remaining.bin")));
        }
        finally
        {
            fixture.Delete(recursive: true);
        }
    }

    [Fact(Timeout = 15_000, DisableParallelization = true)]
    public async Task ExactNameDisappearanceRestartsTheWholeInventory()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Windows NTFS deletion rundown.");
            return;
        }

        var token = TestContext.Current.CancellationToken;
        var fixture = Directory.CreateTempSubdirectory("arcforges-delete-rundown-");
        try
        {
            var cache = CreateObservedDirectory(fixture);
            var quarantine = cache.Parent!.FullName;
            using var root = WorkspacePath.OpenRoot(quarantine);
            var originals = MxcRunServiceTests.CaptureWindowsDeleteRundownDirectories(quarantine, token);
            int rootScans = 0;
            int removed = 0;
            var settled = await MxcRunServiceTests.RequireInterruptedDeleteTreeAsync(
                MxcRunServiceTests.DeleteDuringRemoval, Path.Combine(fixture.FullName, "original"), quarantine,
                root.RootIdentity, OriginalEntries, waitForClosedHandles: true, token, originals,
                beforeWindowsRundownDirectoryOpen: relative =>
                {
                    if (relative.Length == 0)
                    {
                        rootScans++;
                        return;
                    }

                    Assert.Equal(cache.Name, relative);
                    cache.Delete();
                    removed++;
                });

            Assert.Equal(1, removed);
            Assert.Equal(2, rootScans);
            Assert.Equal("remaining.bin", Assert.Single(settled));
            Assert.True(root.InspectRemovalAbsent(cache.Name));
            Assert.Equal("retained", File.ReadAllText(Path.Combine(quarantine, "remaining.bin")));
        }
        finally
        {
            fixture.Delete(recursive: true);
        }
    }

    private static DirectoryInfo CreateObservedDirectory(DirectoryInfo fixture)
    {
        var quarantine = fixture.CreateSubdirectory("quarantine");
        File.WriteAllText(Path.Combine(quarantine.FullName, "remaining.bin"), "retained");
        return quarantine.CreateSubdirectory("cache");
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle OpenFixtureDirectory(string name, uint access, uint share, nint security,
        uint disposition, uint flags, nint template);

    [LibraryImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFixtureDisposition(SafeFileHandle file, int informationClass, ref byte delete, uint length);
}
