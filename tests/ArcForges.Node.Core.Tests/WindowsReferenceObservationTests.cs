// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>No-follow metadata observations of isolated native Windows paths; these are not external-use guards.</summary>
public sealed partial class WindowsReferenceObservationTests
{
    [Fact]
    [Trait("env", "windows-real")]
    public void ObservesARealFileDirectoryAndMissingFinalByHeldNativeParent()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The reference observer uses Windows native identities.");
        var owned = Directory.CreateTempSubdirectory("arcforges-reference-observation-").FullName;
        try
        {
            var tree = Directory.CreateDirectory(Path.Combine(owned, "tree")).FullName;
            var nested = Directory.CreateDirectory(Path.Combine(tree, "nested")).FullName;
            var file = Path.Combine(nested, "file.txt");
            File.WriteAllText(file, "test body");
            using var treeRoot = WorkspacePath.OpenRoot(tree);
            using var nestedRoot = WorkspacePath.OpenRoot(nested);
            var fileObservation = WorkspacePath.ObserveWindowsReference(file);
            Assert.False(fileObservation.MissingFinal);
            Assert.Equal(WorkspaceEntryType.File, fileObservation.Final!.Value.Kind);
            Assert.Contains(fileObservation.Ancestors, identity => identity.SameObject(treeRoot.RootIdentity));
            Assert.Contains(fileObservation.Ancestors, identity => identity.SameObject(nestedRoot.RootIdentity));

            var directoryObservation = WorkspacePath.ObserveWindowsReference(nested);
            Assert.False(directoryObservation.MissingFinal);
            Assert.Equal(WorkspaceEntryType.Directory, directoryObservation.Final!.Value.Kind);
            Assert.True(directoryObservation.Final.Value.Identity.SameObject(nestedRoot.RootIdentity));

            var missing = WorkspacePath.ObserveWindowsReference(Path.Combine(nested, "not-yet-present"));
            Assert.True(missing.MissingFinal);
            Assert.Null(missing.Final);
            Assert.Contains(missing.Ancestors, identity => identity.SameObject(treeRoot.RootIdentity));
            Assert.Equal("test body", File.ReadAllText(file));
        }
        finally
        {
            Directory.Delete(owned, recursive: true);
        }
    }
    [Fact]
    [Trait("env", "windows-real")]
    public void MultiLinkReferencesKeepNativeIdentityWithoutGrantingRemovalAuthority()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The reference observer uses Windows native identities.");
        var owned = Directory.CreateTempSubdirectory("arcforges-reference-hardlinks-").FullName;
        try
        {
            var tree = Directory.CreateDirectory(Path.Combine(owned, "tree")).FullName;
            var inside = Path.Combine(tree, "inside.txt");
            var outside = Path.Combine(owned, "outside.txt");
            File.WriteAllText(inside, "retained hardlink body");
            Assert.True(CreateHardLink(outside, inside, 0), $"Native hardlink fixture failed: {Marshal.GetLastPInvokeError()}");
            using var target = WorkspacePath.OpenRoot(tree);
            using var parent = WorkspacePath.OpenRoot(owned);
            var insideObservation = WorkspacePath.ObserveWindowsReference(inside);
            var outsideObservation = WorkspacePath.ObserveWindowsReference(outside);
            var insideIdentity = insideObservation.Final!.Value.Identity;
            var outsideIdentity = outsideObservation.Final!.Value.Identity;
            Assert.Equal(2u, insideIdentity.Links);
            Assert.Equal(2u, outsideIdentity.Links);
            Assert.True(insideIdentity.SameObject(outsideIdentity));
            Assert.True(insideObservation.OverlapsDirectory(target.RootIdentity, parent.WindowsRootAncestors()));
            Assert.False(outsideObservation.OverlapsDirectory(target.RootIdentity, parent.WindowsRootAncestors()));
            Assert.Equal("workspace_identity_invalid", Assert.Throws<RegisteredWorkspaceException>(
                () => RegisteredWorkspaces.RootIdentity.Encode(insideIdentity, directory: false)).Reason);
            Assert.Equal("path_link_or_special", Assert.Throws<WorkspaceRemovalPlanException>(
                () => WorkspaceRemovalPlan.Capture(parent, "tree", CancellationToken.None)).Reason);
            Assert.Equal("retained hardlink body", File.ReadAllText(outside));
        }
        finally { Directory.Delete(owned, recursive: true); }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateHardLinkW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateHardLink(string name, string existing, nint security);

}
