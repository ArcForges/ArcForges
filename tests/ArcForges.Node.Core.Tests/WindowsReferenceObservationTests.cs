// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>No-follow metadata observations of isolated native Windows paths; these are not external-use guards.</summary>
public sealed class WindowsReferenceObservationTests
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
}
