// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    /// <summary>
    /// Opens one direct child without following a link and makes that same held object the root for
    /// metadata-only traversal. The caller must compare its native identity before enumeration.
    /// This is not a namespace lock or cleanup effect guard.
    /// </summary>
    internal WorkspacePath OpenWindowsHeldChildRoot(string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!OperatingSystem.IsWindows()) throw new WorkspacePathException("path_enforcement_unavailable");
        if (Components(name).Length != 1) throw new WorkspacePathException("path_invalid");

        var parent = RootHandle;
        var child = new WorkspacePath();
        var held = false;
        try
        {
            parent.DangerousAddRef(ref held);
            child._borrowedWindowsRootParent = parent;
            held = false; // child now owns the reference
            child._windowsRootParent = parent;
            child._windowsRootName = name;
            child._windowsDriveRoot = _windowsDriveRoot;
            var opened = Retain(child._directories, OpenChild(parent, name, directory: true));
            CheckVolume(opened);
            child._rootHandle = opened;
            child.RootIdentity = Identity(opened);
            if (!child.RootIdentity.IsDirectory || child.RootIdentity.Links == 0)
                throw new WorkspacePathException("root_not_directory");
            child.RootPath = FinalPath(opened, Path.Combine(RootPath, name));
            return child;
        }
        catch
        {
            if (held) parent.DangerousRelease();
            child.Dispose();
            throw;
        }
    }
}
