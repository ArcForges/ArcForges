// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    internal const string LinuxSandboxDeletionGuardUnavailable = "linux_exact_directory_mutation_unavailable";

    [SupportedOSPlatform("linux")]
    internal void RequireSandboxDeleteLinuxGuard(string name, WorkspaceObjectIdentity expected)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Components(name).Length != 1)
        {
            throw new WorkspacePathException("path_invalid");
        }

        CheckSandboxDirectory(RootHandle, configuredRoot: false);
        using var currentParent = OpenRoot(RootPath, RootIdentity);
        using var source = LinuxOpenAt2(currentParent.RootHandle, name, noCrossMount: true);
        var parent = LinuxBasicIdentity(currentParent.RootHandle);
        var kind = LinuxBasicIdentity(source);
        if (kind.Volume != parent.Volume || kind.High != parent.High)
        {
            throw new WorkspacePathException("mount_crossing");
        }

        if (!kind.IsDirectory || kind.Links == 0 || !expected.SameObject(LinuxIdentity(source, _linuxFileSystemUuid)))
        {
            throw new WorkspacePathException("directory_identity_changed");
        }

        CheckSandboxDirectory(source, configuredRoot: false);

        // This observation binds the child handle. Linux renameat2/unlinkat still take a child name,
        // and this same-UID parent has no kernel exclusion of other writers to that name.
        throw new WorkspacePathException(LinuxSandboxDeletionGuardUnavailable);
    }
}
