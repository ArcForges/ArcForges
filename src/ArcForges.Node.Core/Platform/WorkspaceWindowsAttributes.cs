// SPDX-License-Identifier: AGPL-3.0-only
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>A bounded observation from the already-held Windows target handle.</summary>
internal readonly record struct WorkspaceWindowsAttributes(uint Attributes, long CreationTime);

internal sealed partial class WorkspacePath
{
    /// <summary>Reads basic attributes through the exact handle; it does not inspect ACLs or alternate streams.</summary>
    internal static unsafe WorkspaceWindowsAttributes WindowsAttributes(SafeFileHandle file)
    {
        if (!OperatingSystem.IsWindows()) throw new WorkspacePathException("file_metadata_unavailable");
        if (!GetBasicInformation(file, 0, out var basic, (uint)sizeof(FileBasicInformation)))
            throw new WorkspacePathException("file_metadata_unavailable");
        return new WorkspaceWindowsAttributes(basic.FileAttributes, basic.CreationTime);
    }
}
