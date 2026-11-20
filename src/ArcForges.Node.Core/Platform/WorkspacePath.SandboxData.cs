// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    internal SafeFileHandle CreateSandboxDataStage(string name)
    {
        ValidateDataStageName(name);
        if (OperatingSystem.IsWindows()) return CreateSandboxDataStageWindows(name);
        if (OperatingSystem.IsLinux()) return CreateSandboxDataStageLinux(name);
        throw new WorkspacePathException("path_enforcement_unavailable");
    }

    internal SafeFileHandle OpenSandboxDataStage(string name, string identity, bool writable)
    {
        ValidateDataStageName(name);
        var expected = ParseDataStageIdentity(identity);
        if (OperatingSystem.IsWindows()) return OpenSandboxDataStageWindows(name, expected, writable);
        if (OperatingSystem.IsLinux()) return OpenSandboxDataStageLinux(name, expected, writable);
        throw new WorkspacePathException("path_enforcement_unavailable");
    }

    internal void PublishSandboxDataStage(SafeFileHandle stage, string stageName, SafeFileHandle parent,
        string targetName, Action applied)
    {
        ValidateDataStageName(stageName);
        if (OperatingSystem.IsWindows())
        {
            PublishSandboxDataStageWindows(stage, stageName, parent, targetName, applied);
        }
        else if (OperatingSystem.IsLinux())
        {
            PublishSandboxDataStageLinux(stage, stageName, parent, targetName, applied);
        }
        else
        {
            throw new WorkspacePathException("path_enforcement_unavailable");
        }
    }

    internal void RemoveSandboxDataStage(string name, string identity, Action applied)
    {
        ValidateDataStageName(name);
        var expected = ParseDataStageIdentity(identity);
        if (OperatingSystem.IsWindows())
        {
            RemoveSandboxDataStageWindows(name, expected, applied);
        }
        else if (OperatingSystem.IsLinux())
        {
            RemoveSandboxDataStageLinux(name, expected, applied);
        }
        else
        {
            throw new WorkspacePathException("path_enforcement_unavailable");
        }
    }

    internal static string EncodeDataIdentity(WorkspaceObjectIdentity identity, bool directory = false) =>
        Convert.ToBase64String(RegisteredWorkspaces.RootIdentity.Encode(identity, directory).Bytes);

    private static WorkspaceObjectIdentity ParseDataStageIdentity(string text)
    {
        var identity = Convert.FromBase64String(text);
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(OperatingSystem.IsWindows() ? 1 : 2, identity);
        var volume = BinaryPrimitives.ReadUInt64BigEndian(identity.AsSpan(1, 8));
        return OperatingSystem.IsWindows()
            ? new WorkspaceObjectIdentity(volume, BinaryPrimitives.ReadUInt64BigEndian(identity.AsSpan(9, 8)),
                BinaryPrimitives.ReadUInt64BigEndian(identity.AsSpan(17, 8)),
                BinaryPrimitives.ReadUInt64BigEndian(identity.AsSpan(25, 8)), 0, 1, 0x8000)
            : new WorkspaceObjectIdentity(volume, 0, 0, BinaryPrimitives.ReadUInt64BigEndian(identity.AsSpan(9, 8)),
                BinaryPrimitives.ReadUInt32BigEndian(identity.AsSpan(17, 4)), 1, 0x8000, identity.AsMemory(21));
    }

    private void ValidateDataStageName(string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (name.Length != 32 || !name.All(char.IsAsciiHexDigitLower))
        {
            throw new WorkspacePathException("private_stage_name_invalid");
        }

    }
}
