// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    // Local NTFS only. Reuse the existing held-handle NT API without exposing a pathname mutation.
    private const uint SandboxStageRead = 0x80120000; // GENERIC_READ | SYNCHRONIZE | READ_CONTROL
    private const uint SandboxStageWrite = SandboxStageRead | 0x40010000; // GENERIC_WRITE | DELETE
    private const uint OpenSandboxStage = 1; // FILE_OPEN
    private const uint CreateSandboxStage = 2; // FILE_CREATE

    [SupportedOSPlatform("windows")]
    private SafeFileHandle CreateSandboxDataStageWindows(string name)
    {
        CheckWindowsSandboxDataRoot();
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new WorkspacePathException("file_guard_unavailable");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        string security = owner.Equals(system)
            ? $"O:{owner.Value}D:P(A;;FA;;;SY)"
            : $"O:{owner.Value}D:P(A;;FA;;;SY)(A;;FA;;;{owner.Value})";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(security, 1, out nint descriptor, out _))
        {
            throw new WorkspacePathException("file_guard_unavailable");
        }

        try
        {
            var file = OpenWindowsSandboxDataName(name, CreateSandboxStage, writable: true, descriptor);
            try
            {
                var created = CheckWindowsSandboxDataFile(file);
                if (FileStamp(file).Size != 0)
                {
                    throw new WorkspacePathException("file_identity_changed");
                }

                CheckWindowsSandboxDataLink(name, created);
                RequireWindowsSandboxDataStatus(FlushRemovalBuffers(file, out _));
                return file;
            }
            catch
            {
                file.Dispose();
                throw;
            }
        }
        finally
        {
            _ = LocalFree(descriptor);
        }
    }

    [SupportedOSPlatform("windows")]
    private SafeFileHandle OpenSandboxDataStageWindows(string name, WorkspaceObjectIdentity expected, bool writable)
    {
        CheckWindowsSandboxDataRoot();
        // Prove that the named entry is a regular file before taking data access.
        CheckWindowsSandboxDataLink(name, expected);
        var file = OpenWindowsSandboxDataName(name, OpenSandboxStage, writable, descriptor: 0);
        try
        {
            if (!expected.SameObject(CheckWindowsSandboxDataFile(file)))
            {
                throw new WorkspacePathException("file_identity_changed");
            }

            CheckWindowsSandboxDataLink(name, expected);
            return file;
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    [SupportedOSPlatform("windows")]
    private unsafe void PublishSandboxDataStageWindows(SafeFileHandle stage, string stageName,
        SafeFileHandle targetParent, string targetName, Action applied)
    {
        CheckWindowsSandboxDataRoot();
        if (IntPtr.Size != 8 || Components(targetName).Length != 1)
        {
            throw new WorkspacePathException("path_enforcement_unavailable");
        }

        var targetDirectory = Identity(targetParent);
        if (!targetDirectory.IsDirectory || targetDirectory.Links == 0 || targetDirectory.Volume != RootIdentity.Volume ||
            RootIdentity.SameObject(targetDirectory))
        {
            throw new WorkspacePathException("directory_identity_changed");
        }

        // Native no-replace then also rejects an existing alternate spelling under this parent's case rules.
        RequireWindowsSandboxDataCaseInsensitive(targetParent);
        var staged = CheckWindowsSandboxDataFile(stage);
        CheckWindowsSandboxDataLink(stageName, staged);

        // FILE_RENAME_INFORMATION on the held source. ReplaceIfExists is zero, and the destination is a simple
        // name resolved from the held parent. A collision between these checks and the syscall cannot overwrite it.
        int length = Encoding.Unicode.GetByteCount(targetName);
        var rename = new byte[checked(24 + length)];
        _ = Encoding.Unicode.GetBytes(targetName, rename.AsSpan(20, length));
        var retained = false;
        try
        {
            targetParent.DangerousAddRef(ref retained);
            fixed (byte* information = rename)
            {
                *(nint*)(information + 8) = targetParent.DangerousGetHandle();
                *(uint*)(information + 16) = checked((uint)length);
                RequireWindowsSandboxDataStatus(SetRemovalInformation(stage, out _, information, (uint)rename.Length, 10));
            }

            applied();
            RequireWindowsSandboxDataStatus(FlushRemovalBuffers(stage, out _));
            RequireWindowsSandboxDataCaseInsensitive(targetParent);
            var destination = InspectHeldParentChild(targetParent, targetName);
            if (!targetDirectory.SameObject(Identity(targetParent)) || !staged.SameObject(destination) ||
                destination.Links != 1 || !InspectRemovalAbsent(stageName))
            {
                throw new WorkspacePathException("file_identity_changed");
            }
        }
        finally
        {
            if (retained)
            {
                targetParent.DangerousRelease();
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private unsafe void RemoveSandboxDataStageWindows(string name, WorkspaceObjectIdentity expected, Action applied)
    {
        using (var file = OpenSandboxDataStageWindows(name, expected, writable: true))
        {
            // FILE_DISPOSITION_INFORMATION marks precisely this DELETE-access handle for deletion on close.
            byte delete = 1;
            RequireWindowsSandboxDataStatus(SetRemovalInformation(file, out _, &delete, sizeof(byte), 13));
            applied();
        }

        CheckWindowsSandboxDataRoot();
        if (!InspectRemovalAbsent(name))
        {
            throw new WorkspacePathException("file_identity_changed");
        }
    }

    [SupportedOSPlatform("windows")]
    private unsafe SafeFileHandle OpenWindowsSandboxDataName(string name, uint disposition, bool writable, nint descriptor)
    {
        if (Components(name).Length != 1)
        {
            throw new WorkspacePathException("path_invalid");
        }

        var retained = false;
        try
        {
            RootHandle.DangerousAddRef(ref retained);
            fixed (char* text = name)
            {
                ushort bytes = checked((ushort)(name.Length * sizeof(char)));
                var unicode = new UnicodeString { Length = bytes, MaximumLength = bytes, Buffer = (nint)text };
                var attributes = new ObjectAttributes
                {
                    Length = (uint)sizeof(ObjectAttributes),
                    RootDirectory = RootHandle.DangerousGetHandle(),
                    ObjectName = (nint)(&unicode),
                    Attributes = 0x40, // OBJ_CASE_INSENSITIVE verified on the held stage directory.
                    SecurityDescriptor = descriptor,
                };

                // Synchronous, non-directory, no-follow. Writable staging also requests NTFS write-through.
                uint options = 0x00200060u | (writable ? 2u : 0u);
                int status = NtCreateFile(out var raw, writable ? SandboxStageWrite : SandboxStageRead, ref attributes,
                    out _, 0, 0x80, 0, disposition, options, 0, 0);
                RequireWindowsSandboxDataStatus(status);
                return new SafeFileHandle(raw, ownsHandle: true);
            }
        }
        finally
        {
            if (retained)
            {
                RootHandle.DangerousRelease();
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private void CheckWindowsSandboxDataRoot()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var current = Identity(RootHandle);
        if (!current.IsDirectory || current.Links == 0 || !RootIdentity.SameObject(current) || !WindowsStageIsNtfs(RootHandle))
        {
            throw new WorkspacePathException("root_changed");
        }

        CheckSandboxDirectory(RootHandle, configuredRoot: true);
        RequireWindowsSandboxDataCaseInsensitive(RootHandle);
    }

    private static unsafe void RequireWindowsSandboxDataCaseInsensitive(SafeFileHandle directory)
    {
        uint flags;
        if (!GetCaseInformation(directory, 23, &flags, sizeof(uint)) || flags != 0)
        {
            throw new WorkspacePathException("case_semantics_unavailable");
        }
    }

    [SupportedOSPlatform("windows")]
    private WorkspaceObjectIdentity CheckWindowsSandboxDataFile(SafeFileHandle file)
    {
        var current = Identity(file);
        if (!current.IsFile || current.Links != 1 || current.Volume != RootIdentity.Volume)
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new WorkspacePathException("file_guard_unavailable");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var ownerBytes = new byte[owner.BinaryLength];
        var systemBytes = new byte[system.BinaryLength];
        owner.GetBinaryForm(ownerBytes, 0);
        system.GetBinaryForm(systemBytes, 0);
        CheckPrivateWindowsStageSecurity(file, ownerBytes, systemBytes, owner.Equals(system));
        WorkspaceWriteGuard.RequireWindowsSandboxDataNoMappings(file);
        return current;
    }

    private void CheckWindowsSandboxDataLink(string name, WorkspaceObjectIdentity expected)
    {
        if (Components(name).Length != 1)
        {
            throw new WorkspacePathException("path_invalid");
        }

        var link = InspectEntry(name);
        if (link.Kind != WorkspaceEntryType.File || link.Identity.Links != 1 || !expected.SameObject(link.Identity))
        {
            throw new WorkspacePathException("file_identity_changed");
        }
    }

    private static void RequireWindowsSandboxDataStatus(int status)
    {
        if (status != 0)
        {
            throw new WorkspacePathException("native_" + RtlNtStatusToDosError(status).ToString(CultureInfo.InvariantCulture));
        }
    }
}

internal sealed partial class WorkspaceWriteGuard
{
    // Apply the same native section-reference test without adopting the legacy guarded-write lifetime.
    internal static void RequireWindowsSandboxDataNoMappings(SafeFileHandle file) => CheckWindowsSectionReferences(file);
}
