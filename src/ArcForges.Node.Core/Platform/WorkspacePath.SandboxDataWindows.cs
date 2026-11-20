// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
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
    private const uint SandboxPublicationFlushAccess = 0x40120080; // GENERIC_WRITE | SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES
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
    internal void FlushPublishedSandboxDataFileWindows(SafeFileHandle targetParent, string targetName, string identity)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(targetParent);
        var root = Identity(RootHandle);
        var parent = Identity(targetParent);
        var expected = ParseDataStageIdentity(identity);
        if (!root.IsDirectory || root.Links == 0 || !RootIdentity.SameObject(root) ||
            !parent.IsDirectory || parent.Links == 0 || parent.Volume != root.Volume || expected.Volume != root.Volume)
        {
            throw new WorkspacePathException("directory_identity_changed");
        }

        RequireWindowsSandboxDataCaseInsensitive(targetParent);
        CheckName();
        using var file = OpenWindowsSandboxDataName(targetParent, targetName, OpenSandboxStage,
            SandboxPublicationFlushAccess, writeThrough: false, descriptor: 0);
        if (!expected.SameObject(CheckWindowsSandboxDataFile(file)))
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        var stamp = FileStamp(file);
        CheckName();
        if (!FlushSandboxDataFileBuffers(file))
        {
            throw new WorkspacePathException("native_" + Marshal.GetLastPInvokeError().ToString(CultureInfo.InvariantCulture));
        }

        if (!expected.SameObject(CheckWindowsSandboxDataFile(file)) || stamp != FileStamp(file))
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        CheckName();

        void CheckName()
        {
            var named = InspectHeldParentChild(targetParent, targetName);
            if (!parent.SameObject(Identity(targetParent)) || !root.SameObject(Identity(RootHandle)) ||
                named.Links != 1 || !expected.SameObject(named))
            {
                throw new WorkspacePathException("file_identity_changed");
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private SafeFileHandle OpenWindowsSandboxDataName(string name, uint disposition, bool writable, nint descriptor) =>
        OpenWindowsSandboxDataName(RootHandle, name, disposition, writable ? SandboxStageWrite : SandboxStageRead,
            writeThrough: writable, descriptor);

    [SupportedOSPlatform("windows")]
    private static unsafe SafeFileHandle OpenWindowsSandboxDataName(SafeFileHandle directory, string name, uint disposition,
        uint access, bool writeThrough, nint descriptor)
    {
        if (Components(name).Length != 1)
        {
            throw new WorkspacePathException("path_invalid");
        }

        var retained = false;
        try
        {
            directory.DangerousAddRef(ref retained);
            fixed (char* text = name)
            {
                ushort bytes = checked((ushort)(name.Length * sizeof(char)));
                var unicode = new UnicodeString { Length = bytes, MaximumLength = bytes, Buffer = (nint)text };
                var attributes = new ObjectAttributes
                {
                    Length = (uint)sizeof(ObjectAttributes),
                    RootDirectory = directory.DangerousGetHandle(),
                    ObjectName = (nint)(&unicode),
                    Attributes = 0x40, // OBJ_CASE_INSENSITIVE verified on the held directory.
                    SecurityDescriptor = descriptor,
                };

                // Synchronous, non-directory, no-follow. Writable staging also requests NTFS write-through.
                uint options = 0x00200060u | (writeThrough ? 2u : 0u);
                int status = NtCreateFile(out var raw, access, ref attributes,
                    out _, 0, 0x80, 0, disposition, options, 0, 0);
                RequireWindowsSandboxDataStatus(status);
                return new SafeFileHandle(raw, ownsHandle: true);
            }
        }
        finally
        {
            if (retained)
            {
                directory.DangerousRelease();
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

    [LibraryImport("kernel32.dll", EntryPoint = "FlushFileBuffers", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FlushSandboxDataFileBuffers(SafeFileHandle file);
}

internal sealed partial class WorkspaceWriteGuard
{
    // Apply the same native section-reference test without adopting the legacy guarded-write lifetime.
    internal static void RequireWindowsSandboxDataNoMappings(SafeFileHandle file) => CheckWindowsSectionReferences(file);
}
