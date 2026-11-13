// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    /// <summary>Ends this operation's own completed traversal before a coordinated rename.
    /// The registered anchor and its ancestor handles remain owned and open.</summary>
    internal void EndRemovalTraversal()
    {
        foreach (var file in _files) file.Dispose();
        _files.Clear();
        for (var index = _directories.Count - 1; index >= _rootAncestorCount; index--)
        {
            _directories[index].Dispose();
            _directories.RemoveAt(index);
        }
    }

    /// <summary>Moves one rechecked object, without replacement, while the node coordinates its managed work.
    /// This is not an exclusion guarantee against independent processes.</summary>
    internal unsafe void MoveRemovalTo(string path, WorkspacePath destination, string name,
        WorkspaceObjectIdentity expected, WorkspaceObjectIdentity expectedParent, Action beforeEffect, Action effectStarted)
    {
        var parts = Components(path);
        if (Components(name).Length != 1) throw new WorkspacePathException("path_invalid");
        if (expected.Volume != destination.RootIdentity.Volume) throw new WorkspacePathException("mount_crossing");
        EndRemovalTraversal();
        var parent = OpenDirectory(parts.Length == 1 ? "" : string.Join('/', parts[..^1]));
        if (!expectedParent.SameObject(Identity(parent))) throw new WorkspacePathException("directory_identity_changed");
        using var target = OperatingSystem.IsWindows()
            ? WindowsRemovalOpen(parent, parts[^1], expected.IsDirectory)
            : LinuxOpenAt2(parent, parts[^1], noCrossMount: true);
        var actual = OperatingSystem.IsLinux() ? LinuxIdentity(target, _linuxFileSystemUuid) : Identity(target);
        if (!expected.SameObject(actual) || actual.Mode != expected.Mode || actual.Links != expected.Links)
            throw new WorkspacePathException("file_identity_changed");
        beforeEffect();
        if (OperatingSystem.IsLinux())
        {
            // The node's admission/command coordination is the scope of this name-based effect.
            effectStarted();
            if (RenameRemovalAt(checked((int)parent.DangerousGetHandle()), parts[^1],
                    checked((int)destination.RootHandle.DangerousGetHandle()), name, 1) != 0)
                throw NativeFailure();
            if (SyncDirectory(checked((int)parent.DangerousGetHandle())) != 0 ||
                SyncDirectory(checked((int)destination.RootHandle.DangerousGetHandle())) != 0)
                throw NativeFailure();
        }
        else if (OperatingSystem.IsWindows())
        {
            var bytes = Encoding.Unicode.GetBytes(name);
            var buffer = new byte[checked(20 + bytes.Length)];
            fixed (byte* data = buffer)
            {
                // FILE_RENAME_INFORMATION: ReplaceIfExists=false, opened destination root, exact relative name.
                *(nint*)(data + 8) = destination.RootHandle.DangerousGetHandle();
                *(uint*)(data + 16) = checked((uint)bytes.Length);
                bytes.CopyTo(buffer, 20);
                effectStarted();
                var status = SetRemovalInformation(target, out _, data, checked((uint)buffer.Length), 10);
                if (status < 0) throw new WorkspacePathException("native_" + RtlNtStatusToDosError(status).ToString(CultureInfo.InvariantCulture));
                status = FlushRemovalBuffers(target, out _);
                if (status < 0) throw new WorkspacePathException("native_" + RtlNtStatusToDosError(status).ToString(CultureInfo.InvariantCulture));
            }
        }
        else throw new WorkspacePathException("path_enforcement_unavailable");
        var moved = destination.InspectEntry(name);
        if (!expected.SameObject(moved.Identity) || moved.Kind != (expected.IsDirectory ? WorkspaceEntryType.Directory : WorkspaceEntryType.File))
            throw new WorkspacePathException("file_identity_changed");
    }

    internal bool InspectRemovalAbsent(string name)
    {
        try { _ = InspectEntry(name); return false; }
        catch (WorkspacePathException failure) when (failure.Reason is "native_2" or "native_3") { return true; }
    }

    /// <summary>Creates or validates one private managed quarantine directory relative to this checked parent.</summary>
    internal unsafe WorkspacePath EnsureRemovalDirectory(string name)
    {
        if (Components(name).Length != 1) throw new WorkspacePathException("path_invalid");
        if (OperatingSystem.IsLinux())
        {
            if (MakeRemovalDirectory(checked((int)RootHandle.DangerousGetHandle()), name, 0x1c0) != 0 &&
                Marshal.GetLastPInvokeError() != 17) throw NativeFailure();
            using var metadata = LinuxOpenAt2(RootHandle, name, noCrossMount: true);
            var buffer = stackalloc byte[256];
            if (Statx(checked((int)metadata.DangerousGetHandle()), string.Empty, 0x1000 | 0x100, 0x8 | 0x2, buffer) != 0 ||
                (*(uint*)buffer & 0xa) != 0xa || *(uint*)(buffer + 20) != EffectiveUserId() ||
                (*(ushort*)(buffer + 28) & 0xfe3f) != 0x4000) throw new WorkspacePathException("file_guard_unavailable");
            if (SyncDirectory(checked((int)RootHandle.DangerousGetHandle())) != 0) throw NativeFailure();
            return OpenRoot(Path.Combine(RootPath, name), LinuxIdentity(metadata, _linuxFileSystemUuid));
        }
        if (!OperatingSystem.IsWindows()) throw new WorkspacePathException("path_enforcement_unavailable");
        using var principal = System.Security.Principal.WindowsIdentity.GetCurrent();
        var sid = principal.User ?? throw new WorkspacePathException("file_guard_unavailable");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var text = sid.Equals(system) ? $"O:{sid.Value}D:P(A;;FA;;;SY)" : $"O:{sid.Value}D:P(A;;FA;;;SY)(A;;FA;;;{sid.Value})";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(text, 1, out var descriptor, out _))
            throw new WorkspacePathException("file_guard_unavailable");
        try
        {
            uint flags;
            if (!GetCaseInformation(RootHandle, 23, &flags, sizeof(uint))) throw new WorkspacePathException("case_semantics_unavailable");
            fixed (char* characters = name)
            {
                var unicode = new UnicodeString { Length = checked((ushort)(name.Length * 2)), MaximumLength = checked((ushort)(name.Length * 2)), Buffer = (nint)characters };
                var attributes = new ObjectAttributes
                {
                    Length = (uint)sizeof(ObjectAttributes),
                    RootDirectory = RootHandle.DangerousGetHandle(),
                    ObjectName = (nint)(&unicode),
                    Attributes = (flags & 1) == 0 ? 0x40u : 0u,
                    SecurityDescriptor = descriptor
                };
                var status = NtCreateFile(out var raw, 0x00120081u, ref attributes, out _, 0, 0x10, 3, 3, 0x00200023, 0, 0);
                if (status < 0) throw new WorkspacePathException("native_" + RtlNtStatusToDosError(status).ToString(CultureInfo.InvariantCulture));
                using var directory = new SafeFileHandle(raw, ownsHandle: true);
                var ownerBytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(ownerBytes, 0);
                var systemBytes = new byte[system.BinaryLength]; system.GetBinaryForm(systemBytes, 0);
                CheckPrivateWindowsStageSecurity(directory, ownerBytes, systemBytes, sid.Equals(system));
                var actual = Identity(directory);
                if (!actual.IsDirectory || actual.Volume != RootIdentity.Volume) throw new WorkspacePathException("mount_crossing");
                return OpenRoot(Path.Combine(RootPath, name), actual);
            }
        }
        finally { _ = LocalFree(descriptor); }
    }

    [LibraryImport("libc", EntryPoint = "mkdirat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int MakeRemovalDirectory(int directory, string name, uint mode);

    private static unsafe SafeFileHandle WindowsRemovalOpen(SafeFileHandle parent, string name, bool directory)
    {
        uint flags;
        if (!GetCaseInformation(parent, 23, &flags, sizeof(uint))) throw new WorkspacePathException("case_semantics_unavailable");
        fixed (char* text = name)
        {
            var unicode = new UnicodeString { Length = checked((ushort)(name.Length * 2)), MaximumLength = checked((ushort)(name.Length * 2)), Buffer = (nint)text };
            var attributes = new ObjectAttributes
            {
                Length = (uint)sizeof(ObjectAttributes),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = (nint)(&unicode),
                Attributes = (flags & 1) == 0 ? 0x40u : 0u
            };
            // DELETE, READ_ATTRIBUTES and SYNCHRONIZE; own verification traversal was closed above.
            var status = NtCreateFile(out var raw, 0xC0110000u, ref attributes, out _, 0, 0, 7, 1,
                0x00200022u | (directory ? 1u : 0x40u), 0, 0);
            if (status < 0) throw new WorkspacePathException("native_" + RtlNtStatusToDosError(status).ToString(CultureInfo.InvariantCulture));
            return new SafeFileHandle(raw, ownsHandle: true);
        }
    }

    [LibraryImport("libc", EntryPoint = "renameat2", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int RenameRemovalAt(int oldDirectory, string oldName, int newDirectory, string newName, uint flags);

    [LibraryImport("ntdll.dll", EntryPoint = "NtFlushBuffersFile")]
    private static partial int FlushRemovalBuffers(SafeFileHandle file, out IoStatusBlock status);

    [LibraryImport("ntdll.dll", EntryPoint = "NtSetInformationFile")]
    private static unsafe partial int SetRemovalInformation(SafeFileHandle file, out IoStatusBlock status, void* buffer, uint length, int kind);
}
