// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// An empty named object held by its native exclusive guard. It is not an approval, contains no file body and must
/// not receive bytes until its identity has been durably registered. Disposal closes this handle and does not delete
/// the named object or prove that an independently held reference disappeared.
/// </summary>
internal enum NamedStageDurabilityEvidence
{
    None,
    LinuxFileAndDirectoryFsync,
    WindowsNtfsWriteThroughAndFileFlush,
}

internal sealed class WorkspaceEmptyNamedStage(string name, RegisteredWorkspaces.RootIdentity identity,
    WorkspaceWriteGuard guard, NamedStageDurabilityEvidence durabilityEvidence) : IDisposable
{
    internal string Name { get; } = name;
    internal RegisteredWorkspaces.RootIdentity Identity { get; } = identity;
    internal WorkspaceWriteGuard Guard { get; } = guard;
    internal NamedStageDurabilityEvidence DurabilityEvidence { get; } = durabilityEvidence;
    public void Dispose() => Guard.Dispose();
}

internal sealed partial class WorkspacePath
{
    /// <summary>
    /// Creates a new empty same-directory stage without replacing an existing object. A coordinator must have already
    /// committed the reservation, and must commit this opened identity before any body is written. Windows namespace
    /// persistence uses NTFS write-through creation and file flush; it is not a parent/ancestor or power-loss proof.
    /// Later approval still needs exact-identity reopen, exclusive guard and full rehash after restart.
    /// </summary>
    internal WorkspaceEmptyNamedStage CreateEmptyPrivateNamedStage(string name, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        if (Components(name).Length != 1) throw new WorkspacePathException("path_invalid");
        var root = Identity(RootHandle);
        if (!root.IsDirectory || root.Links == 0 || !RootIdentity.SameObject(root))
            throw new WorkspacePathException("root_changed");
        if (OperatingSystem.IsWindows()) return CreateWindowsEmptyPrivateNamedStage(name, root, cancellationToken);
        if (!OperatingSystem.IsLinux()) throw new WorkspacePathException("file_guard_unavailable");

        var retained = false;
        int descriptor;
        try
        {
            RootHandle.DangerousAddRef(ref retained);
            // O_CREAT|O_EXCL|O_RDWR|O_NOFOLLOW|O_CLOEXEC, mode 0600, relative to the verified directory.
            descriptor = OpenAt(checked((int)RootHandle.DangerousGetHandle()), name, 0x40 | 0x80 | 2 | 0x20000 | 0x80000, 0x180);
        }
        finally
        {
            if (retained) RootHandle.DangerousRelease();
        }
        if (descriptor < 0) throw NativeFailure();

        SafeFileHandle? file = new(descriptor, ownsHandle: true);
        WorkspaceWriteGuard? guard = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var actual = Identity(file);
            if (!actual.IsFile || actual.Links != 1 || actual.Volume != root.Volume || actual.High != root.High ||
                RandomAccess.GetLength(file) != 0)
                throw new WorkspacePathException("file_guard_unavailable");
            CheckPrivateLinuxNamedStageSecurity(file);
            RandomAccess.FlushToDisk(file);
            if (SyncDirectory(checked((int)RootHandle.DangerousGetHandle())) != 0)
                throw new WorkspacePathException("file_guard_unavailable");
            guard = WorkspaceWriteGuard.AcquireLinuxNamedPrivateStage(file, CheckPrivateLinuxNamedStageSecurity);
            file = null;
            using var checkedRoot = OpenRoot(RootPath, RootIdentity);
            var named = InspectEntry(name);
            if (named.Kind != WorkspaceEntryType.File || !actual.SameObject(named.Identity) || named.Identity.Links != 1 ||
                guard.ObserveLength(cancellationToken) != 0)
                throw new WorkspacePathException("file_identity_changed");
            var result = new WorkspaceEmptyNamedStage(name, RegisteredWorkspaces.RootIdentity.Encode(actual, directory: false), guard,
                durabilityEvidence: NamedStageDurabilityEvidence.LinuxFileAndDirectoryFsync);
            guard = null;
            return result;
        }
        finally
        {
            guard?.Dispose();
            file?.Dispose();
        }
    }

    [SupportedOSPlatform("linux")]
    private static unsafe void CheckPrivateLinuxNamedStageSecurity(SafeFileHandle file)
    {
        const uint Required = 0x8 | 0x2; // STATX_UID and STATX_MODE
        var buffer = stackalloc byte[256];
        if (Statx(checked((int)file.DangerousGetHandle()), string.Empty, 0x1000 | 0x100, Required, buffer) != 0 ||
            (*(uint*)buffer & Required) != Required || *(uint*)(buffer + 20) != EffectiveUserId() ||
            (*(ushort*)(buffer + 28) & 0xfe3f) != 0x8000)
            throw new WorkspacePathException("file_guard_unavailable");
    }

    [SupportedOSPlatform("windows")]
    private unsafe WorkspaceEmptyNamedStage CreateWindowsEmptyPrivateNamedStage(string name, WorkspaceObjectIdentity root,
        CancellationToken cancellationToken)
    {
        using var current = System.Security.Principal.WindowsIdentity.GetCurrent();
        var sid = current.User ?? throw new WorkspacePathException("file_guard_unavailable");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var ownerBytes = new byte[sid.BinaryLength];
        var systemBytes = new byte[system.BinaryLength];
        sid.GetBinaryForm(ownerBytes, 0);
        system.GetBinaryForm(systemBytes, 0);
        var samePrincipal = sid.Equals(system);
        var descriptorText = samePrincipal ? $"O:{sid.Value}D:P(A;;FA;;;SY)" : $"O:{sid.Value}D:P(A;;FA;;;SY)(A;;FA;;;{sid.Value})";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(descriptorText, 1, out var descriptor, out _))
            throw new WorkspacePathException("file_guard_unavailable");

        SafeFileHandle? file = null;
        WorkspaceWriteGuard? guard = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            uint caseFlags;
            if (!GetCaseInformation(RootHandle, 23, &caseFlags, sizeof(uint)))
                throw new WorkspacePathException("case_semantics_unavailable");
            fixed (char* characters = name)
            {
                var unicode = new UnicodeString
                {
                    Length = checked((ushort)(name.Length * 2)),
                    MaximumLength = checked((ushort)(name.Length * 2)),
                    Buffer = (nint)characters,
                };
                var retained = false;
                try
                {
                    RootHandle.DangerousAddRef(ref retained);
                    var attributes = new ObjectAttributes
                    {
                        Length = (uint)sizeof(ObjectAttributes),
                        RootDirectory = RootHandle.DangerousGetHandle(),
                        ObjectName = (nint)(&unicode),
                        Attributes = (caseFlags & 1) == 0 ? 0x40u : 0u,
                        SecurityDescriptor = descriptor,
                    };
                    // FILE_CREATE with FILE_WRITE_THROUGH, no sharing and no FILE_DELETE_ON_CLOSE.
                    // On NTFS a write-through request also flushes the request's metadata; no claim about ancestors.
                    var status = NtCreateFile(out var raw, 0xC0130000u, ref attributes, out _, 0, 0x80u, 0u, 2u,
                        0x2u | 0x20u | 0x40u | 0x00200000u, 0, 0);
                    if (status < 0) throw new WorkspacePathException("file_guard_unavailable");
                    file = new SafeFileHandle(raw, ownsHandle: true);
                }
                finally
                {
                    if (retained) RootHandle.DangerousRelease();
                }
            }

            var actual = Identity(file);
            if (!actual.IsFile || actual.Links != 1 || actual.Volume != root.Volume || RandomAccess.GetLength(file) != 0)
                throw new WorkspacePathException("file_guard_unavailable");
            CheckPrivateWindowsStageSecurity(file, ownerBytes, systemBytes, samePrincipal);
            if (!WindowsStageIsNtfs(file)) throw new WorkspacePathException("file_guard_unavailable");
            RandomAccess.FlushToDisk(file);
            guard = WorkspaceWriteGuard.AcquireWindowsPrivateStage(file,
                handle => CheckPrivateWindowsStageSecurity(handle, ownerBytes, systemBytes, samePrincipal));
            file = null;
            using var checkedRoot = OpenRoot(RootPath, RootIdentity);
            var named = InspectEntry(name);
            if (named.Kind != WorkspaceEntryType.File || !actual.SameObject(named.Identity) || named.Identity.Links != 1 ||
                guard.ObserveLength(cancellationToken) != 0)
                throw new WorkspacePathException("file_identity_changed");
            var result = new WorkspaceEmptyNamedStage(name, RegisteredWorkspaces.RootIdentity.Encode(actual, directory: false), guard,
                durabilityEvidence: NamedStageDurabilityEvidence.WindowsNtfsWriteThroughAndFileFlush);
            guard = null;
            return result;
        }
        finally
        {
            guard?.Dispose();
            file?.Dispose();
            _ = LocalFree(descriptor);
        }
    }

    [LibraryImport("libc", EntryPoint = "geteuid")]
    private static partial uint EffectiveUserId();

    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static partial int SyncDirectory(int descriptor);
}
