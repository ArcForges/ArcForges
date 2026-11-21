// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    internal const string LinuxSandboxDeletionGuardUnavailable = "linux_exact_directory_mutation_unavailable";
    private const ulong LinuxSandboxDeleteResolve = 0x0f; // BENEATH | NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV
    private const ulong LinuxSandboxDeleteMetadata = 0x200000 | 0x80000 | 0x20000; // O_PATH | O_CLOEXEC | O_NOFOLLOW
    private const ulong LinuxSandboxDeleteDirectory = 0x10000 | 0x80000 | 0x20000; // O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW

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

    /// <summary>Checks the recorded source and its admitted directory before any deletion receipt is accepted.</summary>
    [SupportedOSPlatform("linux")]
    internal void RequireAdmittedSandboxDeleteLinuxGuard(string name, WorkspaceObjectIdentity expected, LinuxSandboxDeletionAuthority authority)
    {
        RequireLinuxSandboxDeleteParent(authority);
        using var source = OpenLinuxSandboxDeleteRoot(name, expected);
        SyncLinuxSandboxDeleteDirectory(RootHandle);

        // Empty names cannot resolve an entry. Verify this process can reach the native syscall before admission.
        var parent = SandboxDeleteDescriptor(RootHandle);
        try
        {
            if (RenameRemovalAt(parent, string.Empty, parent, string.Empty, 1) == 0)
            {
                throw new WorkspacePathException(LinuxSandboxDeletionGuardUnavailable);
            }

            if (Marshal.GetLastPInvokeError() != 2) // ENOENT is the expected outcome.
            {
                throw NativeFailure();
            }
        }
        catch (EntryPointNotFoundException error)
        {
            throw new WorkspacePathException(LinuxSandboxDeletionGuardUnavailable, error);
        }
    }

    /// <summary>Flushes an exact, admitted parent before recovery persists a previously observed move.</summary>
    [SupportedOSPlatform("linux")]
    internal void SyncAdmittedSandboxDeleteLinuxParent(LinuxSandboxDeletionAuthority authority)
    {
        RequireLinuxSandboxDeleteParent(authority);
        SyncLinuxSandboxDeleteDirectory(RootHandle);
    }

    /// <summary>Moves the verified root between two protected parents on the same live mount, without replacement.</summary>
    [SupportedOSPlatform("linux")]
    internal WorkspaceObjectIdentity QuarantineSandboxLinux(string name, WorkspacePath quarantine, string quarantineName,
        WorkspaceObjectIdentity expected, LinuxSandboxDeletionAuthority authority, Action applied, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(quarantine);
        ArgumentNullException.ThrowIfNull(applied);
        RequireLinuxSandboxDeleteParent(authority);
        quarantine.RequireLinuxSandboxDeleteParent(authority);
        RequireLinuxSandboxDeleteMount(RootIdentity, quarantine.RootIdentity);
        if (RootIdentity.SameObject(quarantine.RootIdentity))
        {
            throw new WorkspacePathException("file_guard_unavailable");
        }

        var sourceName = LinuxSandboxDeleteName(name);
        _ = LinuxSandboxDeleteName(quarantineName);
        using var source = OpenLinuxSandboxDeleteRoot(name, expected);
        cancellationToken.ThrowIfCancellationRequested();

        // Only the admitted principal can write these parents. RENAME_NOREPLACE protects the destination name.
        if (RenameRemovalAt(SandboxDeleteDescriptor(RootHandle), name,
                SandboxDeleteDescriptor(quarantine.RootHandle), quarantineName, 1) != 0)
        {
            throw NativeFailure();
        }

        applied();
        SyncLinuxSandboxDeleteDirectory(RootHandle);
        SyncLinuxSandboxDeleteDirectory(quarantine.RootHandle);
        RequireLinuxSandboxDeleteParent(authority);
        quarantine.RequireLinuxSandboxDeleteParent(authority);
        RequireLinuxSandboxDeleteAbsent(RootHandle, sourceName);
        using var moved = quarantine.OpenLinuxSandboxDeleteRoot(quarantineName, expected);
        var identity = LinuxIdentity(moved, _linuxFileSystemUuid);
        if (!identity.SameObject(LinuxIdentity(source, _linuxFileSystemUuid)))
        {
            throw new WorkspacePathException("directory_identity_changed");
        }

        return identity;
    }

    /// <summary>Unlinks a bounded batch below the verified quarantine directory in postorder.</summary>
    [SupportedOSPlatform("linux")]
    internal SandboxRemovalBatchResult RemoveSandboxQuarantineBatchLinux(string name, WorkspaceObjectIdentity expected,
        int maximumEntries, LinuxSandboxDeletionAuthority authority, Action applied, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(applied);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumEntries, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumEntries, SandboxRemovalScanLimit);
        RequireLinuxSandboxDeleteParent(authority);
        cancellationToken.ThrowIfCancellationRequested();

        var pending = new Stack<LinuxSandboxDeleteDirectoryFrame>();
        int remainingScans = SandboxRemovalScanLimit;
        int removed = 0;
        try
        {
            using var root = OpenLinuxSandboxDeleteRoot(name, expected);
            pending.Push(OpenLinuxSandboxDeleteDirectory(RootHandle, LinuxSandboxDeleteName(name), root, LinuxBasicIdentity(root)));
            while (removed < maximumEntries && pending.TryPeek(out var current))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (remainingScans <= 1)
                {
                    if (removed != 0)
                    {
                        break;
                    }

                    throw new WorkspacePathException("directory_enumeration_limit");
                }

                if (current.Names.Count == 0)
                {
                    _ = CheckLinuxSandboxDeleteEntry(current.Parent, current.Handle);
                    var names = ReadLinuxSandboxDeleteNames(current.Handle, Math.Min(remainingScans - 1, SandboxRemovalPageSize), cancellationToken);
                    remainingScans -= names.Count + 1;
                    if (names.Count == 0)
                    {
                        UnlinkLinuxSandboxDeleteEntry(current.Parent, current.Name, current.Handle, directory: true,
                            authority, applied, cancellationToken);
                        pending.Pop().Dispose();
                        removed++;
                        continue;
                    }

                    foreach (var childName in names)
                    {
                        current.Names.Enqueue(childName);
                    }
                }

                if (remainingScans <= 1)
                {
                    continue;
                }

                remainingScans--;
                var next = current.Names.Dequeue();
                using var child = OpenLinuxSandboxDeleteName(current.Handle, next);
                var identity = CheckLinuxSandboxDeleteEntry(current.Handle, child);
                if (identity.IsDirectory)
                {
                    pending.Push(OpenLinuxSandboxDeleteDirectory(current.Handle, next, child, identity));
                    continue;
                }

                UnlinkLinuxSandboxDeleteEntry(current.Handle, next, child, directory: false, authority, applied, cancellationToken);
                removed++;
            }

            RequireLinuxSandboxDeleteParent(authority);
            return new SandboxRemovalBatchResult(removed, pending.Count == 0);
        }
        finally
        {
            while (pending.TryPop(out var directory))
            {
                directory.Dispose();
            }
        }
    }

    [SupportedOSPlatform("linux")]
    private void RequireLinuxSandboxDeleteParent(LinuxSandboxDeletionAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ObjectDisposedException.ThrowIf(_disposed, this);
        authority.RequirePath(this);
        CheckSandboxDirectory(RootHandle, configuredRoot: false);
        var current = LinuxIdentity(RootHandle, _linuxFileSystemUuid);
        if (!current.IsDirectory || current.Links == 0 || !current.SameObject(RootIdentity))
        {
            throw new WorkspacePathException("directory_identity_changed");
        }
    }

    private SafeFileHandle OpenLinuxSandboxDeleteRoot(string name, WorkspaceObjectIdentity expected)
    {
        var source = OpenLinuxSandboxDeleteName(RootHandle, LinuxSandboxDeleteName(name));
        try
        {
            var current = LinuxIdentity(source, _linuxFileSystemUuid);
            RequireLinuxSandboxDeleteMount(RootIdentity, current);
            if (!current.IsDirectory || current.Links == 0 || !current.SameObject(expected))
            {
                throw new WorkspacePathException("directory_identity_changed");
            }

            CheckSandboxDirectory(source, configuredRoot: false);
            return source;
        }
        catch
        {
            source.Dispose();
            throw;
        }
    }

    private static byte[] LinuxSandboxDeleteName(string name)
    {
        if (Components(name).Length != 1)
        {
            throw new WorkspacePathException("path_invalid");
        }

        var length = StrictUtf8.GetByteCount(name);
        if (length > 255)
        {
            throw new WorkspacePathException("path_too_large");
        }

        var result = new byte[checked(length + 1)];
        _ = StrictUtf8.GetBytes(name, result);
        return result;
    }

    private static void RequireLinuxSandboxDeleteMount(WorkspaceObjectIdentity parent, WorkspaceObjectIdentity child)
    {
        if (parent.Volume != child.Volume || parent.High != child.High)
        {
            throw new WorkspacePathException("mount_crossing");
        }
    }

    private static WorkspaceObjectIdentity CheckLinuxSandboxDeleteEntry(SafeFileHandle parent, SafeFileHandle entry)
    {
        var anchor = LinuxBasicIdentity(parent);
        var identity = LinuxBasicIdentity(entry);
        RequireLinuxSandboxDeleteMount(anchor, identity);
        if (!anchor.IsDirectory || anchor.Links == 0 || identity.Links == 0 ||
            !identity.IsDirectory && (identity.Links != 1 || !identity.IsFile && (identity.Mode & 0xf000) != 0xa000))
        {
            throw new WorkspacePathException("path_link_or_special");
        }

        RequireLinuxSandboxDeleteOwnership(parent, anchor);
        RequireLinuxSandboxDeleteOwnership(entry, identity);
        return identity;
    }

    private static unsafe void RequireLinuxSandboxDeleteOwnership(SafeFileHandle entry, WorkspaceObjectIdentity identity)
    {
        // An independently held descendant dirfd must confer no directory mutation to a different UID.
        if (identity.IsDirectory && (identity.Mode & 0x12) != 0) // S_IWGRP | S_IWOTH
        {
            throw new WorkspacePathException("file_guard_unavailable");
        }

        const uint ownerMask = 8; // STATX_UID
        byte* status = stackalloc byte[256];
        if (Statx(SandboxDeleteDescriptor(entry), string.Empty, 0x1000 | 0x100, ownerMask, status) != 0)
        {
            throw NativeFailure();
        }

        if ((*(uint*)status & ownerMask) != ownerMask || *(uint*)(status + 20) != EffectiveUserId())
        {
            throw new WorkspacePathException("file_guard_unavailable");
        }
    }

    private static LinuxSandboxDeleteDirectoryFrame OpenLinuxSandboxDeleteDirectory(SafeFileHandle parent, byte[] name,
        SafeFileHandle metadata, WorkspaceObjectIdentity identity)
    {
        // Reopen the held directory rather than resolving the original name twice. This descriptor permits fsync.
        var directory = LinuxOpenAt2(metadata, ".", LinuxSandboxDeleteDirectory, LinuxSandboxDeleteResolve);
        try
        {
            var reopened = CheckLinuxSandboxDeleteEntry(parent, directory);
            if (!identity.IsDirectory || !SameLinuxSnapshot(identity, reopened))
            {
                throw new WorkspacePathException("directory_identity_changed");
            }

            return new LinuxSandboxDeleteDirectoryFrame(parent, name, directory);
        }
        catch
        {
            directory.Dispose();
            throw;
        }
    }

    private static unsafe SafeFileHandle OpenLinuxSandboxDeleteName(SafeFileHandle parent, byte[] name)
    {
        fixed (byte* path = name)
        {
            var how = new LinuxOpenHow { Flags = LinuxSandboxDeleteMetadata, Resolve = LinuxSandboxDeleteResolve };
            var descriptor = OpenLinuxSandboxDeleteRaw(437, SandboxDeleteDescriptor(parent), path, ref how, (nuint)sizeof(LinuxOpenHow));
            if (descriptor < 0)
            {
                throw Marshal.GetLastPInvokeError() == 18 ? new WorkspacePathException("mount_crossing") : NativeFailure(); // EXDEV
            }

            return new SafeFileHandle(checked((nint)descriptor), ownsHandle: true);
        }
    }

    private static void RequireLinuxSandboxDeleteAbsent(SafeFileHandle parent, byte[] name)
    {
        try
        {
            using var present = OpenLinuxSandboxDeleteName(parent, name);
        }
        catch (WorkspacePathException failure) when (failure.Reason == "native_2") // ENOENT
        {
            return;
        }

        throw new WorkspacePathException("file_identity_changed");
    }

    [SupportedOSPlatform("linux")]
    private unsafe void UnlinkLinuxSandboxDeleteEntry(SafeFileHandle parent, byte[] name, SafeFileHandle entry, bool directory,
        LinuxSandboxDeletionAuthority authority, Action applied, CancellationToken cancellationToken)
    {
        RequireLinuxSandboxDeleteParent(authority);
        using var named = OpenLinuxSandboxDeleteName(parent, name);
        var current = CheckLinuxSandboxDeleteEntry(parent, named);
        if (current.IsDirectory != directory || !SameLinuxSnapshot(current, CheckLinuxSandboxDeleteEntry(parent, entry)))
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        cancellationToken.ThrowIfCancellationRequested();
        fixed (byte* path = name)
        {
            // A symlink is unlinked as one directory entry. The kernel atomically tests emptiness for a directory.
            if (UnlinkLinuxSandboxDeleteRaw(SandboxDeleteDescriptor(parent), path, directory ? 0x200 : 0) != 0)
            {
                throw NativeFailure();
            }
        }

        applied();
        SyncLinuxSandboxDeleteDirectory(parent);
        RequireLinuxSandboxDeleteAbsent(parent, name);
    }

    private static unsafe List<byte[]> ReadLinuxSandboxDeleteNames(SafeFileHandle directory, int maximum, CancellationToken cancellationToken)
    {
        long syscall = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => 217,
            Architecture.Arm64 => 61,
            _ => throw new WorkspacePathException("directory_enumeration_unavailable"),
        };
        // Start with a fresh cursor after each page is removed. An earlier cursor cannot prove a changed directory empty.
        using var listing = LinuxOpenAt2(directory, ".", LinuxSandboxDeleteDirectory, LinuxSandboxDeleteResolve);
        var buffer = new byte[8192];
        var names = new List<byte[]>();
        fixed (byte* data = buffer)
        {
            while (names.Count < maximum)
            {
                cancellationToken.ThrowIfCancellationRequested();
                long count = ReadLinuxSandboxDeleteRaw(syscall, SandboxDeleteDescriptor(listing), data, (nuint)buffer.Length);
                if (count < 0)
                {
                    throw NativeFailure();
                }

                if (count == 0)
                {
                    break;
                }

                if (count > buffer.Length)
                {
                    throw new WorkspacePathException("directory_entry_invalid");
                }

                ReadLinuxSandboxDeletePage(buffer.AsSpan(0, checked((int)count)), maximum, names);
            }
        }

        return names;
    }

    private static void ReadLinuxSandboxDeletePage(ReadOnlySpan<byte> page, int maximum, List<byte[]> names)
    {
        while (!page.IsEmpty && names.Count < maximum)
        {
            // In a Linux getdents64 record the size is at offset 16 and the name starts at 19.
            if (page.Length < 20)
            {
                throw new WorkspacePathException("directory_entry_invalid");
            }

            int length = MemoryMarshal.Read<ushort>(page[16..]);
            if (length < 20 || length > page.Length)
            {
                throw new WorkspacePathException("directory_entry_invalid");
            }

            var field = page[19..length];
            int end = field.IndexOf((byte)0);
            if (end is < 1 or > 255 || field[..end].Contains((byte)'/'))
            {
                throw new WorkspacePathException("directory_entry_invalid");
            }

            var name = field[..end];
            if (!name.SequenceEqual("."u8) && !name.SequenceEqual(".."u8))
            {
                names.Add(field[..(end + 1)].ToArray());
            }

            page = page[length..];
        }
    }

    private static int SandboxDeleteDescriptor(SafeFileHandle handle) => checked((int)handle.DangerousGetHandle());

    private static void SyncLinuxSandboxDeleteDirectory(SafeFileHandle directory)
    {
        if (SyncDirectory(SandboxDeleteDescriptor(directory)) != 0)
        {
            throw NativeFailure();
        }
    }

    [LibraryImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static unsafe partial long OpenLinuxSandboxDeleteRaw(long number, int parent, byte* name, ref LinuxOpenHow how, nuint size);

    [LibraryImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static unsafe partial long ReadLinuxSandboxDeleteRaw(long number, int directory, byte* data, nuint size);

    [LibraryImport("libc", EntryPoint = "unlinkat", SetLastError = true)]
    private static unsafe partial int UnlinkLinuxSandboxDeleteRaw(int parent, byte* name, int flags);

    private sealed class LinuxSandboxDeleteDirectoryFrame(SafeFileHandle parent, byte[] name, SafeFileHandle handle) : IDisposable
    {
        internal SafeFileHandle Parent { get; } = parent;
        internal byte[] Name { get; } = name;
        internal SafeFileHandle Handle { get; } = handle;
        internal Queue<byte[]> Names { get; } = new();

        public void Dispose() => Handle.Dispose();
    }
}
