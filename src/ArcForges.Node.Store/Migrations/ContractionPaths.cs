// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Store.Migrations;

/// <summary>Resolves local contraction inputs without following directory aliases or opening special files as streams.</summary>
internal static partial class ContractionPaths
{
    private const int WorkingDirectory = -100; // AT_FDCWD
    private const int LinuxPathOnly = 0x200000;
    private const int LinuxCloseOnExec = 0x80000;
    private const int LinuxNonBlocking = 0x800;
    private const int LinuxGetFileStatus = 3; // F_GETFL
    private const int LinuxSetFileStatus = 4; // F_SETFL
    private const ushort LinuxDirectory = 0x4000;
    private const ushort LinuxRegular = 0x8000;
    private const uint LinuxStatMask = 0x1109; // STATX_TYPE | STATX_UID | STATX_INO | STATX_MNT_ID
    private const uint WindowsRead = 0x80000000;
    private const uint WindowsReadAttributes = 0x80;
    private const uint WindowsOpenReparsePoint = 0x00200000;
    private const uint WindowsBackupSemantics = 0x02000000;
    private static readonly int s_linuxNoFollow = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? 0x8000 : 0x20000;
    private static readonly int s_linuxDirectory = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? 0x4000 : 0x10000;

    internal readonly record struct NativeIdentity(ulong Volume, ulong High, ulong Low);

    internal static FileStream OpenRegularRead(string path)
    {
        string full = Normalize(path);
        using var directory = WalkDirectories(Parent(full), allowMissing: false);
        using var probe = OpenRegularHandle(full, directory.Last, readBytes: false);
        NativeIdentity expected = ReadNamedRegular(probe, directory.Last);
        var handle = OpenRegularHandle(full, directory.Last, readBytes: true);
        try
        {
            if (ReadNamedRegular(handle, directory.Last) != expected)
                throw Refused("source_file_identity_changed");

            if (OperatingSystem.IsLinux())
            {
                // Keep nonblocking mode until the opened descriptor is verified as a regular file.
                // A FileStream over a nonblocking Linux descriptor uses sequential reads in .NET 11.
                int flags = GetOrSetFileStatus(handle, LinuxGetFileStatus, 0);
                if (flags < 0 || GetOrSetFileStatus(handle, LinuxSetFileStatus, flags & ~LinuxNonBlocking) != 0)
                    throw Refused("source_file_seekable_read_unavailable");
            }

            return new FileStream(handle, FileAccess.Read);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>Observes the named regular object without taking a data-open that would exclude a current writer.</summary>
    internal static NativeIdentity NamedRegularIdentity(string path)
    {
        string full = Normalize(path);
        using var directory = WalkDirectories(Parent(full), allowMissing: false);
        using var file = OpenRegularHandle(full, directory.Last, readBytes: false);
        return ReadNamedRegular(file, directory.Last);
    }

    private static SafeFileHandle OpenRegularHandle(string full, DirectoryEntry parent, bool readBytes) => OperatingSystem.IsLinux()
        ? OpenLinux(parent.Handle, Path.GetFileName(full), (readBytes ? LinuxNonBlocking : LinuxPathOnly) | s_linuxNoFollow)!
        : OpenWindows(full, readBytes ? WindowsRead : WindowsReadAttributes,
            readBytes ? FileShare.Read : FileShare.ReadWrite | FileShare.Delete)!;

    private static NativeIdentity ReadNamedRegular(SafeFileHandle file, DirectoryEntry parent)
    {
        if (OperatingSystem.IsLinux())
        {
            var observed = ReadLinux(file, LinuxRegular);
            if (observed.Mount != parent.Mount)
                throw Refused("source_file_mount_alias");

            return observed.Identity;
        }

        return ReadWindows(file, directory: false);
    }

    internal static NativeIdentity Identity(SafeFileHandle handle) => OperatingSystem.IsLinux()
        ? ReadLinux(handle, LinuxRegular).Identity
        : OperatingSystem.IsWindows() ? ReadWindows(handle, directory: false) : throw Refused("native_path_identity_unavailable");

    internal static void RequireDirectoryChain(string path)
    {
        using var held = WalkDirectories(Normalize(path), allowMissing: false);
    }

    [SupportedOSPlatform("linux")]
    internal static void RequireExclusiveLock(SafeFileHandle handle)
    {
        const int lockExclusiveNonBlocking = 2 | 4;
        if (Flock((int)handle.DangerousGetHandle(), lockExclusiveNonBlocking) != 0)
            throw new IOException($"native_update_lock_unavailable: errno {Marshal.GetLastPInvokeError()}");
    }

    [LibraryImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static partial int Flock(int fileDescriptor, int operation);

    internal static void RequireOwnedDirectory(string path)
    {
        string full = Normalize(path);
        using var held = WalkDirectories(full, allowMissing: false);
        if (OperatingSystem.IsWindows())
        {
            RequireWindowsDirectoryOwner(full);
        }
        else if (OperatingSystem.IsLinux())
        {
            int descriptor = held.Last.Handle.DangerousGetHandle().ToInt32();
            const uint ownershipMask = LinuxStatMask | 2; // STATX_MODE
            if (Statx(descriptor, "", 0x1100, ownershipMask, out var status) != 0 ||
                (status.Mask & ownershipMask) != ownershipMask || status.Owner != GetEffectiveUid() ||
                ((UnixFileMode)status.Mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
                throw Refused("source_directory_owner_unconfirmed");
        }
    }

    [SupportedOSPlatform("windows")]
    private static void RequireWindowsDirectoryOwner(string path)
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        if (identity.User is not { } owner || !owner.Equals(security.GetOwner(typeof(SecurityIdentifier))))
            throw Refused("source_directory_owner_unconfirmed");

        var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        if ((descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 || descriptor.DiscretionaryAcl is null)
            throw Refused("source_directory_write_authority_unconfirmed");

        const FileSystemRights write = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & write) != 0 &&
                rule.IdentityReference is SecurityIdentifier sid && !owner.Equals(sid) &&
                !sid.IsWellKnown(WellKnownSidType.LocalSystemSid) && !sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                throw Refused("source_directory_write_authority_unconfirmed");
        }
    }

    internal sealed class UpdateDirectory : IDisposable
    {
        private readonly DirectoryChain _directories;
        private readonly string _full;

        internal UpdateDirectory(string path, bool allowSharedStickyParent = false)
        {
            _full = Normalize(path);
            _directories = WalkDirectories(_full, allowMissing: false);
            try
            {
                if (OperatingSystem.IsLinux())
                {
                    foreach (var entry in _directories.Entries)
                        VerifyLinuxDirectory(entry.Handle, leaf: !allowSharedStickyParent && entry == _directories.Last);
                }
                else if (OperatingSystem.IsWindows())
                    RequireWindowsDirectoryOwner(_full);
            }
            catch
            {
                _directories.Dispose();
                throw;
            }
        }

        internal FileStream? TryRead(string name)
        {
            var parent = _directories.Last;
            string path = Path.Combine(_full, name);
            if (OperatingSystem.IsWindows())
            {
                var file = OpenWindows(path, WindowsRead, FileShare.Read, allowMissing: true);
                if (file is null)
                    return null;
                return CheckedStream(file, parent, FileAccess.Read);
            }

            var linux = OpenLinux(parent.Handle, name, LinuxNonBlocking | s_linuxNoFollow, allowMissing: true);
            return linux is null ? null : CheckedStream(linux, parent, FileAccess.Read);
        }

        internal FileStream Lock(string name)
        {
            var parent = _directories.Last;
            string path = Path.Combine(_full, name);
            if (OperatingSystem.IsLinux())
            {
                const int readWriteCreate = 2 | 0x40;
                var file = OpenLinux(parent.Handle, name, readWriteCreate | LinuxNonBlocking | s_linuxNoFollow, mode: 0x180)!;
                var lease = CheckedStream(file, parent, FileAccess.ReadWrite);
                try
                {
                    RequireExclusiveLock(lease.SafeFileHandle);
                    using var probe = OpenLinux(parent.Handle, name, LinuxPathOnly | s_linuxNoFollow)!;
                    if (ReadNamedRegular(probe, parent) != ReadNamedRegular(lease.SafeFileHandle, parent))
                        throw Refused("update_lock_identity_changed");
                    return lease;
                }
                catch
                {
                    lease.Dispose();
                    throw;
                }
            }

            using var current = OpenWindows(path, WindowsReadAttributes, FileShare.ReadWrite, allowMissing: true);
            var expected = current is null ? (NativeIdentity?)null : ReadWindows(current, directory: false);
            var handle = OpenWindows(path, 0x40000000 | WindowsRead, FileShare.None, creation: expected is null ? 1U : 3U, lockAttempt: true)!;
            var windows = CheckedStream(handle, parent, FileAccess.ReadWrite);
            if (expected is not null && expected != ReadWindows(windows.SafeFileHandle, directory: false))
            {
                windows.Dispose();
                throw Refused("update_lock_identity_changed");
            }
            return windows;
        }

        internal FileStream Create(string name)
        {
            var parent = _directories.Last;
            if (OperatingSystem.IsWindows())
            {
                var file = OpenWindows(Path.Combine(_full, name), 0x40000000, FileShare.None, creation: 1)!;
                return CheckedStream(file, parent, FileAccess.Write);
            }

            const int writeCreateExclusive = 1 | 0x40 | 0x80;
            return CheckedStream(OpenLinux(parent.Handle, name, writeCreateExclusive | s_linuxNoFollow, mode: 0x180)!,
                parent, FileAccess.Write);
        }

        internal void Replace(string temporary, string destination) => Publish(temporary, destination, replace: true);

        internal void PublishNew(string temporary, string destination) => Publish(temporary, destination, replace: false);

        private void Publish(string temporary, string destination, bool replace)
        {
            if (OperatingSystem.IsWindows())
            {
                const uint writeThrough = 0x8;
                const uint replaceExisting = 0x1;
                if (!MoveFile(Path.Combine(_full, temporary), Path.Combine(_full, destination),
                    writeThrough | (replace ? replaceExisting : 0)))
                    throw Refused("update_marker_publish_unconfirmed");
                return;
            }

            int descriptor = _directories.Last.Handle.DangerousGetHandle().ToInt32();
            const uint noReplace = 1;
            int result = replace ? RenameAt(descriptor, temporary, descriptor, destination)
                : RenameAt2(descriptor, temporary, descriptor, destination, noReplace);
            if (result != 0)
                throw Refused("update_marker_publish_unconfirmed");
            SynchronizeDirectory();
        }

        internal void SynchronizeDirectory()
        {
            if (!OperatingSystem.IsLinux())
                return;

            using var sync = OpenLinux(_directories.Last.Handle, ".", s_linuxDirectory | s_linuxNoFollow)!;
            if (Sync(sync.DangerousGetHandle().ToInt32()) != 0)
                throw Refused("update_directory_sync_unconfirmed");
        }

        internal void SynchronizeFile(string name)
        {
            var parent = _directories.Last;
            if (OperatingSystem.IsWindows())
            {
                using var file = OpenWindows(Path.Combine(_full, name), 0x40000000 | WindowsReadAttributes, FileShare.Read)!;
                _ = ReadNamedRegular(file, parent);
                if (!FlushFileBuffers(file))
                    throw Refused("update_file_sync_unconfirmed");
            }
            else
            {
                using var file = OpenLinux(parent.Handle, name, LinuxNonBlocking | s_linuxNoFollow)!;
                _ = ReadNamedRegular(file, parent);
                if (Sync(file.DangerousGetHandle().ToInt32()) != 0)
                    throw Refused("update_file_sync_unconfirmed");
            }
        }

        internal void DeleteTemporary(string temporary)
        {
            if (OperatingSystem.IsWindows())
                File.Delete(Path.Combine(_full, temporary));
            else if (UnlinkAt(_directories.Last.Handle.DangerousGetHandle().ToInt32(), temporary, 0) != 0
                && Marshal.GetLastPInvokeError() != 2)
                throw Refused("update_marker_temporary_unconfirmed");
        }

        public void Dispose() => _directories.Dispose();

        private static FileStream CheckedStream(SafeFileHandle file, DirectoryEntry parent, FileAccess access)
        {
            try
            {
                _ = ReadNamedRegular(file, parent);
                if (OperatingSystem.IsLinux())
                {
                    int flags = GetOrSetFileStatus(file, LinuxGetFileStatus, 0);
                    if (flags < 0 || GetOrSetFileStatus(file, LinuxSetFileStatus, flags & ~LinuxNonBlocking) != 0)
                        throw Refused("update_file_seekable_unavailable");
                }
                return new FileStream(file, access);
            }
            catch
            {
                file.Dispose();
                throw;
            }
        }

        private static void VerifyLinuxDirectory(SafeFileHandle directory, bool leaf)
        {
            int descriptor = directory.DangerousGetHandle().ToInt32();
            const uint ownershipMask = LinuxStatMask | 2; // STATX_MODE
            if (Statx(descriptor, "", 0x1100, ownershipMask, out var status) != 0 ||
                (status.Mask & ownershipMask) != ownershipMask)
                throw Refused("update_directory_owner_unconfirmed");

            uint owner = GetEffectiveUid();
            var mode = (UnixFileMode)status.Mode;
            if ((status.Owner != owner && (leaf || status.Owner != 0)) ||
                ((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0 &&
                    (leaf || (mode & UnixFileMode.StickyBit) == 0)))
                throw Refused("update_directory_write_authority_unconfirmed");
        }
    }

    [LibraryImport("libc", EntryPoint = "renameat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int RenameAt(int oldDirectory, string oldName, int newDirectory, string newName);

    [LibraryImport("libc", EntryPoint = "renameat2", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int RenameAt2(int oldDirectory, string oldName, int newDirectory, string newName, uint flags);

    [LibraryImport("libc", EntryPoint = "unlinkat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int UnlinkAt(int directory, string name, int flags);

    internal static void RequireSeparateRoots(string original, string backup, string staging, bool allowMissingBackup = false)
    {
        original = Normalize(original);
        backup = Normalize(backup);
        staging = Normalize(staging);
        if (Overlap(original, backup) || Overlap(original, staging) || Overlap(backup, staging))
            throw Refused("contraction_roots_overlap");

        using var source = WalkDirectories(original, allowMissing: false);
        using var archive = WalkDirectories(backup, allowMissing: allowMissingBackup);
        using var restore = WalkDirectories(staging, allowMissing: true);
        if (source.Overlaps(archive) || source.Overlaps(restore) || archive.Overlaps(restore))
            throw Refused("contraction_root_identity_overlap");

        if (OperatingSystem.IsLinux())
            RequireUnaliasedLinuxMounts([source, archive, restore]);
    }

    private static bool Overlap(string left, string right) => IsWithin(left, right) || IsWithin(right, left);

    private static bool IsWithin(string parent, string candidate)
    {
        string relative = Path.GetRelativePath(parent, candidate);
        return !Path.IsPathRooted(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }

    private static string Normalize(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.Contains('\0'))
            throw Refused("local_absolute_path_required");

        string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (OperatingSystem.IsWindows())
        {
            string root = Path.GetPathRoot(full)!;
            if (root.Length != 3 || !char.IsAsciiLetter(root[0]) || root[1] != ':' || new DriveInfo(root).DriveType != DriveType.Fixed ||
                full.AsSpan(root.Length).Contains(':'))
                throw Refused("local_fixed_windows_path_required");
        }
        else if (!OperatingSystem.IsLinux() || RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
        {
            throw Refused("native_path_identity_unavailable");
        }

        return full;
    }

    private static string Parent(string path) => Path.GetDirectoryName(path) ?? throw Refused("source_file_alias_or_type");

    private static DirectoryChain WalkDirectories(string full, bool allowMissing)
    {
        string root = Path.GetPathRoot(full)!;
        string current = root;
        var chain = new DirectoryChain();
        try
        {
            if (OperatingSystem.IsLinux())
            {
                chain.Add(OpenLinux(parent: null, "/", LinuxPathOnly | s_linuxDirectory | s_linuxNoFollow)!);
            }
            else
            {
                chain.Add(OpenWindows(root, WindowsReadAttributes, FileShare.ReadWrite)!);
                RequireWindowsVolumeRoot(chain.Last.Handle);
            }

            foreach (string name in full[root.Length..].Split(Path.DirectorySeparatorChar))
            {
                if (name.Length == 0)
                    continue;

                SafeFileHandle? next;
                if (OperatingSystem.IsLinux())
                {
                    next = OpenLinux(chain.Last.Handle, name, LinuxPathOnly | s_linuxDirectory | s_linuxNoFollow, allowMissing);
                }
                else
                {
                    current = Path.Combine(current, name);
                    next = OpenWindows(current, WindowsReadAttributes, FileShare.ReadWrite, allowMissing);
                }

                if (next is null)
                {
                    chain.HasLeaf = false;
                    break;
                }

                chain.Add(next);
            }

            return chain;
        }
        catch
        {
            chain.Dispose();
            throw;
        }
    }

    private static void RequireUnaliasedLinuxMounts(DirectoryChain[] chains)
    {
        var mounts = new Dictionary<ulong, (ulong Device, string Root)>();
        var occurrences = new Dictionary<ulong, int>();
        foreach (string line in File.ReadLines("/proc/self/mountinfo"))
        {
            string[] fields = line.Split(' ', 6);
            if (fields.Length != 6 || !ulong.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out var id))
                throw Refused("linux_mount_ancestry_unconfirmed");

            string[] device = fields[2].Split(':');
            if (device.Length != 2 || !uint.TryParse(device[0], NumberStyles.None, CultureInfo.InvariantCulture, out var major) ||
                !uint.TryParse(device[1], NumberStyles.None, CultureInfo.InvariantCulture, out var minor))
                throw Refused("linux_mount_ancestry_unconfirmed");

            ulong volume = LinuxVolume(major, minor);
            if (!mounts.TryAdd(id, (volume, fields[3])))
                throw Refused("linux_mount_ancestry_unconfirmed");

            occurrences[volume] = occurrences.GetValueOrDefault(volume) + 1;
        }

        foreach (var chain in chains)
        {
            ulong? previous = null;
            foreach (var entry in chain.Entries)
            {
                if (entry.Mount == previous)
                    continue;

                if (!mounts.TryGetValue(entry.Mount, out var mount) || mount.Device != entry.Identity.Volume || mount.Root != "/" ||
                    (previous is not null && occurrences[mount.Device] != 1))
                    throw Refused("linux_mount_ancestry_unconfirmed");

                previous = entry.Mount;
            }
        }
    }

    private static SafeFileHandle? OpenLinux(SafeFileHandle? parent, string name, int flags, bool allowMissing = false, uint mode = 0)
    {
        int directory = parent is null ? WorkingDirectory : parent.DangerousGetHandle().ToInt32();
        int fd = OpenAt(directory, name, flags | LinuxCloseOnExec, mode);
        if (fd >= 0)
            return new SafeFileHandle(fd, ownsHandle: true);
        if (allowMissing && Marshal.GetLastPInvokeError() == 2)
            return null;

        throw Refused("source_path_open_unconfirmed");
    }

    private static (NativeIdentity Identity, ulong Mount) ReadLinux(SafeFileHandle handle, ushort type)
    {
        int fd = handle.DangerousGetHandle().ToInt32();
        if (Statx(fd, "", 0x1100, LinuxStatMask, out var stat) != 0 || (stat.Mask & LinuxStatMask) != LinuxStatMask ||
            (stat.Mode & 0xF000) != type || (type == LinuxRegular && stat.Owner != GetEffectiveUid()))
            throw Refused(type == LinuxRegular ? "source_file_alias_or_type" : "source_directory_alias_or_type");

        return (new(LinuxVolume(stat.DeviceMajor, stat.DeviceMinor), 0, stat.Inode), stat.MountId);
    }

    private static ulong LinuxVolume(uint major, uint minor) => ((ulong)major << 32) | minor;

    private static SafeFileHandle? OpenWindows(string full, uint access, FileShare share, bool allowMissing = false, uint creation = 3, bool lockAttempt = false)
    {
        var handle = CreateFile(full, access, (uint)share, 0, creation, WindowsOpenReparsePoint | WindowsBackupSemantics, 0);
        if (!handle.IsInvalid)
            return handle;

        int error = Marshal.GetLastPInvokeError();
        handle.Dispose();
        if (allowMissing && error is 2 or 3)
            return null;
        if (lockAttempt && error is 32 or 80)
            throw new IOException("native_update_lock_unavailable");

        throw Refused("source_path_open_unconfirmed");
    }

    private static NativeIdentity ReadWindows(SafeFileHandle handle, bool directory)
    {
        if (GetFileType(handle) != 1 || !GetWindowsAttributes(handle, 9, out var attributes, 8) ||
            ((FileAttributes)attributes.Flags & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            ((FileAttributes)attributes.Flags).HasFlag(FileAttributes.Directory) != directory || !GetWindowsIdentity(handle, 18, out var id, 24))
            throw Refused(directory ? "source_directory_alias_or_type" : "source_file_alias_or_type");

        return new(id.Volume, id.High, id.Low);
    }

    private static unsafe void RequireWindowsVolumeRoot(SafeFileHandle root)
    {
        const string prefix = @"\\?\Volume{";
        Span<char> name = stackalloc char[64];
        uint length;
        fixed (char* buffer = name)
            length = GetFinalPath(root, buffer, (uint)name.Length, 1); // VOLUME_NAME_GUID

        if (length == 0 || length >= name.Length)
            throw Refused("windows_volume_root_unconfirmed");

        var observed = name[..(int)length];
        if (!observed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !observed.EndsWith("}\\", StringComparison.Ordinal) ||
            !Guid.TryParseExact(observed[prefix.Length..^2], "D", out _))
            throw Refused("windows_volume_root_unconfirmed");
    }

    private static StoreIncompatibleException Refused(string reason) => new("node_contraction_native_scope_refused: " + reason);

    private sealed class DirectoryChain : IDisposable
    {
        internal List<DirectoryEntry> Entries { get; } = [];
        internal bool HasLeaf { get; set; } = true;
        internal DirectoryEntry Last => Entries[^1];

        internal void Add(SafeFileHandle handle)
        {
            try
            {
                var (identity, mount) = OperatingSystem.IsLinux() ? ReadLinux(handle, LinuxDirectory) : (ReadWindows(handle, directory: true), 0UL);
                Entries.Add(new(handle, identity, mount));
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        internal bool Overlaps(DirectoryChain other) =>
            (HasLeaf && other.Entries.Any(entry => entry.Identity == Last.Identity)) ||
            (other.HasLeaf && Entries.Any(entry => entry.Identity == other.Last.Identity));

        public void Dispose()
        {
            for (int index = Entries.Count - 1; index >= 0; index--)
                Entries[index].Handle.Dispose();
        }
    }

    private sealed record DirectoryEntry(SafeFileHandle Handle, NativeIdentity Identity, ulong Mount);

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxStat
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(20)] internal uint Owner;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(136)] internal uint DeviceMajor;
        [FieldOffset(140)] internal uint DeviceMinor;
        [FieldOffset(144)] internal ulong MountId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsAttributes
    {
        internal uint Flags;
        internal uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsIdentity
    {
        internal ulong Volume;
        internal ulong Low;
        internal ulong High;
    }

    [LibraryImport("libc", EntryPoint = "openat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int OpenAt(int directory, string path, int flags, uint mode);

    [LibraryImport("libc", EntryPoint = "fcntl")]
    private static partial int GetOrSetFileStatus(SafeFileHandle file, int command, int flags);

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int Statx(int directory, string path, int flags, uint mask, out LinuxStat status);

    [LibraryImport("libc", EntryPoint = "geteuid")]
    private static partial uint GetEffectiveUid();

    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static partial int Sync(int descriptor);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFile(string name, uint access, uint share, nint security, uint disposition, uint flags, nint template);

    [LibraryImport("kernel32.dll", EntryPoint = "MoveFileExW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool MoveFile(string existing, string destination, uint flags);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FlushFileBuffers(SafeFileHandle file);

    [LibraryImport("kernel32.dll")]
    private static partial uint GetFileType(SafeFileHandle file);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetWindowsAttributes(SafeFileHandle file, int type, out WindowsAttributes attributes, uint size);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetWindowsIdentity(SafeFileHandle file, int type, out WindowsIdentity identity, uint size);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
    private static unsafe partial uint GetFinalPath(SafeFileHandle file, char* path, uint length, uint flags);
}
