// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Client;

internal sealed partial class LocalTransferFile : IDisposable
{
    private const int LinuxNonBlocking = 0x800;
    private readonly FileVersion _version;
    internal FileStream Body { get; }
    internal long Length => _version.Length;

    private LocalTransferFile(FileStream body, FileVersion version)
    {
        Body = body;
        _version = version;
    }

    internal static LocalTransferFile OpenSource(string path)
    {
        var (directory, name) = Resolve(path);
        using var parent = OpenParent(directory, writing: false);
        var handle = OperatingSystem.IsWindows()
            ? OpenWindowsEntry(parent, name, stage: false)
            : CheckedLinuxHandle(OpenAt(Descriptor(parent), name, 0x80000 | 0x20000 | LinuxNonBlocking, 0));
        try
        {
            var version = ReadVersion(handle);
            if (OperatingSystem.IsLinux())
            {
                UseLinuxSynchronousFileIo(handle);
            }

            return new(OpenBody(handle, FileAccess.Read), version);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal void VerifySource()
    {
        if (ReadVersion(Body.SafeFileHandle) != _version)
        {
            throw new IOException("The local source changed during the transfer.");
        }
    }

    public void Dispose() => Body.Dispose();

    internal sealed class Destination : IDisposable
    {
        private readonly SafeFileHandle _parent;
        private readonly SafeFileHandle _stage;
        private readonly FileIdentity _parentIdentity;
        private readonly string _directory;
        private readonly string _name;
        private bool _published;
        private bool _disposed;
        internal FileStream Body { get; }
        internal bool Published => _published;
        internal bool PublicationConfirmed { get; private set; }
        internal string? CleanupFailure { get; private set; }

        private Destination(SafeFileHandle parent, SafeFileHandle stage, FileIdentity parentIdentity, string directory, string name,
            FileStream body)
        {
            _parent = parent;
            _stage = stage;
            _parentIdentity = parentIdentity;
            _directory = directory;
            _name = name;
            Body = body;
        }

        internal static Destination Create(string path)
        {
            var (directory, name) = Resolve(path);
            var parent = OpenParent(directory, writing: true);
            try
            {
                var parentIdentity = ReadIdentity(parent);
                var handle = OperatingSystem.IsWindows()
                    ? OpenWindowsEntry(parent, ".arcforges-export-" + Guid.NewGuid().ToString("N"), stage: true)
                    : CheckedLinuxHandle(OpenAt(Descriptor(parent), ".", 0x410000 | 0x80000 | 2, 0x180));
                return new(parent, handle, parentIdentity, directory, name, OpenBody(handle, FileAccess.ReadWrite));
            }
            catch
            {
                parent.Dispose();
                throw;
            }
        }

        internal void Publish()
        {
            Body.Flush(flushToDisk: true);
            VerifyParent();
            if (OperatingSystem.IsWindows())
            {
                RenameWindows(Body.SafeFileHandle, _parent, _name);
                _published = true;
                RequireWindowsPath(Body.SafeFileHandle, Path.Combine(_directory, _name));
            }
            else
            {
                int stage = Descriptor(Body.SafeFileHandle);
                string source = "/proc/self/fd/" + stage.ToString(CultureInfo.InvariantCulture);
                if (LinkAt(-100, source, Descriptor(_parent), _name, 0x400) != 0)
                {
                    throw NativeFailure("Could not publish the local destination without replacement.");
                }

                _published = true;
                var published = ReadLinuxIdentity(Descriptor(_parent), _name, 0x100);
                if (published != ReadIdentity(Body.SafeFileHandle))
                {
                    throw new IOException("The local publication identity is unconfirmed.");
                }

                if (Sync(Descriptor(_parent)) != 0)
                {
                    throw NativeFailure("The local destination was published, but directory durability is unconfirmed.");
                }
            }

            VerifyParent();
            if (OperatingSystem.IsWindows() && !FlushFileBuffers(_stage))
            {
                throw NativeFailure("The local destination was renamed, but the Windows file flush failed.");
            }

            PublicationConfirmed = true;
        }

        private void VerifyParent()
        {
            using var named = OpenParent(_directory, writing: true);
            if (ReadIdentity(named) != _parentIdentity)
            {
                throw new IOException("The local destination directory changed during export.");
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            try
            {
                if (OperatingSystem.IsWindows() && !_published)
                {
                    DeleteWindows(_stage);
                }
            }
            catch (IOException failure)
            {
                RecordCleanupFailure(failure);
            }

            try
            {
                Body.Dispose();
            }
            catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
            {
                RecordCleanupFailure(failure);
            }
            finally
            {
                _stage.Dispose();
                _parent.Dispose();
            }
        }

        private void RecordCleanupFailure(Exception failure)
        {
            string detail = failure.InnerException is Win32Exception native
                ? FormattableString.Invariant($"{failure.Message} (native error {native.NativeErrorCode})")
                : failure.Message;
            CleanupFailure = CleanupFailure is null ? detail : CleanupFailure + " " + detail;
        }
    }

    private static (string Directory, string Name) Resolve(string path)
    {
        var full = Path.GetFullPath(path);
        var name = Path.GetFileName(full);
        var directory = Path.GetDirectoryName(full);
        if (directory is null || name.Length == 0 || name is "." or "..")
        {
            throw new IOException("The local path must name a regular file.");
        }

        if (OperatingSystem.IsWindows() &&
            (full.StartsWith(@"\\", StringComparison.Ordinal) || full.AsSpan(2).Contains(':')
                || name.EndsWith(' ') || name.EndsWith('.')))
        {
            throw new IOException("The local path must name a filesystem file on a local Windows drive.");
        }

        return (directory, name);
    }

    private static SafeFileHandle OpenParent(string directory, bool writing)
    {
        if (OperatingSystem.IsLinux())
        {
            var options = new LinuxOpen { Flags = 0x80000 | 0x10000, Resolve = 0x04 | 0x02 };
            return CheckedLinuxHandle(OpenAt2(437, -100, directory, in options, 24));
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Local file transfer requires Windows or Linux.");
        }

        uint access = 0x00100000 | 0x0020 | 0x0080 | (writing ? 0x0002u : 0);
        var parent = CreateFile(@"\\?\" + directory, access,
            3, 0, 3, 0x02000000 | 0x00200000, 0);
        try
        {
            if (parent.IsInvalid || !GetInfo(parent, out var info) || (info.Attributes & 0x410) != 0x10)
            {
                throw NativeFailure("Could not hold the local parent directory.");
            }

            RequireWindowsPath(parent, directory);
            return parent;
        }
        catch
        {
            parent.Dispose();
            throw;
        }
    }

    private static unsafe void RequireWindowsPath(SafeFileHandle handle, string expected)
    {
        var chars = new char[32768];
        uint length;
        fixed (char* buffer = chars)
        {
            length = GetFinalPath(handle, buffer, (uint)chars.Length, 0);
        }

        if (length < 4 || length >= chars.Length ||
            !Path.TrimEndingDirectorySeparator(chars.AsSpan(4, checked((int)length) - 4).ToString())
                .Equals(Path.TrimEndingDirectorySeparator(expected), StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("The opened local object resolves through an alternate path.");
        }
    }

    private static FileStream OpenBody(SafeFileHandle handle, FileAccess access)
    {
        try
        {
            return new FileStream(handle, access, bufferSize: 65536, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void UseLinuxSynchronousFileIo(SafeFileHandle handle)
    {
        const int GetStatusFlags = 3;
        const int SetStatusFlags = 4;
        // Keep the initial no-follow open nonblocking until the held descriptor is
        // verified as a regular file. The stream can then use positional I/O.
        int descriptor = Descriptor(handle);
        int flags = FileControl(descriptor, GetStatusFlags, 0);
        if (flags < 0 || (flags & LinuxNonBlocking) != 0 &&
            FileControl(descriptor, SetStatusFlags, flags & ~LinuxNonBlocking) < 0)
        {
            throw NativeFailure("Could not configure the verified local source for positional I/O.");
        }
    }

    private static FileVersion ReadVersion(SafeFileHandle handle)
    {
        if (OperatingSystem.IsLinux())
        {
            const uint Required = 0x0001 | 0x0200 | 0x0080 | 0x0040;
            if (Statx(Descriptor(handle), "", 0x1000, Required, out var info) != 0
                || (info.Mask & Required) != Required || (info.Mode & 0xf000) != 0x8000)
            {
                throw new IOException("The local source is not an opened regular file.");
            }

            return new(checked((long)info.Length), info.Modified, info.ModifiedNanos, info.Changed, info.ChangedNanos);
        }

        if (GetFileType(handle) != 1 || !GetInfo(handle, out var file) || (file.Attributes & 0x450) != 0)
        {
            throw new IOException("The local source is not an opened regular file.");
        }

        return new(checked((long)((ulong)file.LengthHigh << 32 | file.LengthLow)), file.Modified, 0, 0, 0);
    }

    private static FileIdentity ReadIdentity(SafeFileHandle handle)
    {
        if (OperatingSystem.IsLinux())
        {
            return ReadLinuxIdentity(Descriptor(handle), "", 0x1000);
        }

        return GetInfo(handle, out var info) ? new(info.Volume, (ulong)info.IdHigh << 32 | info.IdLow)
            : throw NativeFailure("Could not read the held local object identity.");
    }

    private static FileIdentity ReadLinuxIdentity(int directory, string path, int flags)
    {
        const uint Required = 0x0100 | 0x1000;
        if (Statx(directory, path, flags, Required, out var info) != 0 || (info.Mask & Required) != Required)
        {
            throw NativeFailure("Could not read the held local object identity.");
        }

        return new(info.Mount, info.Inode);
    }

    private static SafeFileHandle CheckedLinuxHandle(long descriptor) => descriptor >= 0
        ? new SafeFileHandle((nint)descriptor, ownsHandle: true)
        : throw NativeFailure("Could not open the exact local transfer path.");

    private static int Descriptor(SafeFileHandle handle) => handle.DangerousGetHandle().ToInt32();

    private static IOException NativeFailure(string reason) =>
        new(reason, new Win32Exception(Marshal.GetLastPInvokeError()));

    [SupportedOSPlatform("windows")]
    private static unsafe SafeFileHandle OpenWindowsEntry(SafeFileHandle parent, string leaf, bool stage)
    {
        byte[] descriptor = [];
        if (stage)
        {
            using var user = WindowsIdentity.GetCurrent();
            var owner = user.User ?? throw new IOException("The current Windows owner is unavailable.");
            var security = new FileSecurity();
            security.SetOwner(owner);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
            descriptor = security.GetSecurityDescriptorBinaryForm();
        }

        fixed (char* buffer = leaf)
        fixed (byte* security = descriptor)
        {
            var length = checked((ushort)(leaf.Length * 2));
            var name = new NtName { Length = length, Maximum = length, Buffer = (nint)buffer };
            var attributes = new NtAttributes
            {
                Length = sizeof(NtAttributes), Root = parent.DangerousGetHandle(), Name = (nint)(&name), Flags = 0x40 | 0x1000,
                Security = (nint)security,
            };
            int status = NtCreateFile(out var raw, stage ? 0xc0110000u : 0x80100000u, in attributes,
                out _, 0, 0x80, stage ? 0u : 1u, stage ? 2u : 1u,
                0x40 | 0x20 | 0x200000 | (stage ? 0x02u : 0), 0, 0);
            if (status < 0)
            {
                throw WindowsFailure("Could not open the exact local transfer file.", status);
            }

            return new SafeFileHandle(raw, ownsHandle: true);
        }
    }

    [SupportedOSPlatform("windows")]
    private static unsafe void RenameWindows(SafeFileHandle stage, SafeFileHandle parent, string name)
    {
        var spelling = Encoding.Unicode.GetBytes(name);
        var record = new byte[20 + spelling.Length];
        spelling.CopyTo(record, 20);
        fixed (byte* buffer = record)
        {
            *(nint*)(buffer + 8) = parent.DangerousGetHandle();
            *(int*)(buffer + 16) = spelling.Length;
            int status = NtSetInformationFile(stage, out _, buffer, (uint)record.Length, 10);
            if (status < 0)
            {
                throw WindowsFailure("Could not publish the local destination without replacement.", status);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static unsafe void DeleteWindows(SafeFileHandle stage)
    {
        byte delete = 1;
        int status = NtSetInformationFile(stage, out _, &delete, 1, 13);
        if (status < 0)
        {
            throw WindowsFailure(FormattableString.Invariant($"Could not remove the private Windows export stage (NTSTATUS 0x{status:X8})."),
                status);
        }
    }

    private static IOException WindowsFailure(string reason, int status) => new(reason, new Win32Exception(RtlNtStatusToDosError(status)));

    private readonly record struct FileVersion(long Length, long Modified, uint ModifiedNanos, long Changed, uint ChangedNanos);
    private readonly record struct FileIdentity(ulong Volume, ulong Number);

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxOpen
    {
        internal ulong Flags;
        internal ulong Mode;
        internal ulong Resolve;
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxStat
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(40)] internal ulong Length;
        [FieldOffset(96)] internal long Changed;
        [FieldOffset(104)] internal uint ChangedNanos;
        [FieldOffset(112)] internal long Modified;
        [FieldOffset(120)] internal uint ModifiedNanos;
        [FieldOffset(144)] internal ulong Mount;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct WinInfo
    {
        internal uint Attributes;
        internal long Created;
        internal long Accessed;
        internal long Modified;
        internal uint Volume;
        internal uint LengthHigh;
        internal uint LengthLow;
        internal uint Links;
        internal uint IdHigh;
        internal uint IdLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NtName
    {
        internal ushort Length;
        internal ushort Maximum;
        internal nint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NtAttributes
    {
        internal int Length;
        internal nint Root;
        internal nint Name;
        internal uint Flags;
        internal nint Security;
        internal nint Quality;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NtIo
    {
        internal nint Status;
        internal nint Information;
    }

    [LibraryImport("libc", EntryPoint = "syscall", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial long OpenAt2(long call, int directory, string path, in LinuxOpen how, nuint size);

    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenAt(int directory, string path, int flags, uint mode);

    [LibraryImport("libc", EntryPoint = "fcntl", SetLastError = true)]
    private static partial int FileControl(int descriptor, int command, int value);

    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Statx(int file, string path, int flags, uint mask, out LinuxStat metadata);

    [LibraryImport("libc", EntryPoint = "linkat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int LinkAt(int source, string path, int target, string name, int flags);

    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static partial int Sync(int target);

    [LibraryImport("kernel32", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFile(string path, uint access, uint share, nint security, uint creation, uint flags, nint template);

    [LibraryImport("kernel32", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
    private static unsafe partial uint GetFinalPath(SafeFileHandle file, char* path, uint count, uint flags);

    [LibraryImport("kernel32", EntryPoint = "GetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetInfo(SafeFileHandle file, out WinInfo information);

    [LibraryImport("kernel32")]
    private static partial uint GetFileType(SafeFileHandle file);

    [LibraryImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FlushFileBuffers(SafeFileHandle file);

    [LibraryImport("ntdll")]
    private static partial int RtlNtStatusToDosError(int status);

    [LibraryImport("ntdll")]
    private static partial int NtCreateFile(out nint file, uint access, in NtAttributes attributes, out NtIo iostatus,
        nint size, uint fileAttributes, uint share, uint disposition, uint options, nint extraAttributes, uint extraLength);

    [LibraryImport("ntdll")]
    private static unsafe partial int NtSetInformationFile(SafeFileHandle file, out NtIo iostatus, byte* information, uint length, uint informationClass);
}
