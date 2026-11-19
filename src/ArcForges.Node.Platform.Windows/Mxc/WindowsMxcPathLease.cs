// SPDX-License-Identifier: AGPL-3.0-only

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Platform.Windows.Mxc;

/// <summary>Holds a protected native path without sharing replacement or following reparse points.</summary>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsMxcPathLease : IDisposable
{
    private const uint ReadControl = 0x00020000;
    private const uint DeleteAccess = 0x00010000;
    private const uint ReadDataOrListDirectory = 0x00000001;
    private const uint ReadAttributes = 0x00000080;
    private const uint GenericRead = 0x80000000;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private const uint DirectoryAttribute = 0x10;
    private const uint ReparseAttribute = 0x400;
    private readonly List<SafeFileHandle> _chain = [];
    private PrivateFileIdentity? _privateFile;
    private string? _grantIdentity;
    private bool _protectedSystemExecutable;

    private WindowsMxcPathLease(string path) => Path = path;

    /// <summary>The absolute, no-reparse name held by this lease.</summary>
    public string Path { get; }

    /// <summary>Opens the full protected path and holds its ancestors through native consumption.</summary>
    public static WindowsMxcPathLease Open(string path, bool directory, bool privateObject = false)
    {
        if (!System.IO.Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException("The MXC path must be fully qualified.", nameof(path));
        }

        var full = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(path));
        var parents = new Stack<string>();
        for (var parent = Directory.GetParent(full); parent is not null; parent = parent.Parent)
        {
            parents.Push(parent.FullName);
        }

        using var current = WindowsIdentity.GetCurrent();
        var sid = current.User ?? throw new IOException("The Windows MXC service principal is unavailable.");
        var lease = new WindowsMxcPathLease(full);
        try
        {
            foreach (var parent in parents)
            {
                lease.OpenOne(parent, directory: true, sid, ancestor: true, privateObject: false);
            }

            lease.OpenOne(full, directory, sid, ancestor: false, privateObject);
            return lease;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    /// <summary>Holds an admitted grant's exact object and its no-reparse ancestry without blocking data writes.</summary>
    public static WindowsMxcPathLease OpenGrant(string path, string? binding) => OpenBoundPath(path, binding, protectedSystemExecutable: false);

    /// <summary>Holds the resolved executable, permitting Windows servicing links only in the protected system directory.</summary>
    public static WindowsMxcPathLease OpenExecutable(string path, string? binding)
    {
        var systemRoot = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(Environment.SystemDirectory));
        var systemImage = path.StartsWith(systemRoot + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        return OpenBoundPath(path, binding, systemImage);
    }

    private static WindowsMxcPathLease OpenBoundPath(string path, string? binding, bool protectedSystemExecutable)
    {
        if (binding is null || binding.Length != 68 || !binding.StartsWith("1:", StringComparison.Ordinal)
            || !System.IO.Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException("The Windows MXC grant has no bound native object.");
        }

        var canonical = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(path));
        if (!canonical.Equals(path, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The bound Windows MXC grant path is not canonical.");
        }

        var lease = new WindowsMxcPathLease(canonical) { _grantIdentity = binding, _protectedSystemExecutable = protectedSystemExecutable };
        var names = new Stack<string>();
        names.Push(canonical);
        for (var parent = Directory.GetParent(canonical); parent is not null; parent = parent.Parent)
        {
            names.Push(parent.FullName);
        }

        try
        {
            while (names.TryPop(out var name))
            {
                // Deny rename/delete while retaining regular data writes to an explicitly writable grant.
                var access = ReadAttributes | ReadDataOrListDirectory | (protectedSystemExecutable ? ReadControl : 0);
                var share = protectedSystemExecutable && names.Count == 0 ? FileShare.Read : FileShare.ReadWrite;
                var handle = CreateFile(name, access, share, 0,
                    FileMode.Open, OpenReparsePoint | BackupSemantics, 0);
                if (handle.IsInvalid)
                {
                    var error = WindowsMxcJob.Error("Hold a Windows MXC grant path component");
                    handle.Dispose();
                    throw error;
                }

                lease._chain.Add(handle);
                if (names.Count != 0) RequirePlainAncestor(handle);
            }

            lease.RequireStableGrant();
            return lease;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    /// <summary>Checks the actual held grant again before submitting it to the fixed official executor.</summary>
    public unsafe void RequireStableGrant()
    {
        if (_grantIdentity is null || _chain.Count == 0)
        {
            throw new InvalidOperationException("No Windows MXC grant is held.");
        }

        foreach (var ancestor in _chain.Take(_chain.Count - 1))
        {
            RequirePlainAncestor(ancestor);
        }

        var file = _chain[^1];
        var actual = FileMetadata(file);
        var directory = (actual.Attributes & DirectoryAttribute) != 0;
        if (actual.LinkCount == 0 || (!directory && actual.LinkCount != 1 && !_protectedSystemExecutable)
            || (_protectedSystemExecutable && directory)
            || (actual.Attributes & ReparseAttribute) != 0 || GetFileType(file) != 1)
        {
            throw new InvalidDataException("The Windows MXC grant type or link count changed.");
        }

        if (_protectedSystemExecutable)
        {
            using var current = WindowsIdentity.GetCurrent();
            var principal = current.User ?? throw new IOException("The Windows MXC service principal is unavailable.");
            foreach (var ancestor in _chain.Take(_chain.Count - 1))
            {
                RequireAcl(ancestor, principal, ancestor: true, privateObject: false);
            }

            RequireAcl(file, principal, ancestor: false, privateObject: false);
        }

        if (!GetFileId(file, 18, out var id, (uint)sizeof(FileId)))
        {
            throw WindowsMxcJob.Error("Read the bound Windows MXC FileIdInfo");
        }

        Span<byte> bytes = stackalloc byte[33];
        bytes[0] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(bytes[1..9], id.Volume);
        BinaryPrimitives.WriteUInt64BigEndian(bytes[9..17], id.Low);
        BinaryPrimitives.WriteUInt64BigEndian(bytes[17..25], id.High);
        BinaryPrimitives.WriteUInt64BigEndian(bytes[25..33], actual.Created);
        if (_grantIdentity != "1:" + Convert.ToHexStringLower(bytes))
        {
            throw new InvalidDataException("The Windows MXC grant object differs from the admitted identity.");
        }

        var buffer = new char[32_768];
        fixed (char* target = buffer)
        {
            var count = GetFinalPathNameByHandle(file, target, (uint)buffer.Length, 0);
            if (count == 0 || count >= buffer.Length)
            {
                throw WindowsMxcJob.Error("Resolve the canonical Windows MXC grant name from its handle");
            }

            ReadOnlySpan<char> observed = buffer.AsSpan(0, (int)count);
            if (!observed.StartsWith(@"\\?\", StringComparison.Ordinal) || !observed[4..].Equals(Path, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("The canonical Windows MXC grant name differs from its bound name.");
            }
        }
    }

    /// <summary>Returns the observed protected file hash within the given byte limit.</summary>
    public string Hash(long maxBytes)
    {
        var file = _chain[^1];
        var length = RandomAccess.GetLength(file);
        if (length <= 0 || length > maxBytes)
        {
            throw new InvalidDataException("A protected MXC file exceeds its byte bound.");
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        for (var offset = 0L; offset < length;)
        {
            var read = RandomAccess.Read(file, buffer.AsSpan(0, (int)Math.Min(buffer.Length, length - offset)), offset);
            if (read == 0) throw new IOException("The protected MXC file changed while reading.");
            hash.AppendData(buffer, 0, read);
            offset += read;
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    /// <summary>Reads exact bytes from a bounded held control artifact.</summary>
    public byte[] Read(int maxBytes)
    {
        var file = _chain[^1];
        var length = RandomAccess.GetLength(file);
        if (length <= 0 || length > maxBytes)
        {
            throw new InvalidDataException("A protected MXC control artifact exceeds its byte bound.");
        }

        var bytes = new byte[(int)length];
        for (var offset = 0; offset < bytes.Length;)
        {
            var read = RandomAccess.Read(file, bytes.AsSpan(offset), offset);
            if (read == 0) throw new IOException("The protected MXC control artifact changed while reading.");
            offset += read;
        }

        return bytes;
    }

    /// <summary>Marks only the originally held private file for deletion once native consumption has ended.</summary>
    public void DeletePrivateFile()
    {
        if (_privateFile is not { } expected)
        {
            throw new InvalidOperationException("No held private MXC file was authorized for removal.");
        }

        _chain[^1].Dispose(); // Release the previous no-delete share while continuing to hold its ancestry.
        _chain.RemoveAt(_chain.Count - 1);
        _privateFile = null;
        DeleteCreatedPrivateFile(Path, expected);
    }

    internal static PrivateFileIdentity CaptureCreatedPrivateFile(SafeFileHandle file)
    {
        var metadata = FileMetadata(file);
        if ((metadata.Attributes & (DirectoryAttribute | ReparseAttribute)) != 0 || metadata.LinkCount != 1
            || GetFileType(file) != 1)
        {
            throw new InvalidDataException("The newly written private MXC file is not a single ordinary file.");
        }

        return FileIdentity(file, metadata);
    }

    internal void RequirePrivateFileIdentity(PrivateFileIdentity expected)
    {
        if (_privateFile != expected)
        {
            throw new InvalidDataException("The held private MXC file differs from the file created for this Run.");
        }
    }

    internal static void DeleteCreatedPrivateFile(string path, PrivateFileIdentity expected)
    {
        using var candidate = CreateFile(path, DeleteAccess | ReadControl | ReadAttributes, FileShare.None,
            0, FileMode.Open, OpenReparsePoint, 0);
        if (candidate.IsInvalid)
        {
            var error = WindowsMxcJob.Error("Reopen the consumed private MXC file for removal");
            if (error.NativeErrorCode == Native.ErrorFileNotFound) return;
            throw error;
        }

        if (CaptureCreatedPrivateFile(candidate) != expected)
        {
            throw new InvalidDataException("The consumed private MXC file was replaced.");
        }

        using var current = WindowsIdentity.GetCurrent();
        RequireAcl(candidate, current.User ?? throw new IOException("The Windows MXC service principal is unavailable."),
            ancestor: false, privateObject: true);
        if (!SetFileInformationByHandle(candidate, 4, 1, 1))
        {
            throw WindowsMxcJob.Error("Delete the consumed private MXC file by its native identity");
        }
    }

    /// <summary>Releases all held path components.</summary>
    public void Dispose()
    {
        for (var index = _chain.Count - 1; index >= 0; index--)
        {
            _chain[index].Dispose();
        }

        _chain.Clear();
    }

    private void OpenOne(string path, bool directory, SecurityIdentifier principal, bool ancestor, bool privateObject)
    {
        var file = CreateFile(path, ReadControl | ReadAttributes | (directory ? ReadDataOrListDirectory : GenericRead),
            directory ? FileShare.ReadWrite : FileShare.Read, 0, FileMode.Open, OpenReparsePoint | (directory ? BackupSemantics : 0), 0);
        if (file.IsInvalid)
        {
            var error = WindowsMxcJob.Error("Open protected MXC path component");
            file.Dispose();
            throw error;
        }

        _chain.Add(file);
        var information = FileMetadata(file);
        var attributes = information.Attributes;
        if ((attributes & ReparseAttribute) != 0 || ((attributes & DirectoryAttribute) != 0) != directory
            || (!directory && information.LinkCount != 1))
        {
            throw new InvalidDataException("A protected MXC path has unexpected type, links or reparse data.");
        }

        RequireAcl(file, principal, ancestor, privateObject);
        if (privateObject && !directory) _privateFile = FileIdentity(file, information);
    }

    private static void RequireAcl(SafeFileHandle file, SecurityIdentifier principal, bool ancestor, bool privateObject)
    {
        var error = GetSecurityInfo(file, 1, 5, out _, out _, out _, out _, out var descriptor);
        try
        {
            if (error != 0 || descriptor == 0)
            {
                throw new System.ComponentModel.Win32Exception((int)error, "Read protected MXC access control failed.");
            }

            var length = GetSecurityDescriptorLength(descriptor);
            if (length is 0 or > 65_536)
            {
                throw new InvalidDataException("The MXC access-control descriptor is missing or oversized.");
            }

            var bytes = new byte[length];
            Marshal.Copy(descriptor, bytes, 0, (int)length);
            var security = new RawSecurityDescriptor(bytes, 0);
            var acl = security.DiscretionaryAcl;
            if (security.Owner is null || acl is null || (privateObject
                    ? security.Owner != principal || acl.Count == 0
                    : !TrustedInstallationSid(security.Owner, principal)))
            {
                throw new UnauthorizedAccessException("The MXC path owner or DACL differs from the required trust boundary.");
            }

            const int genericWriteOrAll = 0x50000000;
            const int modifySecurityOrDelete = 0x000d0040;
            const int modifyContentOrAttributes = 0x00000116;
            var dangerous = genericWriteOrAll | modifySecurityOrDelete | (ancestor ? 0 : modifyContentOrAttributes);
            foreach (GenericAce ace in acl)
            {
                if (privateObject)
                {
                    if (ace is not CommonAce { AceQualifier: AceQualifier.AccessAllowed, IsCallback: false } owned
                        || owned.SecurityIdentifier != principal)
                    {
                        throw new UnauthorizedAccessException("The MXC private artifact permits an unexpected principal.");
                    }
                }
                else if ((ace.AceFlags & AceFlags.InheritOnly) == 0
                    && (ace.AceType == AceType.AccessAllowedCompound
                        || ace is QualifiedAce { AceQualifier: AceQualifier.AccessAllowed } allowed
                        && (allowed.AccessMask & dangerous) != 0
                        && (allowed is not CommonAce { IsCallback: false } || !TrustedInstallationSid(allowed.SecurityIdentifier, principal))))
                {
                    throw new UnauthorizedAccessException("The MXC installation permits untrusted modification.");
                }
            }
        }
        finally
        {
            if (descriptor != 0) _ = LocalFree(descriptor);
        }
    }

    private static bool TrustedInstallationSid(SecurityIdentifier sid, SecurityIdentifier principal) =>
        sid == principal || sid.IsWellKnown(WellKnownSidType.LocalSystemSid)
        || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
        || sid.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; // TrustedInstaller

    private static FileInformation FileMetadata(SafeFileHandle file) =>
        GetFileInformationByHandle(file, out var metadata) ? metadata : throw WindowsMxcJob.Error("Read a held Windows MXC file identity");

    private static unsafe PrivateFileIdentity FileIdentity(SafeFileHandle file, FileInformation metadata)
    {
        if (!GetFileId(file, 18, out var id, (uint)sizeof(FileId)))
        {
            throw WindowsMxcJob.Error("Read a private Windows MXC FileIdInfo");
        }

        return new(id.Volume, id.Low, id.High, metadata.Created);
    }

    internal readonly record struct PrivateFileIdentity(ulong Volume, ulong Low, ulong High, ulong CreationFileTime);

    private static void RequirePlainAncestor(SafeFileHandle handle)
    {
        var metadata = FileMetadata(handle);
        if ((metadata.Attributes & (DirectoryAttribute | ReparseAttribute)) != DirectoryAttribute || GetFileType(handle) != 1)
        {
            throw new InvalidDataException("A Windows MXC grant ancestor is no longer a plain disk directory.");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileId
    {
        internal ulong Volume;
        internal ulong Low;
        internal ulong High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal uint Attributes;
        private readonly FILETIME _created;
        private readonly FILETIME _accessed;
        private readonly FILETIME _modified;
        private readonly uint _volume;
        private readonly uint _lengthHigh;
        private readonly uint _lengthLow;
        internal uint LinkCount;
        private readonly uint _indexHigh;
        private readonly uint _indexLow;

        internal readonly ulong Created => _created.Ticks;

    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        private readonly uint _low;
        private readonly uint _high;

        internal readonly ulong Ticks => ((ulong)_high << 32) | _low;

    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFile(string path, uint access, FileShare share, nint security,
        FileMode mode, uint attributes, nint template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileId(SafeFileHandle file, int type, out FileId value, uint length);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
    private static unsafe partial uint GetFinalPathNameByHandle(SafeFileHandle file, char* path, uint length, uint flags);

    [LibraryImport("kernel32.dll")]
    private static partial uint GetFileType(SafeFileHandle file);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(SafeFileHandle file, int type, in byte information, uint length);

    [LibraryImport("advapi32.dll")]
    private static partial uint GetSecurityInfo(SafeFileHandle file, int type, uint information,
        out nint owner, out nint group, out nint dacl, out nint sacl, out nint descriptor);

    [LibraryImport("advapi32.dll")]
    private static partial uint GetSecurityDescriptorLength(nint descriptor);

    [LibraryImport("kernel32.dll")]
    private static partial nint LocalFree(nint memory);
}
