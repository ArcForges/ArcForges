// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ArcForges.LocalRpc;

/// <summary>
/// Owner-only directories for private launch endpoints. A directory is created with its owner-only access in the same
/// operation (never created open and tightened afterwards), a launch directory becomes visible only by one rename after
/// its record is written, and it disappears by one rename before it is deleted. A record never holds a secret.
/// </summary>
internal static class LaunchDirectory
{
    private const UnixFileMode OwnerOnlyMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode GroupAndOther = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
    private const string RecordName = "launch.rec";
    private const string NewPrefix = ".n-";
    private const string DeletedPrefix = ".d-";
    private static readonly byte[] RecordMagic = "AFLR"u8.ToArray();

    /// <summary>Creates the runtime root owner-only, or verifies an existing one. Its parent must already exist.</summary>
    internal static string EnsureRoot(string root)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (!Path.IsPathFullyQualified(root) || root.StartsWith(@"\\", StringComparison.Ordinal)
            || !string.Equals(Path.GetFullPath(root), root.TrimEnd(Path.DirectorySeparatorChar), StringComparison.Ordinal))
        {
            throw new ArgumentException("The runtime root is a canonical, local, fully qualified path.", nameof(root));
        }

        root = root.TrimEnd(Path.DirectorySeparatorChar);
        var parent = Path.GetDirectoryName(root);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException("The parent of the runtime root must already exist.");
        }

        if (!Directory.Exists(root))
        {
            try
            {
                CreateOwnerOnly(root);
            }
            catch (IOException) when (Directory.Exists(root))
            {
                // Another process created it first; it is verified below like any existing root.
            }
        }

        RequireOwnerOnly(root);
        return root;
    }

    /// <summary>Creates one owner-only directory; it fails if the path exists.</summary>
    internal static void CreateOwnerOnly(string path)
    {
        if (Directory.Exists(path) || File.Exists(path))
        {
            throw new IOException("The directory already exists.");
        }

        if (OperatingSystem.IsWindows())
        {
            CreateOwnerOnlyWindows(path);
        }
        else
        {
            _ = Directory.CreateDirectory(path, OwnerOnlyMode);
        }
    }

    /// <summary>Refuses a directory that is a link or that any principal other than the owner can use.</summary>
    internal static void RequireOwnerOnly(string path)
    {
        var info = new DirectoryInfo(path);
        if (!info.Exists)
        {
            throw new DirectoryNotFoundException("The directory does not exist.");
        }

        if (info.LinkTarget is not null || (info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException("A launch directory is never a link or reparse point.");
        }

        if (OperatingSystem.IsWindows())
        {
            RequireOwnerOnlyWindows(path);
        }
        else if ((File.GetUnixFileMode(path) & GroupAndOther) != 0)
        {
            throw new UnauthorizedAccessException("A launch directory must be accessible by its owner only.");
        }
    }

    /// <summary>
    /// Creates a private launch directory under the root holding the record of the launch, and returns its final path.
    /// The directory is built under a temporary name and renamed into place, so it never exists without its record.
    /// </summary>
    internal static string Publish(string root, Guid launchId, LocalRpcProcessIdentity parent, ulong epoch, string? address)
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var temporary = Path.Combine(root, NewPrefix + Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8)));
            var final = Path.Combine(root, Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(6)));
            CreateOwnerOnly(temporary);
            try
            {
                WriteRecord(Path.Combine(temporary, RecordName), launchId, parent, epoch, address ?? string.Empty);
                Directory.Move(temporary, final);
                return final;
            }
            catch (IOException) when (Directory.Exists(final))
            {
                DeleteQuietly(temporary);
            }
            catch
            {
                DeleteQuietly(temporary);
                throw;
            }
        }

        throw new IOException("Could not allocate a private launch directory.");
    }

    /// <summary>Makes the launch directory vanish with one rename, then deletes it. Best effort; idempotent.</summary>
    internal static void Remove(string directory)
    {
        var root = Path.GetDirectoryName(directory);
        if (root is null || !Directory.Exists(directory))
        {
            return;
        }

        var doomed = Path.Combine(root, DeletedPrefix + Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8)));
        try
        {
            Directory.Move(directory, doomed);
            DeleteQuietly(doomed);
        }
        catch (IOException)
        {
            DeleteQuietly(directory);
        }
        catch (UnauthorizedAccessException)
        {
            DeleteQuietly(directory);
        }
    }

    /// <summary>
    /// Removes launch directories whose issuing parent is gone and leftovers of interrupted creates and removals. A directory of a
    /// running or unverifiable parent is never touched, nor is a link or anything this module did not create.
    /// </summary>
    internal static int SweepStale(string root, Func<LocalRpcProcessIdentity, ProcessLiveness> probe, TimeProvider clock, TimeSpan grace)
    {
        var removed = 0;
        foreach (var entry in Directory.EnumerateDirectories(root))
        {
            var name = Path.GetFileName(entry);
            var info = new DirectoryInfo(entry);
            if (info.LinkTarget is not null || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                continue;
            }

            if (name.StartsWith(DeletedPrefix, StringComparison.Ordinal))
            {
                DeleteQuietly(entry);
                removed += Directory.Exists(entry) ? 0 : 1;
                continue;
            }

            var isNew = name.StartsWith(NewPrefix, StringComparison.Ordinal);
            if (!isNew && !IsLaunchDirectoryName(name))
            {
                continue;
            }

            var parent = ReadRecord(Path.Combine(entry, RecordName));
            var old = clock.GetUtcNow() - new DateTimeOffset(info.CreationTimeUtc, TimeSpan.Zero) > grace;
            var stale = parent is { } identity ? probe(identity) == ProcessLiveness.Dead : old;
            if (stale)
            {
                Remove(entry);
                removed += Directory.Exists(entry) ? 0 : 1;
            }
        }

        return removed;
    }

    private static bool IsLaunchDirectoryName(string name) =>
        name.Length == 12 && name.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static void WriteRecord(string path, Guid launchId, LocalRpcProcessIdentity parent, ulong epoch, string address)
    {
        var text = System.Text.Encoding.UTF8.GetBytes(address);
        var bytes = new byte[RecordMagic.Length + 2 + 16 + 4 + 8 + 8 + 2 + text.Length];
        var span = bytes.AsSpan();
        RecordMagic.CopyTo(span);
        BinaryPrimitives.WriteUInt16BigEndian(span[4..], 1);
        launchId.TryWriteBytes(span[6..], bigEndian: true, out _);
        BinaryPrimitives.WriteInt32BigEndian(span[22..], parent.ProcessId);
        BinaryPrimitives.WriteInt64BigEndian(span[26..], parent.StartTimeUtcTicks);
        BinaryPrimitives.WriteUInt64BigEndian(span[34..], epoch);
        BinaryPrimitives.WriteUInt16BigEndian(span[42..], checked((ushort)text.Length));
        text.CopyTo(span[44..]);
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        using var stream = new FileStream(path, options);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    /// <summary>The issuing parent named by a record, or null when the record is missing, short, foreign or malformed.</summary>
    internal static LocalRpcProcessIdentity? ReadRecord(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length < 44 || !bytes.AsSpan(0, 4).SequenceEqual(RecordMagic)
                || BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(4)) != 1
                || bytes.Length != 44 + BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(42)))
            {
                return null;
            }

            var processId = BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(22));
            return processId > 0 ? new LocalRpcProcessIdentity(processId, BinaryPrimitives.ReadInt64BigEndian(bytes.AsSpan(26))) : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    internal static string RecordPath(string directory) => Path.Combine(directory, RecordName);

    private static void DeleteQuietly(string path)
    {
        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Best effort: a later sweep removes what remains of a directory this module created.
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CreateOwnerOnlyWindows(string path)
    {
        var user = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("The current user has no SID.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            user,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(path).Create(security);
    }

    [SupportedOSPlatform("windows")]
    private static void RequireOwnerOnlyWindows(string path)
    {
        var user = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("The current user has no SID.");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier));
        if (owner is null || (!owner.Equals(user) && !owner.Equals(administrators)))
        {
            throw new UnauthorizedAccessException("A launch directory must be owned by the current user.");
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow
                && !rule.IdentityReference.Equals(user) && !rule.IdentityReference.Equals(system) && !rule.IdentityReference.Equals(administrators))
            {
                throw new UnauthorizedAccessException("A launch directory must be accessible by its owner only.");
            }
        }
    }
}
