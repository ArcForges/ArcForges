// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Text;

namespace ArcForges.Client;

/// <summary>Selects a complete immutable installation. Windows uses a small atomic pointer and Linux uses the service's existing symlink.</summary>
public static partial class NodeVersionSelection
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private const string WindowsParkedPrefix = ".parked-";

    public static string? Read(string appRoot)
    {
        var identity = ReadIdentity(appRoot);
        if (identity is not null)
        {
            _ = RequireInstalled(appRoot, identity);
        }

        return identity;
    }

    /// <summary>Reads the validated pointer while an offline updater checks physical installation custody separately.</summary>
    public static string? ReadIdentity(string appRoot)
    {
        var path = PointerPath(appRoot);
        var attributes = Attributes(path);
        if (attributes is null)
        {
            return null;
        }

        string identity;
        if (OperatingSystem.IsWindows())
        {
            if ((attributes.Value & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            {
                throw new IOException("node_update_selection_not_regular");
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            Span<byte> value = stackalloc byte[65];
            if (stream.Length != value.Length)
            {
                throw new IOException("node_update_selection_invalid");
            }

            stream.ReadExactly(value);
            if (value[^1] != (byte)'\n')
            {
                throw new IOException("node_update_selection_invalid");
            }

            identity = StrictUtf8.GetString(value[..^1]);
        }
        else
        {
            var target = new FileInfo(path).LinkTarget;
            if (target is null || !target.StartsWith("versions/", StringComparison.Ordinal))
            {
                throw new IOException("node_update_selector_requires_verified_versions_layout");
            }

            identity = target["versions/".Length..];
        }

        _ = InstallationDirectory(appRoot, identity);
        return identity;
    }

    public static string InstallationDirectory(string appRoot, string archiveSha256)
    {
        if (archiveSha256.Length != 64 || archiveSha256.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            throw new ArgumentException("Use a full lowercase archive SHA-256.", nameof(archiveSha256));
        }

        if (!Path.IsPathFullyQualified(appRoot))
        {
            throw new ArgumentException("Use an absolute application directory.", nameof(appRoot));
        }

        return Path.Combine(appRoot, "versions", archiveSha256);
    }

    public static string? SelectedInstallation(string appRoot) => Read(appRoot) is { } selected ? RequireInstalled(appRoot, selected) : null;

    public static void PrepareDirectories(string appRoot)
    {
        RequireDirectory(Path.GetDirectoryName(appRoot)!, create: true);
        RequireDirectory(appRoot, create: true);
        RequireDirectory(Path.Combine(appRoot, "versions"), create: true);
    }

    // The update gate serializes writers. An exact previous selection still detects manual or interrupted changes.
    public static void Select(string appRoot, string? expected, string archiveSha256, bool allowMissingExpected = false)
    {
        _ = RequireInstalled(appRoot, archiveSha256);
        var current = ReadIdentity(appRoot);
        if (current != expected)
        {
            throw new IOException("node_update_selection_changed");
        }

        if (expected is not null)
        {
            var previous = InstallationDirectory(appRoot, expected);
            if (allowMissingExpected && OperatingSystem.IsWindows() && Attributes(previous) is null)
            {
                RequireDirectory(WindowsParkedDirectory(previous), create: false);
            }
            else
            {
                _ = RequireInstalled(appRoot, expected);
            }
        }

        var temporary = Path.Combine(appRoot, ".current-" + Guid.NewGuid().ToString("N"));
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
                stream.Write(StrictUtf8.GetBytes(archiveSha256 + "\n"));
                stream.Flush(flushToDisk: true);
            }
            else
            {
                File.CreateSymbolicLink(temporary, "versions/" + archiveSha256);
            }

            PublishSelection(appRoot, temporary, PointerPath(appRoot), replace: expected is not null);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    internal static string WindowsParkedDirectory(string canonical) =>
        Path.Combine(Path.GetDirectoryName(canonical)!, WindowsParkedPrefix + Path.GetFileName(canonical));

    private static void PublishSelection(string appRoot, string temporary, string destination, bool replace)
    {
        if (OperatingSystem.IsWindows())
        {
            const uint WriteThrough = 8;
            const uint ReplaceExisting = 1;
            if (!MoveFileEx(temporary, destination, WriteThrough | (replace ? ReplaceExisting : 0)))
            {
                throw new IOException("node_update_selection_publish_failed:" + Marshal.GetLastPInvokeError());
            }

            return;
        }

        const int DirectoryNoFollowCloseOnExec = 0x10000 | 0x20000 | 0x80000;
        int directory = OpenDirectory(appRoot, DirectoryNoFollowCloseOnExec);
        if (directory < 0)
        {
            throw new IOException("node_update_selection_directory_unavailable:" + Marshal.GetLastPInvokeError());
        }

        try
        {
            File.Move(temporary, destination, overwrite: replace);
            if (SyncDirectory(directory) != 0)
            {
                throw new IOException("node_update_selection_sync_failed:" + Marshal.GetLastPInvokeError());
            }
        }
        finally
        {
            _ = CloseDirectory(directory);
        }
    }

    private static string RequireInstalled(string appRoot, string identity)
    {
        RequireDirectory(appRoot, create: false);
        RequireDirectory(Path.Combine(appRoot, "versions"), create: false);
        var root = InstallationDirectory(appRoot, identity);
        RequireDirectory(root, create: false);
        return root;
    }

    internal static void RequireDirectory(string path, bool create)
    {
        if (create && Attributes(path) is null)
        {
            if (OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(path);
            }
            else
            {
                Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }

        if (Attributes(path) is not FileAttributes attributes || (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory
            || !OperatingSystem.IsWindows() && (File.GetUnixFileMode(path) & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
        {
            throw new IOException("node_update_installation_directory_untrusted");
        }
    }

    private static string PointerPath(string appRoot) => Path.Combine(appRoot, OperatingSystem.IsWindows() ? "current.version" : "current");

    internal static FileAttributes? Attributes(string path)
    {
        try
        {
            return File.GetAttributes(path);
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "MoveFileExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool MoveFileEx(string existingName, string newName, uint flags);

    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenDirectory(string path, int flags);

    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static partial int SyncDirectory(int descriptor);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    private static partial int CloseDirectory(int descriptor);
}
