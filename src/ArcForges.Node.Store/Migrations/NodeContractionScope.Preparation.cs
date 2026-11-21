// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace ArcForges.Node.Store.Migrations;

internal sealed partial class NodeContractionScope
{
    internal static string CurrentPreparationOwner()
    {
        if (OperatingSystem.IsWindows())
        {
            using var identity = WindowsIdentity.GetCurrent();
            return "windows:" + (identity.User?.Value ?? throw Refused("windows_owner_unavailable"));
        }

        if (OperatingSystem.IsLinux())
            return "linux:" + GetEffectiveUid().ToString(CultureInfo.InvariantCulture);

        throw Refused("native_owner_unavailable");
    }

    internal void ValidatePreparationRoot(string path)
    {
        if (!_prepareSchema15)
            throw Refused("original_schema15_required");

        _ = RequirePreparationParent(path);
        if (TryAttributes(path) is not null)
            throw Refused("preparation_output_already_exists");
    }

    internal void CopySchema15To(string expandedRoot)
    {
        ValidatePreparationRoot(expandedRoot);
        CreateNewPreparationRoot(expandedRoot);
        string database = StorePaths.Database(expandedRoot);
        StorePaths.CreatePrivateDirectory(Path.GetDirectoryName(database)!);

        using (var copy = DurableEpochFence.OpenPrivate(database, FileMode.CreateNew))
        {
            _database.Position = 0;
            _database.CopyTo(copy);
            copy.Flush(flushToDisk: true);
            copy.Position = 0;
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(copy), _databaseDigest))
                throw Refused("preparation_copy_does_not_match_source");
        }

        if (OperatingSystem.IsLinux())
        {
            using var instance = DurableEpochFence.OpenPrivate(Path.Combine(expandedRoot, "node.lock"), FileMode.CreateNew);
        }

        VerifyHeld();
    }

    internal static void CreateNewPreparationRoot(string path)
    {
        _ = RequirePreparationParent(path);
        bool created = OperatingSystem.IsWindows() ? CreateWindowsDirectory(path)
            : OperatingSystem.IsLinux() && Mkdir(path, 0x1c0) == 0; // 0700
        if (!created)
            throw Refused("preparation_output_create_failed");

        ContractionPaths.RequireDirectoryChain(path);
    }

    private static string RequirePreparationParent(string path)
    {
        if (!Path.IsPathFullyQualified(path) ||
            (OperatingSystem.IsWindows() && new DriveInfo(Path.GetPathRoot(path)!).DriveType != DriveType.Fixed))
            throw Refused("local_absolute_preparation_output_required");

        string parent = Path.GetDirectoryName(path) ?? throw Refused("preparation_parent_required");
        ContractionPaths.RequireDirectoryChain(parent);
        return parent;
    }

    [SupportedOSPlatform("windows")]
    private static unsafe bool CreateWindowsDirectory(string path)
    {
        using var identity = WindowsIdentity.GetCurrent();
        string sid = identity.User?.Value ?? throw Refused("windows_owner_unavailable");
        var security = new RawSecurityDescriptor($"O:{sid}D:P(A;OICI;FA;;;{sid})");
        var bytes = new byte[security.BinaryLength];
        security.GetBinaryForm(bytes, 0);
        fixed (byte* descriptor = bytes)
        {
            var attributes = new DirectorySecurityAttributes
            {
                Length = checked((uint)sizeof(DirectorySecurityAttributes)),
                SecurityDescriptor = (IntPtr)descriptor,
            };
            return CreateDirectory(path, in attributes);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DirectorySecurityAttributes
    {
        internal uint Length;
        internal IntPtr SecurityDescriptor;
        internal int InheritHandle;
    }

    [LibraryImport("libc", EntryPoint = "mkdir", StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Mkdir(string path, uint mode);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateDirectoryW", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateDirectory(string path, in DirectorySecurityAttributes attributes);

}
