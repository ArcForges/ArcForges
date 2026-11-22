// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Node.Core.Platform;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    private const int WindowsDeletePending = unchecked((int)0xc0000056);
    private const int WindowsObjectNameNotFound = unchecked((int)0xc0000034);
    private const int WindowsNoSuchFile = unchecked((int)0xc000000f);
    private const int WindowsNoMoreFiles = unchecked((int)0x80000006);

    internal static Dictionary<string, WorkspaceObjectIdentity> CaptureWindowsDeleteRundownDirectories(
        string path, CancellationToken token)
    {
        using var root = WorkspacePath.OpenRoot(path);
        var directories = new Dictionary<string, WorkspaceObjectIdentity>(StringComparer.Ordinal);
        foreach (var directory in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories))
        {
            token.ThrowIfCancellationRequested();
            var relative = Path.GetRelativePath(path, directory);
            directories.Add(relative, WorkspacePath.Identity(root.OpenDirectory(relative.Replace('\\', '/'))));
        }

        return directories;
    }

    private static string[] EnumerateWindowsDeleteRundownEntries(WorkspacePath root,
        IReadOnlyDictionary<string, WorkspaceObjectIdentity> originalDirectories, Action<string>? beforeDirectoryOpen,
        CancellationToken token)
    {
        var directories = new Stack<string>();
        var entries = new List<string>();
        directories.Push(string.Empty);
        while (directories.TryPop(out var relative))
        {
            token.ThrowIfCancellationRequested();
            beforeDirectoryOpen?.Invoke(relative);
            FileSystemInfo[] children;
            try
            {
                children = new DirectoryInfo(Path.Combine(root.RootPath, relative))
                    .EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly).ToArray();
            }
            catch (Exception failure) when (failure is UnauthorizedAccessException or DirectoryNotFoundException)
            {
                // Confirm the failure against NT's observation of this named child under its checked parent.
                var required = failure is UnauthorizedAccessException ? WindowsDeletePending : WindowsObjectNameNotFound;
                if (ObserveOriginalWindowsDeleteRundown(root, relative, originalDirectories) != required)
                    throw;

                throw new WindowsDeleteRundownRetryException(relative, required, failure);
            }

            foreach (var child in children)
            {
                var name = Path.Combine(relative, child.Name);
                entries.Add(name);
                if (child is DirectoryInfo)
                {
                    Assert.True(originalDirectories.ContainsKey(name) && (child.Attributes & FileAttributes.ReparsePoint) == 0,
                        "Unexpected directory in the interrupted deletion fixture.");
                    directories.Push(name);
                }
            }
        }

        return entries.Order(StringComparer.Ordinal).ToArray();
    }

    internal static bool IsOriginalWindowsDeleteRundownPending(WorkspacePath root, string relative,
        IReadOnlyDictionary<string, WorkspaceObjectIdentity> originalDirectories) =>
        ObserveOriginalWindowsDeleteRundown(root, relative, originalDirectories) == WindowsDeletePending;

    private static unsafe int ObserveOriginalWindowsDeleteRundown(WorkspacePath root, string relative,
        IReadOnlyDictionary<string, WorkspaceObjectIdentity> originalDirectories)
    {
        if (!originalDirectories.TryGetValue(relative, out var expected))
            return 0;

        var parentPath = Path.GetDirectoryName(relative) ?? string.Empty;
        var name = Path.GetFileName(relative);
        using var parent = root.OpenDirectoryForEnumeration(parentPath.Replace('\\', '/'));
        var expectedParent = parentPath.Length == 0 ? root.RootIdentity : originalDirectories[parentPath];
        if (!expectedParent.SameObject(WorkspacePath.Identity(parent)) || expected.Volume != expectedParent.Volume)
            return 0;

        fixed (char* characters = name)
        {
            ushort length = checked((ushort)(name.Length * sizeof(char)));
            var nativeName = new WindowsDeleteRundownName(length, (nint)characters);
            bool retained = false;
            try
            {
                parent.DangerousAddRef(ref retained);
                var attributes = new WindowsDeleteRundownAttributes
                {
                    Length = (uint)sizeof(WindowsDeleteRundownAttributes),
                    RootDirectory = parent.DangerousGetHandle(),
                    ObjectName = (nint)(&nativeName),
                    Attributes = 0,
                    SecurityDescriptor = 0,
                    SecurityQualityOfService = 0,
                };
                const uint options = 0x00200021; // Open reparse point, synchronous nonalert, directory only.
                nint raw = 0;
                int status = OpenWindowsDeleteRundownChild(ref raw, 0x00100081, ref attributes, out _, 7, options);
                if (status >= 0 && raw != 0 && raw != -1)
                {
                    using var opened = new SafeFileHandle(raw, ownsHandle: true);
                }

                if (status is not (WindowsDeletePending or WindowsObjectNameNotFound))
                    return 0;

                var entry = ReadWindowsDeleteRundownEntry(parent, name, expected, &nativeName);
                if (entry == WindowsDeleteRundownEntry.Original && status == WindowsDeletePending ||
                    entry == WindowsDeleteRundownEntry.Absent && status == WindowsObjectNameNotFound)
                    return status;

                return 0;
            }
            finally
            {
                if (retained)
                    parent.DangerousRelease();
            }
        }
    }

    private static unsafe WindowsDeleteRundownEntry ReadWindowsDeleteRundownEntry(SafeFileHandle parent, string name,
        WorkspaceObjectIdentity expected, WindowsDeleteRundownName* nativeName)
    {
        // FILE_ID_EXTD_DIR_INFORMATION provides this child's native ID even when its name is delete-pending.
        const int nameOffset = 88;
        ulong* storage = stackalloc ulong[128];
        var bytes = (byte*)storage;
        int status = QueryWindowsDeleteRundownEntry(parent, 0, 0, 0, out var result, bytes, 1024,
            60, 1, nativeName, 1); // FileIdExtdDirectoryInformation, return one entry, restart scan.
        if (status is WindowsNoSuchFile or WindowsNoMoreFiles)
            return WindowsDeleteRundownEntry.Absent;

        if (status != 0 || unchecked((int)result.Status) != 0 || result.Information < nameOffset || result.Information > 1024)
            return WindowsDeleteRundownEntry.Unconfirmed;

        uint nameBytes = *(uint*)(bytes + 60);
        uint attributes = *(uint*)(bytes + 56);
        return nameBytes == name.Length * sizeof(char) && nameBytes <= result.Information - nameOffset
            && (attributes & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint)) == (uint)FileAttributes.Directory
            && *(ulong*)(bytes + 8) == expected.Created
            && *(ulong*)(bytes + 72) == expected.Low && *(ulong*)(bytes + 80) == expected.High
            && new ReadOnlySpan<char>(bytes + nameOffset, name.Length).SequenceEqual(name.AsSpan())
            ? WindowsDeleteRundownEntry.Original : WindowsDeleteRundownEntry.Unconfirmed;
    }

    private enum WindowsDeleteRundownEntry
    {
        Unconfirmed,
        Original,
        Absent,
    }

    private sealed class WindowsDeleteRundownRetryException(string relative, int status, Exception inner)
        : IOException(relative, inner)
    {
        internal string NativeReason => status == WindowsDeletePending
            ? "STATUS_DELETE_PENDING (0xc0000056)" : "STATUS_OBJECT_NAME_NOT_FOUND (0xc0000034)";
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct WindowsDeleteRundownName(ushort length, nint buffer)
    {
        internal readonly ushort Length = length;
        internal readonly ushort MaximumLength = length;
        internal readonly nint Buffer = buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsDeleteRundownAttributes
    {
        internal uint Length;
        internal nint RootDirectory;
        internal nint ObjectName;
        internal uint Attributes;
        internal nint SecurityDescriptor;
        internal nint SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsDeleteRundownStatus
    {
        internal nint Status;
        internal nuint Information;
    }

    [LibraryImport("ntdll.dll", EntryPoint = "NtQueryDirectoryFile")]
    private static unsafe partial int QueryWindowsDeleteRundownEntry(SafeFileHandle directory, nint signal, nint callback,
        nint callbackState, out WindowsDeleteRundownStatus result, void* information, uint length, int informationClass,
        byte returnSingleEntry, WindowsDeleteRundownName* name, byte restartScan);

    [LibraryImport("ntdll.dll", EntryPoint = "NtOpenFile")]
    private static partial int OpenWindowsDeleteRundownChild(ref nint handle, uint access,
        ref WindowsDeleteRundownAttributes attributes, out WindowsDeleteRundownStatus result, uint share, uint options);
}
