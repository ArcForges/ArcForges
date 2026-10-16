// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// Detects a data root kept in memory (Linux <c>tmpfs</c> or <c>ramfs</c>, by <c>statfs</c> <c>f_type</c>). Captured output and the
/// attempts' temporary files live under the data root; in memory their pages belong to the writing attempt's cgroup and cannot be
/// reclaimed without swap (<c>MemorySwapMax</c> defaults to 0), so a long output counts against the attempt's memory limits and the
/// machine's memory. The node reports it as a capability fact and a warning in its log; it does not refuse to start.
/// </summary>
public static unsafe partial class MemoryFileSystems
{
    private const long TmpfsMagic = 0x01021994;
    private const long RamfsMagic = unchecked((long)0x858458f6);

    /// <summary>The in-memory file system kind of <paramref name="path"/> (<c>tmpfs</c>, <c>ramfs</c>), or null (disk, or not Linux).</summary>
    public static string? KindOf(string path)
    {
        if (!OperatingSystem.IsLinux() || !Directory.Exists(path))
        {
            return null;
        }

        // struct statfs is 120 bytes on x86-64 and arm64; f_type is its first field (a long).
        var buffer = stackalloc byte[256];
        try
        {
            if (StatFs(path, buffer) != 0)
            {
                return null;
            }
        }
        catch (Exception exception) when (exception is EntryPointNotFoundException or DllNotFoundException)
        {
            return null;
        }

        return *(long*)buffer switch
        {
            TmpfsMagic => "tmpfs",
            RamfsMagic => "ramfs",
            _ => null,
        };
    }

    /// <summary>
    /// The data root and its output (<c>logs</c>) and temporary (<c>tmp</c>) sub-roots that are in memory (each can be its own mount),
    /// as (path, kind) pairs.
    /// </summary>
    public static List<(string Path, string Kind)> UnderDataRoot(string dataRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        var found = new List<(string Path, string Kind)>();
        foreach (var path in (string[])[dataRoot, Path.Combine(dataRoot, "logs"), Path.Combine(dataRoot, "tmp")])
        {
            if (KindOf(path) is { } kind)
            {
                found.Add((path, kind));
            }
        }

        return found;
    }

    [LibraryImport("libc", EntryPoint = "statfs", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int StatFs(string path, byte* buffer);
}
