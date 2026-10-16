// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// Drops indexed output from the Linux page cache (<c>posix_fadvise(POSIX_FADV_DONTNEED)</c>). On Linux the command writes its output
/// to the node-owned file, so the file's pages are charged to the attempt's cgroup; without this they accumulate up to the attempt's
/// <c>MemoryHigh</c> and the writer then reclaims in its own context, which bounds output capture by reclaim (15 section 1). The kernel
/// drops only clean pages and starts the write-back of dirty ones, so a range is advised twice: once when indexed and once on the next
/// read, by when it is clean. Readers that need the bytes later read them from the disk. Does nothing elsewhere.
/// </summary>
internal static partial class PageCache
{
    private const int DontNeed = 4;

    /// <summary>Advises the kernel that <c>[offset, offset + length)</c> of the file is not needed; errors are ignored (advice only).</summary>
    public static void Drop(SafeFileHandle handle, long offset, long length)
    {
        if (!OperatingSystem.IsLinux() || length <= 0 || handle.IsInvalid || handle.IsClosed)
        {
            return;
        }

        var added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            _ = FAdvise((int)handle.DangerousGetHandle(), offset, length, DontNeed);
        }
        catch (Exception exception) when (exception is ObjectDisposedException or EntryPointNotFoundException or DllNotFoundException)
        {
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    [LibraryImport("libc", EntryPoint = "posix_fadvise")]
    private static partial int FAdvise(int fileDescriptor, long offset, long length, int advice);
}
