// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// Compares the kernel's opened executable identities of two live processes, without inspecting command lines or
/// environment. This is one worker-parent check, not an authorization or proof that a parent process is a node.
/// </summary>
[SupportedOSPlatform("linux")]
internal static unsafe partial class LinuxExecutableIdentity
{
    internal static bool MatchesCurrent(int processId)
    {
        if (processId <= 0 || !LinuxOwnedProcessIdentity.HasMatchingProcView()) return false;
        Span<byte> own = stackalloc byte[256];
        Span<byte> other = stackalloc byte[256];
        own.Clear();
        other.Clear();
        fixed (byte* a = own, b = other)
        {
            if (Statx(-100, "/proc/self/exe", 0, 0x101, a) != 0 ||
                Statx(-100, "/proc/" + processId.ToString(CultureInfo.InvariantCulture) + "/exe", 0, 0x101, b) != 0 ||
                (*(uint*)a & 0x101) != 0x101 || (*(uint*)b & 0x101) != 0x101 ||
                (*(ushort*)(a + 28) & 0xf000) != 0x8000 || (*(ushort*)(b + 28) & 0xf000) != 0x8000)
                return false;
            return *(ulong*)(a + 32) == *(ulong*)(b + 32) &&
                *(uint*)(a + 136) == *(uint*)(b + 136) && *(uint*)(a + 140) == *(uint*)(b + 140);
        }
    }

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int Statx(int directoryFd, string path, int flags, uint mask, byte* stat);
}
