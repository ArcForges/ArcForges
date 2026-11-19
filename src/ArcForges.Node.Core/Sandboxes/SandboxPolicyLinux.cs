// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Sandboxes;

[SupportedOSPlatform("linux")]
internal static partial class SandboxPolicyLinux
{
    internal static bool ProbePty()
    {
        const int readWriteNoControllingTerminalCloseOnExec = 0x80102;
        var raw = OpenPty(readWriteNoControllingTerminalCloseOnExec);
        if (raw < 0)
        {
            return false;
        }

        using var descriptor = new SafeFileHandle(raw, ownsHandle: true);
        return GrantPty(descriptor) == 0 && UnlockPty(descriptor) == 0;
    }

    [LibraryImport("libc", EntryPoint = "posix_openpt", SetLastError = true)]
    private static partial int OpenPty(int flags);

    [LibraryImport("libc", EntryPoint = "grantpt", SetLastError = true)]
    private static partial int GrantPty(SafeFileHandle descriptor);

    [LibraryImport("libc", EntryPoint = "unlockpt", SetLastError = true)]
    private static partial int UnlockPty(SafeFileHandle descriptor);
}
