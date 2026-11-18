// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.MxcProbe;

[SupportedOSPlatform("windows")]
internal static partial class WindowsProbeErrorMode
{
    // Test workers must return native loader/crash failures rather than wait for
    // a desktop dialog. Children inherit this process-local mode. No registry,
    // machine policy, isolation setting or failure verdict is changed.
    internal static void EnableNoninteractiveFailures() => _ = SetErrorMode(GetErrorMode() | 0x0001 | 0x0002);

    [LibraryImport("kernel32.dll")] private static partial uint GetErrorMode();
    [LibraryImport("kernel32.dll")] private static partial uint SetErrorMode(uint mode);
}
