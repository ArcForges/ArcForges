// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// The identity of the running boot (AD-0006 section 3; architecture 02 section 2 step 4): on Linux
/// <c>/proc/sys/kernel/random/boot_id</c>; on Windows the machine GUID with the boot time reported by the kernel. Two node runs see
/// the same value exactly when no reboot happened between them.
/// </summary>
public static partial class BootIdentity
{
    private const int SystemTimeOfDayInformation = 3;

    /// <summary>Reads the current boot identity.</summary>
    public static string Read()
    {
        if (OperatingSystem.IsWindows())
        {
            return ReadWindows();
        }

        var bootId = File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();
        return "linux:" + bootId;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static unsafe string ReadWindows()
    {
        var machine = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", null) as string ?? "unknown";
        var information = stackalloc long[6];
        var status = NtQuerySystemInformation(SystemTimeOfDayInformation, information, 48, out _);
        if (status != 0)
        {
            throw new InvalidOperationException(string.Create(CultureInfo.InvariantCulture, $"NtQuerySystemInformation failed (0x{status:X8})."));
        }

        // SYSTEM_TIMEOFDAY_INFORMATION.BootTime (100 ns since 1601) less BootTimeBias; whole seconds, so clock steps do not move it.
        var bootTime = information[0] - information[4];
        return string.Create(CultureInfo.InvariantCulture, $"windows:{machine}:{bootTime / 10_000_000}");
    }

    [LibraryImport("ntdll.dll")]
    private static unsafe partial int NtQuerySystemInformation(int informationClass, void* information, uint length, out uint returned);
}
