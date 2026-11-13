// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Core.Platform;

internal enum LinuxProcessObservation
{
    Alive,
    Ended,
    Unknown,
}

/// <summary>
/// Durable identity for a positive owned child in one Linux boot and PID namespace. This observes process lifetime,
/// not completion of a file effect or authorization. An unobservable identity is never treated as ended.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed partial record LinuxOwnedProcessIdentity(Guid BootId, string PidNamespace, int ProcessId, long StartTicks)
{
    internal static LinuxOwnedProcessIdentity CaptureChild(Process child)
    {
        ArgumentNullException.ThrowIfNull(child);
        var pid = child.Id;
        if (pid <= 1 || child.HasExited) throw new InvalidOperationException("The owned child is unavailable.");
        CheckProcView();
        var boot = CurrentBoot();
        var pidNamespace = CurrentPidNamespace();
        var (parent, start) = ProcessStat(pid);
        if (parent != Environment.ProcessId || child.HasExited)
            throw new InvalidOperationException("The process is not a live child of this node.");
        return new LinuxOwnedProcessIdentity(boot, pidNamespace, pid, start);
    }

    internal LinuxProcessObservation Observe()
    {
        if (ProcessId <= 1 || StartTicks <= 0 || BootId == Guid.Empty || !ValidNamespace(PidNamespace))
            return LinuxProcessObservation.Unknown;
        try
        {
            CheckProcView();
            var currentBoot = CurrentBoot();
            // A different boot could mean this data root moved to another still-running host.
            if (currentBoot != BootId) return LinuxProcessObservation.Unknown;
            if (!string.Equals(CurrentPidNamespace(), PidNamespace, StringComparison.Ordinal))
                return LinuxProcessObservation.Unknown;
            if (SignalZero(ProcessId, 0) != 0)
                return Marshal.GetLastPInvokeError() == 3 ? LinuxProcessObservation.Ended : LinuxProcessObservation.Unknown;
            try
            {
                var (_, start) = ProcessStat(ProcessId);
                return start == StartTicks ? LinuxProcessObservation.Alive : LinuxProcessObservation.Ended;
            }
            catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
            {
                // A process can exit between signal-zero and stat. Only the kernel's second ESRCH proves absence.
                return SignalZero(ProcessId, 0) != 0 && Marshal.GetLastPInvokeError() == 3
                    ? LinuxProcessObservation.Ended : LinuxProcessObservation.Unknown;
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or FormatException or InvalidDataException or NotSupportedException or System.Security.SecurityException)
        {
            return LinuxProcessObservation.Unknown;
        }
    }

    internal static bool HasMatchingProcView()
    {
        try { CheckProcView(); return true; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or
            NotSupportedException or System.Security.SecurityException)
        { return false; }
    }

    private static void CheckProcView()
    {
        // A procfs mounted for another PID namespace may interpret a positive PID as a different process.
        var value = File.ReadAllText("/proc/self/stat");
        var open = value.IndexOf('(');
        if (open < 1 || !int.TryParse(value.AsSpan(0, open).Trim(), NumberStyles.None,
            CultureInfo.InvariantCulture, out var pid) || pid != Environment.ProcessId)
            throw new InvalidDataException("The procfs PID view does not match this process.");
    }

    private static Guid CurrentBoot()
    {
        var text = File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();
        return Guid.TryParseExact(text, "D", out var value) && value != Guid.Empty
            ? value : throw new InvalidDataException("The Linux boot identity is unavailable.");
    }

    private static string CurrentPidNamespace()
    {
        var value = new FileInfo("/proc/self/ns/pid").LinkTarget;
        return ValidNamespace(value) ? value! : throw new InvalidDataException("The Linux PID namespace identity is unavailable.");
    }

    private static bool ValidNamespace(string? value)
    {
        if (value is null || !value.StartsWith("pid:[", StringComparison.Ordinal) || !value.EndsWith(']')) return false;
        var number = value.AsSpan(5, value.Length - 6);
        return ulong.TryParse(number, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed > 0;
    }

    private static (int Parent, long StartTicks) ProcessStat(int processId)
    {
        var value = File.ReadAllText("/proc/" + processId.ToString(CultureInfo.InvariantCulture) + "/stat");
        var open = value.IndexOf('(');
        var close = value.LastIndexOf(')');
        if (open < 1 || close <= open || close + 2 >= value.Length ||
            !int.TryParse(value.AsSpan(0, open).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var parsedPid) ||
            parsedPid != processId)
            throw new InvalidDataException("The Linux process identity is unavailable.");
        var fields = value[(close + 2)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 20 || fields[0].Length != 1 ||
            !int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var parent) || parent < 0 ||
            !long.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out var start) || start <= 0)
            throw new InvalidDataException("The Linux process identity is unavailable.");
        return (parent, start);
    }

    [LibraryImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static partial int SignalZero(int pid, int signal);
}
