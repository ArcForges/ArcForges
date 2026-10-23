// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// The virtual machine processes of a Windows node (03 section 9; AD-0018 section 2): the WSL VM's worker (<c>vmmem</c>, or
/// <c>vmmemWSL</c> on newer WSL; A-L01) is one <c>GUEST_VM</c> consumer, and a task that runs a WSL launcher crosses the VM boundary.
/// Names compare without case and with or without <c>.exe</c>. Git's <c>bash.exe</c> shares its name with the legacy WSL launcher, so
/// <c>bash.exe</c> is not treated as one.
/// </summary>
public static class VmProcesses
{
    private static readonly string[] Workers = ["vmmem", "vmmemWSL"];
    private static readonly string[] Launchers = ["wsl", "wslg", "wslhost"];

    /// <summary>True when <paramref name="image"/> is a VM worker process.</summary>
    public static bool IsWorker(string image) => Matches(image, Workers);

    /// <summary>True when <paramref name="image"/> launches work into the WSL VM.</summary>
    public static bool IsLauncher(string image) => Matches(image, Launchers);

    private static bool Matches(string image, string[] names)
    {
        ArgumentNullException.ThrowIfNull(image);
        var name = Path.GetFileName(image.Replace('\\', '/').Split('/')[^1]);
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            name = name[..^4];
        }

        return names.Any(candidate => string.Equals(candidate, name, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>
/// The Windows observation sources (03 section 1): machine CPU from <c>GetSystemTimes</c>, memory and commit from
/// <c>GlobalMemoryStatusEx</c>, and the process table from one <c>NtQuerySystemInformation(SystemProcessInformation)</c> call, which
/// carries every process's ID, parent, creation time, image name, processor times, private working set and I/O transfer counts. The
/// table replaces <c>CreateToolhelp32Snapshot</c> plus per-process <c>GetProcessTimes</c>, <c>GetProcessMemoryInfo</c> and
/// <c>GetProcessIoCounters</c>: the same values without opening a handle to any process (a running game among the top processes is
/// never opened), and the processes to detail can be chosen by CPU because the whole table has it.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed unsafe class WindowsResourceSampler : IResourceSampler
{
    private const int SystemProcessInformation = 5;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

    // SYSTEM_PROCESS_INFORMATION, 64-bit layout (x64 and arm64). The SDK's winternl.h names only NextEntryOffset, NumberOfThreads,
    // ImageName, BasePriority, UniqueProcessId and the memory counters: CreateTime, UserTime, KernelTime and WorkingSetPrivateSize lie in
    // its Reserved1[48], InheritedFromUniqueProcessId is its Reserved2, and the I/O transfer counts lie in its Reserved7[6]. These offsets
    // are therefore undocumented, though unchanged since Windows Vista and relied on by every process tool. The windows-real cross-check
    // (ResourceSamplerTests.TheTableMatchesToolhelpAndTheProcessApi) compares each of them with a documented source on every run (the
    // parent and image with Toolhelp, the times with GetProcessTimes, the private working set with GetProcessMemoryInfo and the transfer
    // counts with GetProcessIoCounters), so a layout change fails the suite instead of producing wrong figures.
    private const int NextEntryOffset = 0x00;
    private const int WorkingSetPrivateSize = 0x08;
    private const int CreateTime = 0x20;
    private const int UserTime = 0x28;
    private const int KernelTime = 0x30;
    private const int ImageNameLength = 0x38;
    private const int ImageNameBuffer = 0x40;
    private const int UniqueProcessId = 0x50;
    private const int InheritedFromUniqueProcessId = 0x58;
    private const int ReadTransferCount = 0xE8;
    private const int WriteTransferCount = 0xF0;

    private readonly Lock _gate = new();
    // Pinned: the image names in the table point into the buffer itself.
    private byte[] _buffer = GC.AllocateUninitializedArray<byte>(1 << 20, pinned: true);

    /// <summary>Creates the sampler (a 64-bit process only: the table is read with the 64-bit layout's offsets).</summary>
    public WindowsResourceSampler() => RequireSixtyFourBit();

    /// <inheritdoc />
    public string Name => "windows";

    /// <inheritdoc />
    public MachineSample Machine()
    {
        if (!Native.GetSystemTimes(out var idle, out var kernel, out var user))
        {
            throw new Win32Exception(Native.LastError);
        }

        var status = new Native.MemoryStatusEx { Length = sizeof(Native.MemoryStatusEx) };
        if (!Native.GlobalMemoryStatusEx(&status))
        {
            throw new Win32Exception(Native.LastError);
        }

        // Kernel time includes idle time (GetSystemTimes); FILETIME units are 100 ns.
        return new MachineSample
        {
            CpuBusyMs = (kernel + user - idle) / 10_000,
            CpuTotalMs = (kernel + user) / 10_000,
            TotalMemoryBytes = (long)status.TotalPhys,
            AvailableMemoryBytes = (long)status.AvailPhys,
            CommitBytes = (long)(status.TotalPageFile - status.AvailPageFile),
            CommitLimitBytes = (long)status.TotalPageFile,
        };
    }

    /// <inheritdoc />
    public IReadOnlyList<ProcessSample> Processes()
    {
        lock (_gate)
        {
            int returned;
            while (true)
            {
                int result;
                fixed (byte* buffer = _buffer)
                {
                    result = Native.NtQuerySystemInformation(SystemProcessInformation, buffer, _buffer.Length, out returned);
                }

                if (result == StatusInfoLengthMismatch)
                {
                    _buffer = GC.AllocateUninitializedArray<byte>(Math.Max(_buffer.Length * 2, returned + (64 * 1024)), pinned: true);
                    continue;
                }

                if (result < 0)
                {
                    throw new Win32Exception(Native.RtlNtStatusToDosError(result));
                }

                break;
            }

            return Parse(_buffer.AsSpan(0, returned));
        }
    }

    /// <inheritdoc />
    public bool MachineIoFromProcesses => true;

    /// <inheritdoc />
    public bool IsVmWorker(string image) => VmProcesses.IsWorker(image);

    /// <inheritdoc />
    public bool IsVmLauncher(string image) => VmProcesses.IsLauncher(image);

    /// <summary>Parses a <c>SystemProcessInformation</c> buffer (the idle process, ID 0, is left out).</summary>
    internal static List<ProcessSample> Parse(ReadOnlySpan<byte> buffer)
    {
        RequireSixtyFourBit();
        var processes = new List<ProcessSample>(512);
        var offset = 0;
        while (offset + WriteTransferCount + 8 <= buffer.Length)
        {
            var entry = buffer[offset..];
            var pid = (int)Read64(entry, UniqueProcessId);
            if (pid != 0)
            {
                var length = MemoryMarshal.Read<ushort>(entry[ImageNameLength..]);
                var name = MemoryMarshal.Read<nint>(entry[ImageNameBuffer..]);
                var image = name == 0 || length == 0 ? (pid == 4 ? "System" : "?") : new string((char*)name, 0, length / 2);
                var created = Read64(entry, CreateTime);
                processes.Add(new ProcessSample(pid, (int)Read64(entry, InheritedFromUniqueProcessId),
                    created > 0 ? DateTimeOffset.FromFileTime(created).ToUniversalTime() : DateTimeOffset.UnixEpoch, image)
                {
                    CpuTimeMs = (Read64(entry, UserTime) + Read64(entry, KernelTime)) / 10_000,
                    MemoryBytes = Read64(entry, WorkingSetPrivateSize),
                    IoReadBytes = Read64(entry, ReadTransferCount),
                    IoWriteBytes = Read64(entry, WriteTransferCount),
                });
            }

            var next = MemoryMarshal.Read<int>(entry[NextEntryOffset..]);
            if (next <= 0)
            {
                break;
            }

            offset += next;
        }

        return processes;
    }

    private static long Read64(ReadOnlySpan<byte> entry, int offset) => MemoryMarshal.Read<long>(entry[offset..]);

    /// <summary>The offsets above are those of the 64-bit layout; a 32-bit process would read every field from the wrong place.</summary>
    private static void RequireSixtyFourBit()
    {
        if (!Environment.Is64BitProcess)
        {
            throw new PlatformNotSupportedException("The Windows resource sampler reads the 64-bit SYSTEM_PROCESS_INFORMATION layout; run a 64-bit node.");
        }
    }
}
