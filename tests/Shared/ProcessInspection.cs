// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Tests;

/// <summary>
/// Reads another process's command line and environment, so a test can tell its own processes from those of a test running beside it
/// (the processes of one test node all carry that node's unique <c>ARCFORGES_ENDPOINT</c>, and a holder names its attempt on its command
/// line). Linux reads <c>/proc/&lt;pid&gt;/cmdline</c> and <c>/proc/&lt;pid&gt;/environ</c>; Windows reads the process parameters of
/// the target's PEB (64-bit processes of the same user). Returns <see langword="null"/> when the process is gone or unreadable: a caller
/// treats that process as not its own. Linked into the test projects that need it.
/// </summary>
internal static partial class ProcessInspection
{
    /// <summary>The value of the environment variable <paramref name="name"/> in process <paramref name="pid"/>, or null.</summary>
    public static string? EnvironmentValue(int pid, string name)
    {
        var block = OperatingSystem.IsWindows() ? WindowsParameters(pid, environment: true) : ProcText(pid, "environ");
        if (block is null)
        {
            return null;
        }

        var prefix = name + "=";
        foreach (var entry in block.Split('\0'))
        {
            if (entry.StartsWith(prefix, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            {
                return entry[prefix.Length..];
            }
        }

        return null;
    }

    /// <summary>The command line of process <paramref name="pid"/> (Linux: the arguments joined by spaces), or null.</summary>
    public static string? CommandLine(int pid) => OperatingSystem.IsWindows()
        ? WindowsParameters(pid, environment: false)
        : ProcText(pid, "cmdline")?.TrimEnd('\0').Replace('\0', ' ');

    private static string? ProcText(int pid, string file)
    {
        try
        {
            return Encoding.UTF8.GetString(File.ReadAllBytes($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/{file}"));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    // x64 and arm64 layouts: PROCESS_BASIC_INFORMATION.PebBaseAddress at 8, PEB.ProcessParameters at 0x20, and in
    // RTL_USER_PROCESS_PARAMETERS the CommandLine UNICODE_STRING at 0x70 (length) / 0x78 (buffer), Environment at 0x80 and
    // EnvironmentSize at 0x3F0.
    [SupportedOSPlatform("windows")]
    private static string? WindowsParameters(int pid, bool environment)
    {
        if (!Environment.Is64BitProcess)
        {
            return null;
        }

        using var process = OpenProcess(QueryLimitedInformation | VirtualMemoryRead, inherit: false, pid);
        if (process.IsInvalid)
        {
            return null;
        }

        var basic = new byte[48];
        if (NtQueryInformationProcess(process, 0, basic, basic.Length, out _) != 0
            || Read(process, BitConverter.ToInt64(basic, 8) + 0x20, 8) is not { } parametersPointer)
        {
            return null;
        }

        var parameters = BitConverter.ToInt64(parametersPointer);
        if (Read(process, parameters, 0x3F8) is not { } block)
        {
            return null;
        }

        var (address, length) = environment
            ? (BitConverter.ToInt64(block, 0x80), Math.Min(BitConverter.ToInt64(block, 0x3F0), 1L << 20))
            : (BitConverter.ToInt64(block, 0x78), BitConverter.ToUInt16(block, 0x70));
        return address != 0 && length > 0 && Read(process, address, (int)length) is { } text ? Encoding.Unicode.GetString(text) : null;
    }

    [SupportedOSPlatform("windows")]
    private static byte[]? Read(SafeProcessHandle process, long address, int length)
    {
        var buffer = new byte[length];
        return ReadProcessMemory(process, (nint)address, buffer, length, out var read) && read == length ? buffer : null;
    }

    private const uint QueryLimitedInformation = 0x1000;
    private const uint VirtualMemoryRead = 0x0010;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int processId);

    [LibraryImport("ntdll.dll")]
    private static partial int NtQueryInformationProcess(SafeProcessHandle process, int informationClass, [Out] byte[] information, int length, out int returned);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ReadProcessMemory(SafeProcessHandle process, nint address, [Out] byte[] buffer, nint size, out nint read);
}
