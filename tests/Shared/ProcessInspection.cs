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
/// the target's PEB (64-bit processes of the same user). Returns <see langword="null"/> (or false) when the process is gone or
/// unreadable; a caller that filters processes by owner reports a running unreadable one rather than dropping it. Linked into the test projects that need it.
/// </summary>
internal static partial class ProcessInspection
{
    /// <summary>
    /// Reads variable <paramref name="name"/> of process <paramref name="pid"/>: false when its environment cannot be read (it exited, or
    /// it is not inspectable), true with the value, or null when the variable is not set.
    /// </summary>
    public static bool TryEnvironmentValue(int pid, string name, out string? value)
    {
        value = null;
        var block = OperatingSystem.IsWindows() ? WindowsParameters(pid, Parameter.Environment) : ProcText(pid, "environ");
        if (block is null)
        {
            return false;
        }

        var prefix = name + "=";
        foreach (var entry in block.Split('\0'))
        {
            if (entry.StartsWith(prefix, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            {
                value = entry[prefix.Length..];
                return true;
            }
        }

        return true;
    }

    /// <summary>The working directory of process <paramref name="pid"/>, or null.</summary>
    public static string? CurrentDirectory(int pid)
    {
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                return new FileInfo($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/cwd").LinkTarget;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        }

        return WindowsParameters(pid, Parameter.CurrentDirectory);
    }

    /// <summary>The command line of process <paramref name="pid"/> (Linux: the arguments joined by spaces), or null.</summary>
    public static string? CommandLine(int pid) => OperatingSystem.IsWindows()
        ? WindowsParameters(pid, Parameter.CommandLine)
        : ProcText(pid, "cmdline")?.TrimEnd('\0').Replace('\0', ' ');

    /// <summary>
    /// Whether process <paramref name="pid"/> has exited but is not reaped yet (Linux state Z). Its environment cannot be read (EACCES),
    /// and <see cref="System.Diagnostics.Process.HasExited"/> is false for a zombie that is not this process's child.
    /// </summary>
    public static bool IsZombie(int pid) =>
        !OperatingSystem.IsWindows() && ProcText(pid, "stat") is { } stat && stat.LastIndexOf(')') is var end and >= 0
        && stat.AsSpan(end + 1).TrimStart().StartsWith("Z", StringComparison.Ordinal);

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

    private enum Parameter
    {
        CurrentDirectory,
        CommandLine,
        Environment,
    }

    // x64 and arm64 layouts: PROCESS_BASIC_INFORMATION.PebBaseAddress at 8, PEB.ProcessParameters at 0x20, and in
    // RTL_USER_PROCESS_PARAMETERS the CurrentDirectory.DosPath UNICODE_STRING at 0x38 (length) / 0x40 (buffer), the CommandLine
    // UNICODE_STRING at 0x70 / 0x78, Environment at 0x80 and EnvironmentSize at 0x3F0.
    [SupportedOSPlatform("windows")]
    private static string? WindowsParameters(int pid, Parameter parameter)
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

        var (address, length) = parameter switch
        {
            Parameter.Environment => (BitConverter.ToInt64(block, 0x80), Math.Min(BitConverter.ToInt64(block, 0x3F0), 1L << 20)),
            Parameter.CommandLine => (BitConverter.ToInt64(block, 0x78), BitConverter.ToUInt16(block, 0x70)),
            _ => (BitConverter.ToInt64(block, 0x40), BitConverter.ToUInt16(block, 0x38)),
        };
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
