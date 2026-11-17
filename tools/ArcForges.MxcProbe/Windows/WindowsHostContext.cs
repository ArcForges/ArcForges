// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.MxcProbe;

// Call from the actual background owner, before executor launch. This observes
// its process token, never an impersonating thread token. The local user SID is
// identity metadata; redact it before publishing a report. No account name,
// environment, credential, command line or personal path is inspected here.
[SupportedOSPlatform("windows")]
internal static unsafe partial class WindowsHostContext
{
    private const int ErrorInvalidData = 13;
    private const int ErrorInsufficientBuffer = 122;

    /// <summary>Writes one complete JSON object describing the calling owner.</summary>
    internal static void Write(Utf8JsonWriter writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStartObject();
        writer.WriteString("observedUtc", DateTimeOffset.UtcNow);
        writer.WriteNumber("processId", Environment.ProcessId);
        writer.WriteString("identitySource", "current_process_token");
        WriteToken(writer);
        WriteConsole(writer);
        WriteJob(writer);
        writer.WriteEndObject();
    }

    private static void WriteToken(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("token");
        if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out var token))
        {
            var error = Marshal.GetLastPInvokeError();
            token?.Dispose();
            WriteError(writer, error);
            writer.WriteEndObject();
            return;
        }

        using (token)
        {
            writer.WriteString("status", "opened_for_query");
            WriteSid(writer, token, "user", 1, includeIntegrity: false);
            WriteUInt32(writer, token, "elevation", 20);
            WriteUInt32(writer, token, "elevationType", 18);
            WriteUInt32(writer, token, "sessionId", 12);
            WriteSid(writer, token, "integrity", 25, includeIntegrity: true);
        }

        writer.WriteEndObject();
    }

    private static void WriteUInt32(Utf8JsonWriter writer, SafeFileHandle token, string name, int informationClass)
    {
        writer.WriteStartObject(name);
        uint value = 0;
        if (!GetTokenInformation(token, informationClass, &value, sizeof(uint), out var returned))
        {
            WriteError(writer, Marshal.GetLastPInvokeError());
        }
        else if (returned != sizeof(uint))
        {
            WriteError(writer, ErrorInvalidData);
        }
        else
        {
            writer.WriteString("status", "observed");
            writer.WriteNumber("value", value);
        }

        writer.WriteEndObject();
    }

    private static void WriteSid(Utf8JsonWriter writer, SafeFileHandle token, string name, int informationClass, bool includeIntegrity)
    {
        writer.WriteStartObject(name);
        _ = GetTokenInformation(token, informationClass, null, 0, out var required);
        var error = Marshal.GetLastPInvokeError();
        // TOKEN_USER and TOKEN_MANDATORY_LABEL both start with SID_AND_ATTRIBUTES.
        if (error != ErrorInsufficientBuffer || required < IntPtr.Size + sizeof(uint) || required > 65536)
        {
            WriteError(writer, error == ErrorInsufficientBuffer ? ErrorInvalidData : error);
            writer.WriteEndObject();
            return;
        }

        var buffer = NativeMemory.Alloc((nuint)required);
        try
        {
            if (!GetTokenInformation(token, informationClass, buffer, required, out var returned))
            {
                WriteError(writer, Marshal.GetLastPInvokeError());
            }
            else if (returned < IntPtr.Size + sizeof(uint) || returned > required || *(nint*)buffer == 0 || !IsValidSid(*(nint*)buffer))
            {
                WriteError(writer, ErrorInvalidData);
            }
            else if (!ConvertSidToStringSid(*(nint*)buffer, out var text))
            {
                WriteError(writer, Marshal.GetLastPInvokeError());
            }
            else
            {
                try
                {
                    writer.WriteString("status", "observed");
                    writer.WriteString("sid", Marshal.PtrToStringUni(text));
                    if (includeIntegrity)
                    {
                        var sid = *(nint*)buffer;
                        var count = GetSidSubAuthorityCount(sid);
                        if (count == null || *count == 0)
                        {
                            writer.WriteStartObject("rid");
                            WriteError(writer, ErrorInvalidData);
                            writer.WriteEndObject();
                        }
                        else
                        {
                            var rid = GetSidSubAuthority(sid, (uint)(*count - 1));
                            if (rid == null)
                            {
                                writer.WriteStartObject("rid");
                                WriteError(writer, ErrorInvalidData);
                                writer.WriteEndObject();
                            }
                            else
                            {
                                writer.WriteNumber("rid", *rid);
                            }
                        }
                    }
                }
                finally
                {
                    _ = LocalFree(text);
                }
            }
        }
        finally
        {
            NativeMemory.Free(buffer);
        }

        writer.WriteEndObject();
    }

    private static void WriteConsole(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("console");
        writer.WriteBoolean("windowPresent", GetConsoleWindow() != 0);
        uint firstProcess = 0;
        var count = GetConsoleProcessList(&firstProcess, 1);
        if (count == 0)
        {
            // With no attached console this query normally reports INVALID_HANDLE.
            // Keep that actual result rather than presenting a fabricated count.
            WriteError(writer, Marshal.GetLastPInvokeError());
            writer.WriteNull("attached");
        }
        else
        {
            writer.WriteString("status", "observed");
            writer.WriteBoolean("attached", true);
            writer.WriteNumber("reportedProcessCount", count);
        }

        writer.WriteEndObject();
    }

    private static void WriteJob(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("job");
        writer.WriteString("queryScope", "calling_process_immediate_job_only");
        writer.WriteBoolean("allAncestorJobsEnumerated", false);
        writer.WriteString("coverage", "Unknown ancestor Jobs are not enumerated. The experiment must separately query every handle in its externally constructed owned chain.");
        if (!IsProcessInJob(GetCurrentProcess(), 0, out var inJob))
        {
            WriteError(writer, Marshal.GetLastPInvokeError());
            writer.WriteNull("inJob");
            writer.WriteEndObject();
            return;
        }

        writer.WriteString("status", "membership_observed");
        writer.WriteBoolean("inJob", inJob);
        if (inJob)
        {
            WriteJobLimits(writer);
            WriteJobAccounting(writer);
            uint ui = 0;
            writer.WriteStartObject("uiRestrictions");
            if (QueryJob(writer, 4, &ui, sizeof(uint))) writer.WriteNumber("flags", ui);
            writer.WriteEndObject();
            var cpu = default(ConPtyNative.CpuLimits);
            writer.WriteStartObject("cpuRateControl");
            if (QueryJob(writer, 15, &cpu, sizeof(ConPtyNative.CpuLimits)))
            {
                writer.WriteNumber("flags", cpu.Flags);
                // This is the raw documented union: rate, weight or min/max,
                // interpreted only together with ControlFlags, never as a cap alone.
                writer.WriteNumber("rawValue", cpu.Rate);
            }

            writer.WriteEndObject();
        }

        writer.WriteEndObject();
    }

    private static void WriteJobLimits(Utf8JsonWriter writer)
    {
        var limits = default(ConPtyNative.ExtendedLimits);
        writer.WriteStartObject("extendedLimits");
        if (QueryJob(writer, 9, &limits, sizeof(ConPtyNative.ExtendedLimits)))
        {
            writer.WriteNumber("flags", limits.Basic.LimitFlags);
            writer.WriteBoolean("breakawayAllowed", (limits.Basic.LimitFlags & 0x0800) != 0);
            writer.WriteBoolean("silentBreakawayAllowed", (limits.Basic.LimitFlags & 0x1000) != 0);
            writer.WriteBoolean("killOnClose", (limits.Basic.LimitFlags & 0x2000) != 0);
            writer.WriteNumber("processTimeLimit100ns", limits.Basic.ProcessTime);
            writer.WriteNumber("jobTimeLimit100ns", limits.Basic.JobTime);
            writer.WriteNumber("activeProcessLimit", limits.Basic.ActiveProcessLimit);
            writer.WriteNumber("processCommitLimitBytes", (ulong)limits.ProcessMemoryLimit);
            writer.WriteNumber("jobCommitLimitBytes", (ulong)limits.JobMemoryLimit);
            writer.WriteNumber("peakProcessCommitBytes", (ulong)limits.PeakProcessMemory);
            writer.WriteNumber("peakJobCommitBytes", (ulong)limits.PeakJobMemory);
            writer.WriteNumber("priorityClass", limits.Basic.PriorityClass);
            writer.WriteNumber("schedulingClass", limits.Basic.SchedulingClass);
            writer.WriteNumber("affinity", (ulong)limits.Basic.Affinity);
            writer.WriteNumber("minimumWorkingSetBytes", (ulong)limits.Basic.MinimumWorkingSet);
            writer.WriteNumber("maximumWorkingSetBytes", (ulong)limits.Basic.MaximumWorkingSet);
        }

        writer.WriteEndObject();
    }

    private static void WriteJobAccounting(Utf8JsonWriter writer)
    {
        var accounting = default(ConPtyNative.Accounting);
        writer.WriteStartObject("accounting");
        if (QueryJob(writer, 1, &accounting, sizeof(ConPtyNative.Accounting)))
        {
            writer.WriteNumber("userTime100ns", accounting.UserTime);
            writer.WriteNumber("kernelTime100ns", accounting.KernelTime);
            writer.WriteNumber("periodUserTime100ns", accounting.PeriodUser);
            writer.WriteNumber("periodKernelTime100ns", accounting.PeriodKernel);
            writer.WriteNumber("totalPageFaults", accounting.PageFaults);
            writer.WriteNumber("totalProcesses", accounting.TotalProcesses);
            writer.WriteNumber("activeProcesses", accounting.ActiveProcesses);
            writer.WriteNumber("terminatedProcesses", accounting.TerminatedProcesses);
        }

        writer.WriteEndObject();
    }

    private static bool QueryJob(Utf8JsonWriter writer, int informationClass, void* value, int size)
    {
        if (!QueryInformationJobObject(0, informationClass, value, size, out var returned))
        {
            WriteError(writer, Marshal.GetLastPInvokeError());
            return false;
        }

        if (returned != size)
        {
            WriteError(writer, ErrorInvalidData);
            return false;
        }

        writer.WriteString("status", "observed");
        return true;
    }

    private static void WriteError(Utf8JsonWriter writer, int error)
    {
        writer.WriteString("status", "query_failed");
        writer.WriteNumber("win32Error", error);
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(nint process, uint access, out SafeFileHandle token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(SafeFileHandle token, int informationClass, void* information, int length, out int returned);

    [LibraryImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertSidToStringSid(nint sid, out nint text);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsValidSid(nint sid);

    [LibraryImport("advapi32.dll")] private static partial byte* GetSidSubAuthorityCount(nint sid);
    [LibraryImport("advapi32.dll")] private static partial uint* GetSidSubAuthority(nint sid, uint index);
    [LibraryImport("kernel32.dll")] private static partial nint LocalFree(nint memory);
    [LibraryImport("kernel32.dll", SetLastError = true)] private static partial uint GetConsoleProcessList(uint* processes, uint count);
    [LibraryImport("kernel32.dll")] private static partial nint GetConsoleWindow();
    [LibraryImport("kernel32.dll")] private static partial nint GetCurrentProcess();
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsProcessInJob(nint process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool result);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryInformationJobObject(nint job, int informationClass, void* information, int length, out int returned);
}
