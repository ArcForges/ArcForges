// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Windows;

/// <summary>The accounting of a job (basic, I/O and peak commit; V-W03: it covers terminated processes and child jobs).</summary>
/// <param name="UserTime">Total user-mode time.</param>
/// <param name="KernelTime">Total kernel-mode time.</param>
/// <param name="TotalProcesses">Processes ever associated.</param>
/// <param name="ActiveProcesses">Processes associated now.</param>
/// <param name="ReadBytes">Bytes read.</param>
/// <param name="WriteBytes">Bytes written.</param>
/// <param name="PeakJobMemory">Peak committed memory of the job.</param>
/// <param name="JobMemoryLimit">The commit limit in force (0 = none).</param>
public sealed record JobAccounting(TimeSpan UserTime, TimeSpan KernelTime, int TotalProcesses, int ActiveProcesses, long ReadBytes, long WriteBytes,
    long PeakJobMemory, long JobMemoryLimit);

/// <summary>
/// A Windows job object (AD-0005 Windows sections 1-2; V-W01-V-W05): creation by name, the limits ArcForges sets (CPU weight or hard
/// cap, commit limit, notification limit, active-process limit, kill-on-close; never UI restrictions, which prevent nesting, and never
/// breakaway), assignment, termination, accounting, limit violations and the completion-port association with clear-then-attach
/// (L-15). The handle has full job access.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed unsafe class JobObject : IDisposable
{
    private const int ErrorAlreadyExists = 183;

    private JobObject(SafeKernelHandle handle, string? name)
    {
        Handle = handle;
        Name = name;
    }

    /// <summary>The handle.</summary>
    public SafeKernelHandle Handle { get; }

    /// <summary>The job's name, or <see langword="null"/> for an unnamed job.</summary>
    public string? Name { get; }

    /// <summary>Creates a job; a named job that already exists is re-opened only when <paramref name="openExisting"/> is set.</summary>
    /// <exception cref="Win32Exception">The OS refused, or the named job exists and <paramref name="openExisting"/> is false.</exception>
    public static JobObject Create(string? name, bool openExisting = false)
    {
        var handle = Native.CreateJobObject(0, name);
        var error = Native.LastError;
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new Win32Exception(error, $"CreateJobObject({name ?? "unnamed"}) failed.");
        }

        if (error == ErrorAlreadyExists && !openExisting)
        {
            handle.Dispose();
            throw new Win32Exception(error, $"The job {name} already exists.");
        }

        return new JobObject(handle, name);
    }

    /// <summary>Opens a named job, or returns <see langword="null"/> when no job of that name exists (L-14: no handle holds it).</summary>
    public static JobObject? Open(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var handle = Native.OpenJobObject(Native.JobObjectAllAccess, inherit: false, name);
        if (handle.IsInvalid)
        {
            var error = Native.LastError;
            handle.Dispose();
            return error == Native.ErrorFileNotFound ? null : throw new Win32Exception(error, $"OpenJobObject({name}) failed.");
        }

        return new JobObject(handle, name);
    }

    /// <summary>Wraps an inherited job handle (the holder).</summary>
    public static JobObject FromHandle(nint handle, string? name) => new(new SafeKernelHandle(handle, ownsHandle: true), name);

    /// <summary>
    /// Sets the extended limits: the commit limit (0 = none), the active-process limit (null = none) and kill-on-close. No breakaway is
    /// allowed: neither breakaway flag is ever set.
    /// </summary>
    public void SetLimits(long commitLimitBytes, int? activeProcessLimit, bool killOnClose)
    {
        var info = default(Native.JobObjectExtendedLimitInformation);
        if (commitLimitBytes > 0)
        {
            info.BasicLimitInformation.LimitFlags |= Native.JobObjectLimitJobMemory;
            info.JobMemoryLimit = (nuint)commitLimitBytes;
        }

        if (activeProcessLimit is { } processes)
        {
            info.BasicLimitInformation.LimitFlags |= Native.JobObjectLimitActiveProcess;
            info.BasicLimitInformation.ActiveProcessLimit = (uint)processes;
        }

        if (killOnClose)
        {
            info.BasicLimitInformation.LimitFlags |= Native.JobObjectLimitKillOnJobClose;
        }

        Set(Native.JobObjectExtendedLimitInformationClass, &info, sizeof(Native.JobObjectExtendedLimitInformation));
    }

    /// <summary>A notification-only commit limit (V-W05): crossing it is reported, never enforced.</summary>
    public void SetMemoryNotification(long bytes)
    {
        var info = default(Native.JobObjectNotificationLimitInformation);
        info.JobMemoryLimit = (ulong)bytes;
        info.LimitFlags = Native.JobObjectLimitJobMemory;
        Set(Native.JobObjectNotificationLimitInformationClass, &info, sizeof(Native.JobObjectNotificationLimitInformation));
    }

    /// <summary>Weight-based CPU rate control (1-9; V-W04).</summary>
    public void SetCpuWeight(int weight)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(weight, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(weight, 9);
        var info = new Native.JobObjectCpuRateControlInformation
        {
            ControlFlags = Native.CpuRateControlEnable | Native.CpuRateControlWeightBased,
            Value = (uint)weight,
        };
        Set(Native.JobObjectCpuRateControlInformationClass, &info, sizeof(Native.JobObjectCpuRateControlInformation));
    }

    /// <summary>A hard CPU cap in 1/100 percent (1-10000) of the machine, or of the parent job's allocation when nested (V-W04).</summary>
    public void SetCpuHardCap(int rate)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(rate, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(rate, 10_000);
        var info = new Native.JobObjectCpuRateControlInformation
        {
            ControlFlags = Native.CpuRateControlEnable | Native.CpuRateControlHardCap,
            Value = (uint)rate,
        };
        Set(Native.JobObjectCpuRateControlInformationClass, &info, sizeof(Native.JobObjectCpuRateControlInformation));
    }

    /// <summary>The CPU rate control in force: the flags and the rate or weight.</summary>
    public (uint Flags, uint Value) CpuRateControl()
    {
        var info = default(Native.JobObjectCpuRateControlInformation);
        Query(Native.JobObjectCpuRateControlInformationClass, &info, sizeof(Native.JobObjectCpuRateControlInformation));
        return (info.ControlFlags, info.Value);
    }

    /// <summary>The extended limits in force.</summary>
    public (uint Flags, long JobMemoryLimit, int ActiveProcessLimit) Limits()
    {
        var info = default(Native.JobObjectExtendedLimitInformation);
        Query(Native.JobObjectExtendedLimitInformationClass, &info, sizeof(Native.JobObjectExtendedLimitInformation));
        return (info.BasicLimitInformation.LimitFlags, (long)info.JobMemoryLimit, (int)info.BasicLimitInformation.ActiveProcessLimit);
    }

    /// <summary>Assigns a process (V-W01: a process already in the parent is nested into this job).</summary>
    /// <exception cref="Win32Exception">The OS refused.</exception>
    public void Assign(SafeHandle process)
    {
        if (!Native.AssignProcessToJobObject(Handle, process))
        {
            throw new Win32Exception(Native.LastError, $"AssignProcessToJobObject({Name ?? "unnamed"}) failed.");
        }
    }

    /// <summary>Whether <paramref name="process"/> is in this job (or one nested in it).</summary>
    public bool Contains(SafeHandle process) => Native.IsProcessInJob(process, Handle.DangerousGetHandle(), out var result) && result;

    /// <summary>Terminates every process in the job and the jobs nested in it.</summary>
    public bool Terminate(uint exitCode) => Native.TerminateJobObject(Handle, exitCode);

    /// <summary>The accounting.</summary>
    public JobAccounting Accounting()
    {
        var info = default(Native.JobObjectBasicAndIoAccountingInformation);
        Query(Native.JobObjectBasicAndIoAccountingInformationClass, &info, sizeof(Native.JobObjectBasicAndIoAccountingInformation));
        var extended = default(Native.JobObjectExtendedLimitInformation);
        Query(Native.JobObjectExtendedLimitInformationClass, &extended, sizeof(Native.JobObjectExtendedLimitInformation));
        return new JobAccounting(
            TimeSpan.FromTicks(info.BasicInfo.TotalUserTime),
            TimeSpan.FromTicks(info.BasicInfo.TotalKernelTime),
            (int)info.BasicInfo.TotalProcesses,
            (int)info.BasicInfo.ActiveProcesses,
            (long)info.IoInfo.ReadTransferCount,
            (long)info.IoInfo.WriteTransferCount,
            (long)extended.PeakJobMemoryUsed,
            (extended.BasicLimitInformation.LimitFlags & Native.JobObjectLimitJobMemory) != 0 ? (long)extended.JobMemoryLimit : 0);
    }

    /// <summary>
    /// Limits the job exceeded (<c>JobObjectLimitViolationInformation</c>; AD-0005 section 4): <c>job_memory</c>, <c>cpu_time</c>, <c>io</c>.
    /// </summary>
    public List<string> LimitViolations()
    {
        var info = default(Native.JobObjectLimitViolationInformation);
        var violations = new List<string>();
        if (!Native.QueryInformationJobObject(Handle, Native.JobObjectLimitViolationInformationClass, &info, sizeof(Native.JobObjectLimitViolationInformation), out _))
        {
            return violations;
        }

        if ((info.ViolationLimitFlags & Native.JobObjectLimitJobMemory) != 0)
        {
            violations.Add("job_memory");
        }

        if ((info.ViolationLimitFlags & Native.JobObjectLimitJobTime) != 0)
        {
            violations.Add("cpu_time");
        }

        if ((info.ViolationLimitFlags & 0x00000400) != 0 || (info.ViolationLimitFlags & 0x00000800) != 0)
        {
            violations.Add("io");
        }

        return violations;
    }

    /// <summary>The IDs of the processes in the job now.</summary>
    public int[] ProcessIds()
    {
        for (var capacity = 64; ; capacity *= 4)
        {
            var length = 8 + (capacity * IntPtr.Size);
            var buffer = (byte*)NativeMemory.Alloc((nuint)length);
            try
            {
                if (Native.QueryInformationJobObject(Handle, Native.JobObjectBasicProcessIdListClass, buffer, length, out _))
                {
                    var listed = *(uint*)(buffer + 4);
                    var ids = new int[listed];
                    var list = (nuint*)(buffer + 8);
                    for (var index = 0; index < listed; index++)
                    {
                        ids[index] = (int)list[index];
                    }

                    return ids;
                }

                var error = Native.LastError;
                if (error != 234 /* ERROR_MORE_DATA */ || capacity > 1 << 20)
                {
                    throw new Win32Exception(error, "JobObjectBasicProcessIdList failed.");
                }
            }
            finally
            {
                NativeMemory.Free(buffer);
            }
        }
    }

    /// <summary>
    /// Associates <paramref name="port"/> with <paramref name="key"/>. A job accepts one port (L-15): with <paramref name="clearFirst"/>
    /// an existing association (a previous node run's) is cleared first, then the port attached.
    /// </summary>
    public void AssociateCompletionPort(SafeHandle port, nuint key, bool clearFirst)
    {
        ArgumentNullException.ThrowIfNull(port);
        if (clearFirst)
        {
            var clear = default(Native.JobObjectAssociateCompletionPort);
            Native.SetInformationJobObject(Handle, Native.JobObjectAssociateCompletionPortInformationClass, &clear, sizeof(Native.JobObjectAssociateCompletionPort));
        }

        var info = new Native.JobObjectAssociateCompletionPort { CompletionKey = (nint)key, CompletionPort = port.DangerousGetHandle() };
        Set(Native.JobObjectAssociateCompletionPortInformationClass, &info, sizeof(Native.JobObjectAssociateCompletionPort));
    }

    /// <summary>Closes the handle.</summary>
    public void Dispose() => Handle.Dispose();

    private void Set(int informationClass, void* info, int length)
    {
        if (!Native.SetInformationJobObject(Handle, informationClass, info, length))
        {
            throw new Win32Exception(Native.LastError, $"SetInformationJobObject(class {informationClass}) on {Name ?? "unnamed"} failed.");
        }
    }

    private void Query(int informationClass, void* info, int length)
    {
        if (!Native.QueryInformationJobObject(Handle, informationClass, info, length, out _))
        {
            throw new Win32Exception(Native.LastError, $"QueryInformationJobObject(class {informationClass}) on {Name ?? "unnamed"} failed.");
        }
    }
}
