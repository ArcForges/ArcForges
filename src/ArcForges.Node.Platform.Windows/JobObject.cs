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
    /// Sets the extended limits: the commit limit (0 = none), the active-process limit (null = none), kill-on-close and the priority class
    /// every process of the job runs at (null = none; <c>JOB_OBJECT_LIMIT_PRIORITY_CLASS</c>: the job's processes cannot change it). No
    /// breakaway is allowed: neither breakaway flag is ever set.
    /// </summary>
    public void SetLimits(long commitLimitBytes, int? activeProcessLimit, bool killOnClose, uint? priorityClass = null)
    {
        var info = default(Native.JobObjectExtendedLimitInformation);
        if (priorityClass is { } priority)
        {
            info.BasicLimitInformation.LimitFlags |= Native.JobObjectLimitPriorityClass;
            info.BasicLimitInformation.PriorityClass = priority;
        }

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

    /// <summary>The enabled memory-notification threshold in force for this job, or zero when none is set.</summary>
    public long MemoryNotificationLimit()
    {
        var info = default(Native.JobObjectNotificationLimitInformation);
        Query(Native.JobObjectNotificationLimitInformationClass, &info, sizeof(Native.JobObjectNotificationLimitInformation));
        return (info.LimitFlags & Native.JobObjectLimitJobMemory) != 0 ? (long)info.JobMemoryLimit : 0;
    }

    /// <summary>Whether this job's own peak has notification or hard-limit evidence; the snapshot belongs to this job.</summary>
    internal bool HasOwnMemoryLimitEvidence(JobAccounting accounting)
    {
        ArgumentNullException.ThrowIfNull(accounting);
        var notification = MemoryNotificationLimit();
        return (notification > 0 && accounting.PeakJobMemory > notification)
            || (accounting.JobMemoryLimit > 0 && accounting.PeakJobMemory >= accounting.JobMemoryLimit - (64 * 1024));
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

    /// <summary>The priority class limit in force, or <see langword="null"/> when the job sets none.</summary>
    public uint? PriorityClassLimit()
    {
        var info = default(Native.JobObjectExtendedLimitInformation);
        Query(Native.JobObjectExtendedLimitInformationClass, &info, sizeof(Native.JobObjectExtendedLimitInformation));
        return (info.BasicLimitInformation.LimitFlags & Native.JobObjectLimitPriorityClass) != 0 ? info.BasicLimitInformation.PriorityClass : null;
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
    /// The job's committed memory now (<c>JobObjectLimitViolationInformation.JobMemory</c>). <c>PeakJobMemoryUsed</c> can exceed the commit
    /// limit by the size of a rejected request (the charge is counted before it is refused), so bounds are checked on this value.
    /// </summary>
    public long CurrentCommit()
    {
        var info = default(Native.JobObjectLimitViolationInformation);
        return Native.QueryInformationJobObject(Handle, Native.JobObjectLimitViolationInformationClass, &info, sizeof(Native.JobObjectLimitViolationInformation), out _)
            ? (long)info.JobMemory
            : -1;
    }

    /// <summary>
    /// Limits the job exceeded (<c>JobObjectLimitViolationInformation</c>; AD-0005 section 4): <c>job_memory</c>, <c>cpu_time</c>, <c>io</c>.
    /// </summary>
    public List<string> LimitViolations()
    {
        var info = default(Native.JobObjectLimitViolationInformation);
        return Native.QueryInformationJobObject(Handle, Native.JobObjectLimitViolationInformationClass, &info, sizeof(Native.JobObjectLimitViolationInformation), out _)
            ? JobViolationFlags.Names(info.ViolationLimitFlags)
            : [];
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

/// <summary>
/// The limit flags of <c>JOBOBJECT_LIMIT_VIOLATION_INFORMATION</c> (winnt.h <c>JOB_OBJECT_LIMIT_*</c>) the node reports: job memory 0x200,
/// job time 0x4, job read bytes 0x10000 and job write bytes 0x20000. 0x400 (DIE_ON_UNHANDLED_EXCEPTION) and 0x800 (BREAKAWAY_OK) are
/// never violations.
/// </summary>
public static class JobViolationFlags
{
    private const uint JobTime = 0x00000004;
    private const uint JobMemory = 0x00000200;
    private const uint JobReadBytes = 0x00010000;
    private const uint JobWriteBytes = 0x00020000;

    /// <summary>The names of the limits in a violation flag set (winnt.h <c>JOB_OBJECT_LIMIT_*</c>).</summary>
    public static List<string> Names(uint flags)
    {
        var violations = new List<string>();
        if ((flags & JobMemory) != 0)
        {
            violations.Add("job_memory");
        }

        if ((flags & JobTime) != 0)
        {
            violations.Add("cpu_time");
        }

        if ((flags & (JobReadBytes | JobWriteBytes)) != 0)
        {
            violations.Add("io");
        }

        return violations;
    }
}
