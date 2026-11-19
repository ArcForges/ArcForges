// SPDX-License-Identifier: AGPL-3.0-only

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Windows.Mxc;

/// <summary>Native Windows Run limits, in hundredths of a percent, commit bytes and active processes.</summary>
public sealed record WindowsMxcJobLimits(int CpuRate, long CommitBytes, int MaxProcesses);

/// <summary>A sample of an exact held Job, including independent process count and membership queries.</summary>
public sealed record WindowsMxcJobObservation(int ActiveProcesses, int[] ProcessIds, JobAccounting Accounting)
{
    /// <summary>Both native queries reported an empty Job.</summary>
    public bool Empty => ActiveProcesses == 0 && ProcessIds.Length == 0;
}

/// <summary>An anonymous kill-on-close Job used by the pinned Windows MXC composition.</summary>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsMxcJob : IDisposable
{
    private const int BasicUiRestrictions = 4;
    private const uint ScopedLimitFlags = Native.JobObjectLimitJobMemory | Native.JobObjectLimitActiveProcess | Native.JobObjectLimitKillOnJobClose;
    private const uint HardCpuFlags = Native.CpuRateControlEnable | Native.CpuRateControlHardCap;
    private const uint ForcedExitCode = 0xc000013a;
    private readonly JobObject _job;

    private WindowsMxcJob(JobObject job) => _job = job;

    internal SafeKernelHandle Handle => _job.Handle;
    internal long RecoveryToken => Handle.DangerousGetHandle().ToInt64();

    /// <summary>Creates the whole Run's resource scope or its separately terminable payload scope.</summary>
    public static WindowsMxcJob Create(WindowsMxcJobLimits? limits)
    {
        var job = new WindowsMxcJob(JobObject.Create(null));
        try
        {
            if (limits is not null)
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(limits.CpuRate, 1);
                ArgumentOutOfRangeException.ThrowIfGreaterThan(limits.CpuRate, 10_000);
                ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limits.CommitBytes);
                ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limits.MaxProcesses);
                job._job.SetCpuHardCap(limits.CpuRate);
            }

            job._job.SetLimits(limits?.CommitBytes ?? 0, limits?.MaxProcesses, killOnClose: true);
            job.RequireLimits(limits);
            return job;
        }
        catch
        {
            job.Dispose();
            throw;
        }
    }

    /// <summary>Takes ownership of a Job capability delivered over the authenticated bootstrap channel.</summary>
    public static WindowsMxcJob Accept(long value, WindowsMxcJobLimits limits)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
        var job = new WindowsMxcJob(JobObject.FromHandle(checked((nint)value), null));
        try
        {
            job.RequireNoninheritable();
            job.RequireLimits(limits);
            using var current = ProcessInfo.Open(Environment.ProcessId)
                ?? throw Error("Open the current supervisor process");
            job.RequireMember(current);
            job.RequireOnly(Environment.ProcessId);
            return job;
        }
        catch
        {
            job.Dispose();
            throw;
        }
    }

    internal static WindowsMxcJob AcceptStandby(long value, WindowsMxcJob witness)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
        if (value == witness.RecoveryToken)
        {
            throw new InvalidDataException("The Windows standby Job capability reused the witness handle.");
        }

        var standby = new WindowsMxcJob(JobObject.FromHandle(checked((nint)value), null));
        try
        {
            standby.RequireNoninheritable();
            if (!Native.CompareObjectHandles(witness.Handle, standby.Handle))
            {
                throw Error("Verify the standby and original Run Job are the same object");
            }

            return standby;
        }
        catch
        {
            standby.Dispose();
            throw;
        }
    }

    internal static WindowsMxcJob Rebind(SafeKernelHandle owner, long remoteHandle)
    {
        var value = WindowsMxcProcess.DuplicateJobFromOwner(owner, remoteHandle);
        var job = new WindowsMxcJob(JobObject.FromHandle(value, null));
        try
        {
            job.RequireNoninheritable();
            _ = job.ReadResourceLimits();
            job.RequireMember(owner);
            return job;
        }
        catch
        {
            job.Dispose();
            throw;
        }
    }

    private void RequireNoninheritable()
    {
        if (!GetHandleInformation(Handle, out var handleFlags))
        {
            throw Error("Read the transferred Run Job handle flags");
        }

        if ((handleFlags & Native.HandleFlagInherit) != 0)
        {
            throw new InvalidDataException("The transferred Run Job capability is inheritable.");
        }
    }

    /// <summary>Verifies the exact current limit values, including no UI or breakaway flags.</summary>
    public void RequireLimits(WindowsMxcJobLimits? limits)
    {
        var flags = limits is null ? Native.JobObjectLimitKillOnJobClose : ScopedLimitFlags;
        var cpuFlags = limits is null ? 0 : HardCpuFlags;
        if (ReadUiRestrictions() != 0 || _job.Limits() != (flags, limits?.CommitBytes ?? 0, limits?.MaxProcesses ?? 0)
            || _job.CpuRateControl() != (cpuFlags, (uint)(limits?.CpuRate ?? 0)))
        {
            throw new InvalidDataException("Run Job resource, UI or lifetime readback differs from its admitted settings.");
        }
    }

    internal WindowsMxcJobLimits ReadResourceLimits()
    {
        var extended = _job.Limits();
        var cpu = _job.CpuRateControl();
        if (ReadUiRestrictions() != 0 || extended.Flags != ScopedLimitFlags || extended.JobMemoryLimit <= 0 || extended.ActiveProcessLimit <= 0
            || cpu.Flags != HardCpuFlags || cpu.Value is < 1 or > 10_000)
        {
            throw new InvalidDataException("windows_run_job_limits_unverified");
        }

        return new WindowsMxcJobLimits((int)cpu.Value, extended.JobMemoryLimit, extended.ActiveProcessLimit);
    }

    internal static ulong? NormalizeResourceLimit(RunResourceDimension dimension, ulong value, uint processors) => dimension switch
    {
        RunResourceDimension.Cpu when WindowsMxcProcess.ResourceCpuRate(value, processors) is int rate =>
            WindowsMxcProcess.ResourceCpuMillicores(rate, processors),
        RunResourceDimension.Memory when value is > 0 and <= long.MaxValue && value >= (ulong)Environment.SystemPageSize =>
            value - (value % (ulong)Environment.SystemPageSize),
        _ => null,
    };

    internal RunResourceWriteResult ApplyResourceLimit(RunResourceDimension dimension, ulong value, uint processors)
    {
        if (dimension is not (RunResourceDimension.Cpu or RunResourceDimension.Memory))
        {
            return new(RunResourceWriteStatus.Unsupported, Reason: "windows_run_limit_dimension_unsupported");
        }

        if (NormalizeResourceLimit(dimension, value, processors) is not { } normalized)
        {
            return new(RunResourceWriteStatus.Unsupported, Reason: "windows_run_limit_unrepresentable");
        }

        var previous = ReadResourceLimits();
        if (dimension == RunResourceDimension.Cpu)
        {
            var rate = WindowsMxcProcess.ResourceCpuRate(value, processors)!.Value;
            if (rate != previous.CpuRate)
            {
                _job.SetCpuHardCap(rate);
            }
        }
        else
        {
            if (normalized < (ulong)previous.CommitBytes)
            {
                // Live committed usage is unproved. A working set or historic peak cannot authorize tightening.
                return new(RunResourceWriteStatus.Unsupported, Reason: "windows_commit_reduction_unverified");
            }

            if (normalized != (ulong)previous.CommitBytes)
            {
                _job.SetLimits((long)normalized, previous.MaxProcesses, killOnClose: true);
            }
        }

        return new(RunResourceWriteStatus.Applied, normalized);
    }

    private unsafe uint ReadUiRestrictions()
    {
        var restrictions = 0u;
        return Native.QueryInformationJobObject(Handle, BasicUiRestrictions, &restrictions, sizeof(uint), out _)
            ? restrictions
            : throw Error("Read Run Job UI restrictions");
    }

    /// <summary>Requires membership from the exact held native process handle.</summary>
    public void RequireMember(LaunchedProcess process)
    {
        ArgumentNullException.ThrowIfNull(process);
        RequireMember(process.Process);
    }

    internal void RequireMember(SafeKernelHandle process)
    {
        if (!Native.IsProcessInJob(process, Handle.DangerousGetHandle(), out var contains))
        {
            throw Error("Read process membership in the Run Job");
        }

        if (!contains)
        {
            throw new InvalidDataException("The held process is outside its Run Job.");
        }
    }

    /// <summary>Reads the current count and list separately to establish drain evidence.</summary>
    public WindowsMxcJobObservation Observe()
    {
        var accounting = _job.Accounting();
        return new(accounting.ActiveProcesses, _job.ProcessIds(), accounting);
    }

    internal unsafe RunResourceObservation? ObserveResources()
    {
        var handle = Handle;
        var retained = false;
        try
        {
            // Hold the original native Job across the membership checks that take a raw HANDLE.
            handle.DangerousAddRef(ref retained);
            var basic = default(Native.JobObjectBasicAndIoAccountingInformation);
            var hasBasic = Native.QueryInformationJobObject(handle, Native.JobObjectBasicAndIoAccountingInformationClass,
                &basic, sizeof(Native.JobObjectBasicAndIoAccountingInformation), out _);
            var extended = default(Native.JobObjectExtendedLimitInformation);
            var hasExtended = Native.QueryInformationJobObject(handle, Native.JobObjectExtendedLimitInformationClass,
                &extended, sizeof(Native.JobObjectExtendedLimitInformation), out _);
            if (!hasBasic && !hasExtended)
            {
                return null;
            }

            var sample = new RunResourceObservation(RunMemoryAccounting.WindowsCommit)
            {
                CumulativeCpuUsec = hasBasic && basic.BasicInfo.TotalUserTime >= 0 && basic.BasicInfo.TotalKernelTime >= 0
                    ? ((ulong)basic.BasicInfo.TotalUserTime + (ulong)basic.BasicInfo.TotalKernelTime) / 10 : null,
                PeakMemoryBytes = hasExtended ? extended.PeakJobMemoryUsed : null,
            };
            if (!hasBasic)
            {
                return sample;
            }

            int[] members;
            try
            {
                members = _job.ProcessIds();
            }
            catch (Win32Exception)
            {
                return sample;
            }

            var identities = new HashSet<int>(members);
            if (members.Length != basic.BasicInfo.ActiveProcesses || identities.Count != members.Length
                || identities.Any(pid => pid <= 0))
            {
                return sample;
            }

            sample = sample with { ProcessCount = basic.BasicInfo.ActiveProcesses };
            return sample with { ResidentBytes = ResidentBytes(members, identities, handle.DangerousGetHandle()) };
        }
        catch (ObjectDisposedException)
        {
            return null;
        }
        finally
        {
            if (retained)
            {
                handle.DangerousRelease();
            }
        }
    }

    private ulong? ResidentBytes(int[] members, HashSet<int> identities, nint job)
    {
        var processes = new List<SafeKernelHandle>(members.Length);
        try
        {
            ulong bytes = 0;
            foreach (var pid in members)
            {
                var process = ProcessInfo.Open(pid);
                if (process is null)
                {
                    return null;
                }

                processes.Add(process);
                if (!Native.IsProcessInJob(process, job, out var isMember) || !isMember
                    || ProcessInfo.CreationFileTime(process) <= 0 || !ProcessInfo.IsRunning(process)
                    || WindowsResourceSampler.PrivateResidentBytes(process) is not { } workingSet
                    || workingSet > ulong.MaxValue - bytes)
                {
                    return null;
                }

                bytes += workingSet;
            }

            // The open handles pin process identities through the second membership read.
            var current = _job.ProcessIds();
            return current.Length == members.Length && identities.SetEquals(current) && processes.All(ProcessInfo.IsRunning)
                ? bytes : null;
        }
        catch (Win32Exception)
        {
            return null;
        }
        finally
        {
            foreach (var process in processes)
            {
                process.Dispose();
            }
        }
    }

    /// <summary>Verifies only the exact known process IDs are in the Job.</summary>
    public WindowsMxcJobObservation RequireOnly(params int[] members)
    {
        var value = Observe();
        if (value.ActiveProcesses != members.Length || value.ProcessIds.Length != members.Length
            || !members.All(value.ProcessIds.Contains))
        {
            throw new InvalidDataException("Run Job has unexpected active process membership.");
        }

        return value;
    }

    /// <summary>Waits for an exact scope to be independently verified empty or to contain only its trusted owner.</summary>
    public async ValueTask<WindowsMxcJobObservation> WaitForDrainAsync(int? ownerPid, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var started = Stopwatch.StartNew();
        do
        {
            var value = Observe();
            if (ownerPid is { } owner
                ? value.ActiveProcesses == 1 && value.ProcessIds.Length == 1 && value.ProcessIds[0] == owner
                : value.Empty)
            {
                return value;
            }

            await Task.Delay(20, cancellationToken).ConfigureAwait(false);
        }
        while (started.Elapsed < timeout);

        throw new TimeoutException("The exact Run Job did not prove drain within its cleanup deadline.");
    }

    /// <summary>Forcibly ends all members of the exact held Job.</summary>
    public void Terminate()
    {
        if (!_job.Terminate(ForcedExitCode))
        {
            throw Error("Terminate the exact Run Job");
        }
    }

    /// <summary>Releases this reference. The native last-close contract governs remaining processes.</summary>
    public void Dispose() => _job.Dispose();

    internal static Win32Exception Error(string operation) => new(Marshal.GetLastPInvokeError(), operation + " failed.");

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetHandleInformation(SafeKernelHandle handle, out uint flags);
}
