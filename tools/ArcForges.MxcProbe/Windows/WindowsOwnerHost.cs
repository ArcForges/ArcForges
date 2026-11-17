// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.MxcProbe;

[SupportedOSPlatform("windows")]
internal sealed class WindowsOwnerLaunchException(Exception launchFailure, Exception cleanupFailure, WindowsOwnerHost cleanupOwner)
    : Exception("Background owner launch failed and aggregate cleanup is unresolved; retain the guardian.", new AggregateException(launchFailure, cleanupFailure))
{
    public WindowsOwnerHost CleanupOwner { get; } = cleanupOwner;
}

// This outer holder is the experiment's guardian, NOT the restartable Node or
// terminal client. It never goes away as a side effect of simulating Node loss.
// The background owner owns its separate inner ConPtySession; these two Jobs
// allow the guardian to independently observe owner-loss descendant cleanup.
[SupportedOSPlatform("windows")]
internal sealed class WindowsOwnerHost : IAsyncDisposable
{
    private const uint JobFlags = 0x2000 | 0x200 | 0x8;
    private const uint CpuFlags = 0x1 | 0x4;
    private readonly SafeFileHandle _job;
    private SafeFileHandle? _process;
    private bool _disposed;

    private WindowsOwnerHost(SafeFileHandle job) => _job = job;

    public uint ProcessId { get; private set; }
    public long ProcessCreationFileTime { get; private set; }
    public DateTimeOffset ProcessStartTimeUtc => DateTimeOffset.FromFileTime(ProcessCreationFileTime).ToUniversalTime();

    public static WindowsOwnerHost Start(string stage, string privateOwnerConfigPath, ConPtyLimits aggregateLimits)
    {
        ArgumentNullException.ThrowIfNull(aggregateLimits);
        if (aggregateLimits.CpuRate is < 1 or > 10_000 || aggregateLimits.MemoryBytes is < 16_777_216 or > 2_147_483_648
            || aggregateLimits.ProcessLimit is < 1 or > 64)
            throw new ArgumentOutOfRangeException(nameof(aggregateLimits), "Probe limits require CPU 1..10000, commit 16MiB..2GiB and processes 1..64.");
        ValidatePath(stage, directory: true);
        ValidatePath(privateOwnerConfigPath, directory: false);
        var executable = Path.Combine(stage, "arcforges-mxc-probe.exe");
        ValidatePath(executable, directory: false);
        WindowsPolicy.VerifyPrivateFile(privateOwnerConfigPath);
        var control = Path.GetDirectoryName(privateOwnerConfigPath)!;
        WindowsPolicy.VerifyPrivateControl(control);
        // Keep no-write/no-delete leases until the fixed-role child is resumed.
        // Stage verification is also repeated here; no arbitrary host executable.
        using var executableLease = File.Open(executable, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var configLease = File.Open(privateOwnerConfigPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        Program.ValidateStage(Path.Combine(stage, "mxc-manifest.json"));
        var job = ConPtyNative.CreateJobObject(0, null);
        if (job.IsInvalid)
        {
            var error = Error("Create guardian aggregate Job");
            job.Dispose();
            throw error;
        }

        var host = new WindowsOwnerHost(job);
        try
        {
            host.SetLimits(aggregateLimits);
            host.Launch(executable, privateOwnerConfigPath, control, aggregateLimits);
            return host;
        }
        catch (Exception launchFailure)
        {
            try { host.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
            catch (Exception cleanupFailure) { throw new WindowsOwnerLaunchException(launchFailure, cleanupFailure, host); }
            throw;
        }
    }

    private unsafe void Launch(string executable, string config, string control, ConPtyLimits expected)
    {
        var startup = new ConPtyNative.StartupInfoEx { Info = new() { Cb = sizeof(ConPtyNative.StartupInfoEx) } };
        var command = (Quote(executable) + " --windows-owner " + Quote(config) + "\0").ToCharArray();
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        // A trusted background owner also gets a closed environment, rather than
        // incidentally inheriting the driver/CI's credentials or global helpers.
        var environment = ("PATH=" + system + "\0SystemRoot=" + windows + "\0TEMP=" + control + "\0TMP=" + control
            + "\0WINDIR=" + windows + "\0\0").ToCharArray();
        ConPtyNative.ProcessInformation process;
        fixed (char* commandPointer = command)
        fixed (char* environmentPointer = environment)
        {
            // SUSPENDED | UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT |
            // NO_WINDOW. No shell, breakaway, stdio or inheritable handle list.
            if (!ConPtyNative.CreateProcess(executable, commandPointer, 0, 0, false, 0x4 | 0x400 | 0x80000 | 0x08000000,
                environmentPointer, Path.GetDirectoryName(executable)!, ref startup, out process))
                throw Error("Create suspended background owner");
        }

        _process = new SafeFileHandle(process.Process, ownsHandle: true);
        using var thread = new SafeFileHandle(process.Thread, ownsHandle: true);
        ProcessId = process.ProcessId;
        if (!ConPtyNative.GetProcessTimes(_process, out var creation, out _, out _, out _)) throw Error("Read held owner creation identity");
        ProcessCreationFileTime = creation;
        if (!ConPtyNative.AssignProcessToJobObject(_job, _process)) throw Error("Assign suspended owner to aggregate Job");
        if (!ConPtyNative.IsProcessInJob(_process.DangerousGetHandle(), _job.DangerousGetHandle(), out var member))
            throw Error("Read back owner aggregate membership");
        if (!member) throw new InvalidOperationException("Suspended owner is absent from its aggregate Job.");
        var observed = ObserveAggregate();
        RequireLimits(observed, expected);
        if (!observed.ProcessIds.Contains(ProcessId)) throw new InvalidOperationException("Independent aggregate enumeration did not contain the suspended owner.");
        if (ConPtyNative.ResumeThread(thread.DangerousGetHandle()) == uint.MaxValue) throw Error("Resume admitted background owner");
    }

    private unsafe void SetLimits(ConPtyLimits limits)
    {
        var extended = new ConPtyNative.ExtendedLimits
        {
            Basic = new() { LimitFlags = JobFlags, ActiveProcessLimit = limits.ProcessLimit },
            JobMemoryLimit = checked((nuint)limits.MemoryBytes),
        };
        var cpu = new ConPtyNative.CpuLimits { Flags = CpuFlags, Rate = limits.CpuRate };
        uint ui = 0;
        if (!ConPtyNative.SetInformationJobObject(_job, 9, &extended, sizeof(ConPtyNative.ExtendedLimits))) throw Error("Apply guardian memory/process/kill-on-close limits");
        if (!ConPtyNative.SetInformationJobObject(_job, 15, &cpu, sizeof(ConPtyNative.CpuLimits))) throw Error("Apply guardian CPU hard cap");
        if (!ConPtyNative.SetInformationJobObject(_job, 4, &ui, sizeof(uint))) throw Error("Set guardian Job without UI restrictions");
        RequireLimits(ObserveAggregate(), limits); // Before even the trusted worker executes.
    }

    private static void RequireLimits(ConPtyJobObservation actual, ConPtyLimits expected)
    {
        if (actual.Limits != expected || actual.LimitFlags != JobFlags || actual.CpuFlags != CpuFlags || actual.UiRestrictions != 0)
            throw new InvalidOperationException("Guardian Job readback differs from its no-UI/no-breakaway resource policy.");
    }

    public unsafe ConPtyJobObservation ObserveAggregate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var limits = default(ConPtyNative.ExtendedLimits);
        var cpu = default(ConPtyNative.CpuLimits);
        var accounting = default(ConPtyNative.Accounting);
        uint ui = 0;
        if (!ConPtyNative.QueryInformationJobObject(_job, 9, &limits, sizeof(ConPtyNative.ExtendedLimits), out _)
            || !ConPtyNative.QueryInformationJobObject(_job, 15, &cpu, sizeof(ConPtyNative.CpuLimits), out _)
            || !ConPtyNative.QueryInformationJobObject(_job, 1, &accounting, sizeof(ConPtyNative.Accounting), out _)
            || !ConPtyNative.QueryInformationJobObject(_job, 4, &ui, sizeof(uint), out _)) throw Error("Observe held guardian aggregate Job");
        const int capacity = 256;
        var list = stackalloc byte[8 + (capacity * sizeof(nuint))];
        if (!ConPtyNative.QueryInformationJobObject(_job, 3, list, 8 + (capacity * sizeof(nuint)), out _)) throw Error("Enumerate held guardian aggregate Job");
        var count = *(uint*)(list + 4);
        if (count > capacity) throw new InvalidDataException("Guardian aggregate enumeration exceeded its bounded capacity.");
        var ids = new uint[count];
        for (var index = 0; index < count; index++) ids[index] = checked((uint)((nuint*)(list + 8))[index]);
        return new(new(cpu.Rate, (ulong)limits.JobMemoryLimit, limits.Basic.ActiveProcessLimit), limits.Basic.LimitFlags,
            cpu.Flags, ui, accounting.TotalProcesses, accounting.ActiveProcesses, ids, accounting.UserTime, accounting.KernelTime, (ulong)limits.PeakJobMemory);
    }

    // Only this exact held owner process is terminated. Do not use the outer
    // Job as a substitute for demonstrating the inner owner's kill-on-close.
    public async Task KillOwnerAsync(TimeSpan timeout)
    {
        ValidateTimeout(timeout);
        ObjectDisposedException.ThrowIf(_disposed, this);
        var process = _process ?? throw new InvalidOperationException("The background owner was not created.");
        TerminateHeldOwner(process);
        await WaitOwnerAsync(process, Stopwatch.StartNew(), timeout).ConfigureAwait(false);
    }

    public async Task<ConPtyJobObservation> WaitEmptyAsync(TimeSpan timeout)
    {
        ValidateTimeout(timeout);
        ObjectDisposedException.ThrowIf(_disposed, this);
        return await WaitEmptyCoreAsync(Stopwatch.StartNew(), timeout).ConfigureAwait(false);
    }

    private async Task<ConPtyJobObservation> WaitEmptyCoreAsync(Stopwatch watch, TimeSpan timeout)
    {
        while (true)
        {
            var actual = ObserveAggregate();
            if (actual.ActiveProcesses == 0 && actual.ProcessIds.Length == 0) return actual;
            await PauseAsync(watch, timeout).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        // Cleanup is distinct from KillOwnerAsync's test operation. The guardian
        // can explicitly end the exact owned aggregate and a still-suspended
        // create-success/assignment-failure process, never a PID-only target.
        var watch = Stopwatch.StartNew();
        var timeout = TimeSpan.FromSeconds(10);
        if (!ConPtyNative.TerminateJobObject(_job, 125)) throw Error("Terminate held guardian aggregate Job");
        if (_process is { } process)
        {
            TerminateHeldOwner(process);
            await WaitOwnerAsync(process, watch, timeout).ConfigureAwait(false);
        }

        _ = await WaitEmptyCoreAsync(watch, timeout).ConfigureAwait(false);
        // Any query/termination/deadline failure above deliberately leaves both
        // handles retained for diagnosis and an explicit retry by the caller.
        _process?.Dispose();
        _job.Dispose();
        _disposed = true;
    }

    private static void TerminateHeldOwner(SafeFileHandle process)
    {
        var wait = ConPtyNative.WaitForSingleObject(process, 0);
        if (wait == 0) return;
        if (wait != 258) throw Error("Observe held owner process");
        if (!ConPtyNative.TerminateProcess(process, 125))
        {
            var error = Error("Terminate held owner process");
            if (ConPtyNative.WaitForSingleObject(process, 0) != 0) throw error;
        }
    }

    private static async Task WaitOwnerAsync(SafeFileHandle process, Stopwatch watch, TimeSpan timeout)
    {
        while (true)
        {
            var wait = ConPtyNative.WaitForSingleObject(process, 0);
            if (wait == 0) return;
            if (wait != 258) throw Error("Wait for held owner process");
            await PauseAsync(watch, timeout).ConfigureAwait(false);
        }
    }

    private static async Task PauseAsync(Stopwatch watch, TimeSpan timeout)
    {
        var remaining = timeout - watch.Elapsed;
        if (remaining <= TimeSpan.Zero) throw new TimeoutException("Guardian cleanup deadline expired; retain native ownership and mark cleanup unresolved.");
        await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(10, remaining.TotalMilliseconds))).ConfigureAwait(false);
    }

    private static void ValidateTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(2)) throw new ArgumentOutOfRangeException(nameof(timeout));
    }

    private static void ValidatePath(string path, bool directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path) || path.Contains('"', StringComparison.Ordinal) || path.Contains('\0', StringComparison.Ordinal)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 || (directory ? !Directory.Exists(path) : !File.Exists(path)))
            throw new ArgumentException("Expected an existing absolute non-reparse stage/control path.", nameof(path));
    }

    private static string Quote(string path) => "\"" + path + new string('\\', path.Length - path.TrimEnd('\\').Length) + "\"";
    private static Win32Exception Error(string operation) => new(Marshal.GetLastPInvokeError(), operation);
}
