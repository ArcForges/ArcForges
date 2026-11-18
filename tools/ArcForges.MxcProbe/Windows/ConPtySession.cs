// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.MxcProbe;

internal sealed record ConPtyLimits(uint CpuRate, ulong MemoryBytes, uint ProcessLimit);
internal sealed record ConPtyLaunchOptions(string ExecutorPath, string PrivateConfigPath, string ControlDirectory,
    int Columns, int Rows, ConPtyLimits Limits, int ReplayBytes = 262_144, bool PrivateDiagnostics = false);
internal sealed record ConPtyReplay(long StartSequence, long NextSequence, long AvailableFrom, long AvailableUntil,
    long? GapFrom, long? GapUntil, byte[] Data, bool EndOfStream, string? DrainFailure);
internal sealed record ConPtyJobObservation(ConPtyLimits Limits, uint LimitFlags, uint CpuFlags, uint UiRestrictions,
    uint TotalProcesses, uint ActiveProcesses, uint[] ProcessIds, long UserTimeTicks, long KernelTimeTicks, ulong PeakMemoryBytes);
internal sealed record ConPtyExit(uint RawExitCode, string ExitSource, bool JobEmpty, ConPtyJobObservation Job);

internal sealed class ConPtyAssignmentEvidence
{
    public uint WorkerProcessId { get; set; }
    public DateTimeOffset WorkerCreatedUtc { get; set; }
    public uint CandidateProcessId { get; set; }
    public DateTimeOffset CandidateCreatedUtc { get; set; }
    public bool WorkerResumed { get; set; }
    public bool CandidateResumed { get; set; }
    public bool AssignmentRejected { get; set; }
    public int NativeErrorCode { get; set; }
    public uint? CandidateExitCode { get; set; }
    public bool CleanupCompleted { get; set; }
    public ConPtyJobObservation? ParentBeforeAssignment { get; set; }
    public ConPtyJobObservation? ParentAfterCleanup { get; set; }
    public ConPtyJobObservation? CandidateAfterCleanup { get; set; }
}

[SupportedOSPlatform("windows")]
internal sealed class ConPtyLaunchException(Exception launchFailure, Exception cleanupFailure, ConPtySession cleanupOwner)
    : Exception("Executor launch failed and native cleanup remains unresolved; retain the cleanup owner.", new AggregateException(launchFailure, cleanupFailure))
{
    public ConPtySession CleanupOwner { get; } = cleanupOwner;
}

// A bounded experimental owner for the unchanged, stage-verified executor. The
// caller compiles/owns the private request and authenticates terminal clients;
// this primitive never accepts a payload command, backend override or SDK HPCON.
[SupportedOSPlatform("windows")]
internal sealed class ConPtySession : IAsyncDisposable
{
    private const uint JobFlags = 0x2000 | 0x200 | 0x8; // kill-on-close, aggregate commit, process count; no breakaway.
    private const uint CpuFlags = 0x1 | 0x4; // enabled hard cap, in 1/100 percent.
    private readonly SafeFileHandle _job;
    private readonly NamedPipeServerStream _input;
    private readonly NamedPipeServerStream _output;
    private readonly byte[] _replay;
    private readonly object _gate = new();
    private readonly SemaphoreSlim _inputGate = new(1, 1);
    private readonly CancellationTokenSource _inputCancellation = new();
    private readonly CancellationTokenSource _drainCancellation = new();
    private readonly Task _drain;
    private SafeFileHandle? _process;
    private bool _assignedToJob;
    private AssignmentProbeState? _assignmentProbe;
    private nint _console;
    private long _sequence;
    private bool _eof;
    private string? _drainFailure;
    private Task? _consoleClose;
    private bool _disposed;

    private ConPtySession(SafeFileHandle job, NamedPipeServerStream input, NamedPipeServerStream output, int replayBytes)
    {
        _job = job;
        _input = input;
        _output = output;
        _replay = new byte[replayBytes];
        _drain = DrainAsync(); // Always active, including with no attached client.
    }

    public uint ProcessId { get; private set; }
    public DateTimeOffset ProcessStartTimeUtc { get; private set; }
    public double SpawnMs { get; private set; }
    public bool InheritedJob { get; private set; }
    public string ExitSource { get; } = "official_executor";

    public uint? GetExecutorExitCode()
    {
        var process = _process ?? throw new InvalidOperationException("Executor creation did not complete.");
        var wait = ConPtyNative.WaitForSingleObject(process, 0);
        if (wait == 258) return null;
        if (wait != 0) throw Error("Observe executor process handle");
        if (!ConPtyNative.GetExitCodeProcess(process, out var code)) throw Error("Read official executor exit code");
        return code;
    }

    public void Resize(int columns, int rows)
    {
        ValidateSize(columns, rows); // Reject before narrowing or calling native APIs.
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_consoleClose is not null) throw new InvalidOperationException("The pseudoconsole is closing.");
            Marshal.ThrowExceptionForHR(ConPtyNative.ResizePseudoConsole(_console, new((short)columns, (short)rows)));
        }
    }

    public async Task WriteInputAsync(ReadOnlyMemory<byte> data, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        ValidateTimeout(timeout);
        if (data.Length is < 1 or > 32_768) throw new ArgumentOutOfRangeException(nameof(data), "Terminal input must contain 1..32768 bytes.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _inputCancellation.Token);
        deadline.CancelAfter(timeout);
        await _inputGate.WaitAsync(deadline.Token).ConfigureAwait(false);
        try
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (_consoleClose is not null) throw new InvalidOperationException("The pseudoconsole is closing.");
            }
            await _input.WriteAsync(data, deadline.Token).ConfigureAwait(false);
        }
        finally { _inputGate.Release(); }
    }

    // ETX is terminal input, not a promise of a signal/graceful exit. The caller
    // owns the grace deadline and explicit escalation to the exact outer Job.
    public Task SendEtxAsync(TimeSpan timeout, CancellationToken cancellationToken = default) =>
        WriteInputAsync(new byte[] { 3 }, timeout, cancellationToken);

    public ConPtyReplay ReadReplay(long afterSequence, int maxBytes = 32_768)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(afterSequence, 0);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBytes, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxBytes, 32_768);
        lock (_gate)
        {
            if (afterSequence > _sequence) throw new ArgumentOutOfRangeException(nameof(afterSequence), "The cursor is ahead of observed terminal output.");
            var availableFrom = Math.Max(0, _sequence - _replay.Length);
            var start = Math.Max(afterSequence, availableFrom);
            var length = checked((int)Math.Min(maxBytes, _sequence - start));
            var data = new byte[length];
            var offset = (int)(start % _replay.Length);
            var first = Math.Min(length, _replay.Length - offset);
            _replay.AsSpan(offset, first).CopyTo(data);
            _replay.AsSpan(0, length - first).CopyTo(data.AsSpan(first));
            return new(start, start + length, availableFrom, _sequence, afterSequence < availableFrom ? afterSequence : null,
                afterSequence < availableFrom ? availableFrom : null, data, _eof && start + length == _sequence, _drainFailure);
        }
    }

    public static ConPtySession Start(ConPtyLaunchOptions options) => StartCore(options, null, null);

    // Exact experimental owner-loss boundary, after native admission readback
    // and before ResumeThread. This is not a product extensibility callback.
    internal static ConPtySession StartForOwnerPhase(ConPtyLaunchOptions options, Action<ConPtySession> beforeResume)
    {
        ArgumentNullException.ThrowIfNull(beforeResume);
        return StartCore(options, beforeResume, null);
    }

    internal static ConPtyAssignmentEvidence ProbeParentAssignmentFailure(ConPtyLaunchOptions options)
    {
        var evidence = new ConPtyAssignmentEvidence();
        try
        {
            var unexpected = StartCore(options, null, evidence);
            unexpected.DisposeAsync().AsTask().GetAwaiter().GetResult();
            throw new InvalidOperationException("The full owned parent unexpectedly admitted an executor.");
        }
        catch (Win32Exception error) when (evidence.AssignmentRejected && evidence.CleanupCompleted && error.NativeErrorCode == evidence.NativeErrorCode)
        {
            return evidence;
        }
    }

    private static ConPtySession StartCore(ConPtyLaunchOptions options, Action<ConPtySession>? beforeResume, ConPtyAssignmentEvidence? assignmentEvidence)
    {
        ArgumentNullException.ThrowIfNull(options);
        ValidateSize(options.Columns, options.Rows);
        ValidateLimits(options.Limits);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.ReplayBytes, 1_024);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.ReplayBytes, 1_048_576);
        ValidatePath(options.ExecutorPath, false);
        ValidatePath(options.PrivateConfigPath, false);
        ValidatePath(options.ControlDirectory, true);
        if (!Path.GetFileName(options.ExecutorPath).Equals("wxc-exec.exe", StringComparison.OrdinalIgnoreCase)
            || !Path.GetDirectoryName(options.PrivateConfigPath)!.Equals(Path.TrimEndingDirectorySeparator(options.ControlDirectory), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Expected the official executor and a request directly inside the private control directory.");

        // Hold no-write/no-delete leases through CreateProcess and admission.
        // Stage validation remains the caller's responsibility for the cohort.
        using var executorLease = File.Open(options.ExecutorPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var policyLease = File.Open(options.PrivateConfigPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        // A fresh private diagnostic only, never an ambient/shared sink. Keep
        // its no-delete lease until launch admission; the executor may append.
        using var diagnosticLease = options.PrivateDiagnostics
            ? new FileStream(Path.Combine(options.ControlDirectory, "executor-diagnostic.log"), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite)
            : null;
        if (Convert.ToHexStringLower(SHA256.HashData(executorLease)) != Program.WindowsNative["wxc-exec.exe"])
            throw new InvalidDataException("The terminal executor differs from the pinned official executor.");

        var job = ConPtyNative.CreateJobObject(0, null);
        if (job.IsInvalid) { job.Dispose(); throw Error("Create outer terminal Job"); }
        NamedPipeServerStream? input = null;
        NamedPipeServerStream? output = null;
        ConPtySession? session = null;
        try
        {
            SetLimits(job, options.Limits);
            using var inputPeer = CreatePipe(PipeDirection.Out, out input);
            using var outputPeer = CreatePipe(PipeDirection.In, out output);
            // Allocate the owner, bounded capture and live drain before native
            // creation; no successful HPCON waits for an allocating hand-off.
            session = new ConPtySession(job, input, output, options.ReplayBytes);
            if (assignmentEvidence is not null)
            {
                session._assignmentProbe = new AssignmentProbeState(assignmentEvidence);
                session._assignmentProbe.Prepare(options);
            }
            var hr = ConPtyNative.CreatePseudoConsole(new((short)options.Columns, (short)options.Rows), inputPeer.SafePipeHandle, outputPeer.SafePipeHandle, 0, out session._console);
            Marshal.ThrowExceptionForHR(hr);
            session.Launch(options, beforeResume);
            return session;
        }
        catch (Exception launchFailure)
        {
            if (session is not null)
            {
                try { session.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
                catch (Exception cleanupFailure) { throw new ConPtyLaunchException(launchFailure, cleanupFailure, session); }
            }
            else { input?.Dispose(); output?.Dispose(); job.Dispose(); }
            throw;
        }
    }

    // Host ends use overlapped I/O, so writes and the perpetual drain are
    // cancellable. ConPTY receives the normal synchronous ends, not a fake PTY.
    private static NamedPipeClientStream CreatePipe(PipeDirection hostDirection, out NamedPipeServerStream server)
    {
        var name = "arcforges-mxc-" + Guid.NewGuid().ToString("N");
        server = new NamedPipeServerStream(name, hostDirection, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4_096, 4_096);
        NamedPipeClientStream? client = null;
        try
        {
            var connected = server.WaitForConnectionAsync();
            client = new NamedPipeClientStream(".", name, hostDirection == PipeDirection.Out ? PipeDirection.In : PipeDirection.Out,
                PipeOptions.None, TokenImpersonationLevel.Anonymous);
            client.Connect(5_000);
            connected.GetAwaiter().GetResult();
            return client;
        }
        catch { client?.Dispose(); server.Dispose(); throw; }
    }

    private unsafe void Launch(ConPtyLaunchOptions options, Action<ConPtySession>? beforeResume)
    {
        var watch = Stopwatch.StartNew();
        if (!ConPtyNative.IsProcessInJob(ConPtyNative.GetCurrentProcess(), 0, out var inherited)) throw Error("Observe inherited Job");
        InheritedJob = inherited;
        nuint bytes = 0;
        _ = ConPtyNative.InitializeProcThreadAttributeList(0, 1, 0, ref bytes);
        var attributes = Marshal.AllocHGlobal((nint)bytes);
        var initialized = false;
        nint thread = 0;
        try
        {
            if (!ConPtyNative.InitializeProcThreadAttributeList(attributes, 1, 0, ref bytes)) throw Error("Initialize ConPTY attributes");
            initialized = true;
            // HPCON is passed by value (not a pointer to the HPCON variable).
            if (!ConPtyNative.UpdateProcThreadAttribute(attributes, 0, 0x20016, (void*)_console, (nuint)sizeof(nint), 0, 0)) throw Error("Bind real pseudoconsole");
            // The owner itself may have redirected stdio. Explicit NULL std
            // handles prevent those defaults crossing into the ConPTY child;
            // ConPTY initializes its console handles instead (DHowett,
            // https://github.com/microsoft/terminal/discussions/15814).
            var startup = new ConPtyNative.StartupInfoEx { Info = new() { Cb = sizeof(ConPtyNative.StartupInfoEx), Flags = 0x100 }, Attributes = attributes };
            var expectedCommand = Quote(options.ExecutorPath) + " --config " + Quote(options.PrivateConfigPath);
            if (options.PrivateDiagnostics) expectedCommand += " --log-file " + Quote(Path.Combine(options.ControlDirectory, "executor-diagnostic.log"));
            var command = (expectedCommand + '\0').ToCharArray();
            var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var environment = ("PATH=\0SystemRoot=" + Directory.GetParent(system)!.FullName + "\0TEMP=" + options.ControlDirectory + "\0TMP=" + options.ControlDirectory + "\0\0").ToCharArray();
            ConPtyNative.ProcessInformation information;
            fixed (char* commandPointer = command)
            fixed (char* environmentPointer = environment)
            {
                // No inherited handles, breakaway, shell, PATH lookup or window.
                if (!ConPtyNative.CreateProcess(options.ExecutorPath, commandPointer, 0, 0, false, 0x4 | 0x400 | 0x80000,
                    environmentPointer, options.ControlDirectory, ref startup, out information)) throw Error("Create suspended official terminal executor");
            }
            _process = new SafeFileHandle(information.Process, true);
            thread = information.Thread;
            ProcessId = information.ProcessId;
            if (!ConPtyNative.GetProcessTimes(_process, out var created, out _, out _, out _)) throw Error("Read executor creation identity");
            ProcessStartTimeUtc = DateTimeOffset.FromFileTime(created);
            if (_assignmentProbe is not null)
            {
                if (ReadCommandLine(_process) != expectedCommand) throw new InvalidOperationException("Assignment probe executor argv differs from the exact private invocation.");
                _assignmentProbe.RejectCandidate(_process, ProcessId, ProcessStartTimeUtc);
            }
            if (!ConPtyNative.AssignProcessToJobObject(_job, _process)) throw Error("Assign suspended executor to owned outer Job");
            _assignedToJob = true;
            if (!ConPtyNative.IsProcessInJob(_process.DangerousGetHandle(), _job.DangerousGetHandle(), out var member) || !member)
                throw new InvalidOperationException("Suspended executor is not in its owned outer Job.");
            var observation = ObserveJob();
            if (observation.ActiveProcesses != 1 || !observation.ProcessIds.Contains(ProcessId) || observation.Limits != options.Limits)
                throw new InvalidOperationException("Pre-resume Job membership or resource readback differs from admission.");
            if (ReadCommandLine(_process) != expectedCommand) throw new InvalidOperationException("Actual official executor command differs from the private-config invocation.");
            beforeResume?.Invoke(this);
            if (ConPtyNative.ResumeThread(thread) != 1) throw Error("Resume admitted terminal executor");
            if (_assignmentProbe is not null) _assignmentProbe.Evidence.CandidateResumed = true;
            SpawnMs = watch.Elapsed.TotalMilliseconds;
        }
        finally
        {
            if (thread != 0) _ = ConPtyNative.CloseHandle(thread);
            if (initialized) ConPtyNative.DeleteProcThreadAttributeList(attributes);
            Marshal.FreeHGlobal(attributes);
        }
    }

    private async Task DrainAsync()
    {
        var buffer = new byte[8_192];
        try
        {
            while (true)
            {
                var count = await _output.ReadAsync(buffer, _drainCancellation.Token).ConfigureAwait(false);
                if (count == 0) break;
                lock (_gate)
                {
                    for (var i = 0; i < count; i++) _replay[(int)((_sequence + i) % _replay.Length)] = buffer[i];
                    _sequence = checked(_sequence + count);
                }
            }
        }
        catch (Exception error) when (error is IOException or OperationCanceledException or ObjectDisposedException)
        {
            // Never copy arbitrary exception/path/output text to a public record.
            lock (_gate) _drainFailure = error.GetType().Name;
        }
        finally { lock (_gate) _eof = true; }
    }

    public ConPtyJobObservation UpdateLimits(ConPtyLimits limits)
    {
        ValidateLimits(limits);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            SetLimits(_job, limits);
            return ObserveJob();
        }
    }

    public ConPtyJobObservation ObserveJob() => ObserveJob(_job);

    private static unsafe ConPtyJobObservation ObserveJob(SafeFileHandle job)
    {
        var extended = default(ConPtyNative.ExtendedLimits);
        var cpu = default(ConPtyNative.CpuLimits);
        var accounting = default(ConPtyNative.Accounting);
        uint ui = 0;
        if (!ConPtyNative.QueryInformationJobObject(job, 9, &extended, sizeof(ConPtyNative.ExtendedLimits), out _)
            || !ConPtyNative.QueryInformationJobObject(job, 15, &cpu, sizeof(ConPtyNative.CpuLimits), out _)
            || !ConPtyNative.QueryInformationJobObject(job, 1, &accounting, sizeof(ConPtyNative.Accounting), out _)
            || !ConPtyNative.QueryInformationJobObject(job, 4, &ui, sizeof(uint), out _)) throw Error("Read owned outer Job");
        if (extended.Basic.LimitFlags != JobFlags || cpu.Flags != CpuFlags || ui != 0)
            throw new InvalidOperationException("Owned Job has unexpected breakaway/UI/resource flags.");
        // The native process limit bounds the list. Allow extra slots for an
        // update racing a terminating former member; never allocate unboundedly.
        const int capacity = 256;
        var list = stackalloc byte[8 + (capacity * sizeof(nuint))];
        if (!ConPtyNative.QueryInformationJobObject(job, 3, list, 8 + (capacity * sizeof(nuint)), out _)) throw Error("Enumerate owned Job descendants");
        var listed = *(uint*)(list + 4);
        if (listed > capacity) throw new InvalidDataException("Owned Job process enumeration exceeded the bounded capacity.");
        var ids = new uint[listed];
        for (var i = 0; i < listed; i++) ids[i] = checked((uint)((nuint*)(list + 8))[i]);
        return new(new(cpu.Rate, (ulong)extended.JobMemoryLimit, extended.Basic.ActiveProcessLimit), extended.Basic.LimitFlags,
            cpu.Flags, ui, accounting.TotalProcesses, accounting.ActiveProcesses, ids, accounting.UserTime, accounting.KernelTime, (ulong)extended.PeakJobMemory);
    }

    public Task<ConPtyExit> WaitAsync(TimeSpan timeout, CancellationToken cancellationToken = default) =>
        WaitCoreAsync(timeout, requireDrainSuccess: true, cancellationToken);

    private async Task<ConPtyExit> WaitCoreAsync(TimeSpan timeout, bool requireDrainSuccess, CancellationToken cancellationToken)
    {
        ValidateTimeout(timeout);
        var watch = Stopwatch.StartNew();
        var process = _process ?? throw new InvalidOperationException("Executor creation did not complete.");
        while (true)
        {
            var wait = ConPtyNative.WaitForSingleObject(process, 0);
            if (wait == 0) break;
            if (wait != 258) throw Error("Observe executor process handle");
            await PauseAsync(watch, timeout, cancellationToken).ConfigureAwait(false);
        }
        if (!ConPtyNative.GetExitCodeProcess(process, out var code)) throw Error("Read official executor exit code");
        ConPtyJobObservation observed;
        while ((observed = ObserveJob()).ActiveProcesses != 0 || observed.ProcessIds.Length != 0)
            await PauseAsync(watch, timeout, cancellationToken).ConfigureAwait(false);
        // Closing HPCON can wait for output. The independent drain stays alive.
        Task close;
        lock (_gate) close = _consoleClose ??= Task.Run(() => ConPtyNative.ClosePseudoConsole(_console), CancellationToken.None);
        _inputCancellation.Cancel();
        await close.WaitAsync(Remaining(watch, timeout), cancellationToken).ConfigureAwait(false);
        await _drain.WaitAsync(Remaining(watch, timeout), cancellationToken).ConfigureAwait(false);
        lock (_gate)
        {
            if (requireDrainSuccess && _drainFailure is not null) throw new IOException("Terminal drain did not complete; preserve the terminal failure observation.");
        }
        return new(code, ExitSource, true, observed);
    }

    public Task<ConPtyExit> ForceStopAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        ValidateTimeout(timeout);
        TerminateOwned();
        return WaitAsync(timeout, cancellationToken);
    }

    private void TerminateOwned()
    {
        if (!ConPtyNative.TerminateJobObject(_job, 125)) throw Error("Terminate exact owned Job");
        // Job termination is asynchronous. Do not race it with a redundant
        // TerminateProcess on an already terminating assigned process. Direct
        // termination is only for create-success/assign-failure while suspended.
        if (!_assignedToJob && _process is { } process && ConPtyNative.WaitForSingleObject(process, 0) == 258
            && !ConPtyNative.TerminateProcess(process, 125))
        {
            var error = Marshal.GetLastPInvokeError();
            // A failed active-process-limit assignment may already be killing
            // this held process. Only actual handle signaling resolves it.
            if (_assignmentProbe?.Evidence.AssignmentRejected != true || ConPtyNative.WaitForSingleObject(process, 1000) != 0)
                throw new Win32Exception(error, "Terminate owned executor handle failed.");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        if (_process is not null)
        {
            TerminateOwned();
            // Terminal trace failure remains observable, but does not prevent
            // releasing handles once native empty/close/EOF were proven.
            var cleanup = await WaitCoreAsync(TimeSpan.FromSeconds(10), requireDrainSuccess: false, CancellationToken.None).ConfigureAwait(false);
            if (_assignmentProbe is not null) _assignmentProbe.Evidence.CandidateAfterCleanup = cleanup.Job;
        }
        else
        {
            Task close;
            lock (_gate) close = _consoleClose ??= _console == 0 ? Task.CompletedTask : Task.Run(() => ConPtyNative.ClosePseudoConsole(_console));
            _inputCancellation.Cancel();
            await close.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            await _drain.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        if (_assignmentProbe is not null)
        {
            if (_process is not null && ConPtyNative.GetExitCodeProcess(_process, out var candidateExit)) _assignmentProbe.Evidence.CandidateExitCode = candidateExit;
            await _assignmentProbe.DisposeAsync().ConfigureAwait(false);
        }
        // On an unresolved cleanup exception retain ownership/handles so the
        // caller can record failure and retry; never fabricate a released scope.
        if (!await _inputGate.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false)) throw new TimeoutException("Owned terminal input did not finish cancellation; retain the cleanup owner.");
        lock (_gate) { _disposed = true; _console = 0; }
        _input.Dispose();
        _output.Dispose();
        _process?.Dispose();
        _job.Dispose();
        _drainCancellation.Dispose();
        _inputCancellation.Dispose();
        _inputGate.Dispose();
    }

    private static unsafe void SetLimits(SafeFileHandle job, ConPtyLimits limits)
    {
        var extended = new ConPtyNative.ExtendedLimits { Basic = new() { LimitFlags = JobFlags, ActiveProcessLimit = limits.ProcessLimit }, JobMemoryLimit = checked((nuint)limits.MemoryBytes) };
        var cpu = new ConPtyNative.CpuLimits { Flags = CpuFlags, Rate = limits.CpuRate };
        if (!ConPtyNative.SetInformationJobObject(job, 9, &extended, sizeof(ConPtyNative.ExtendedLimits))) throw Error("Apply aggregate memory/process/kill-on-close limits");
        if (!ConPtyNative.SetInformationJobObject(job, 15, &cpu, sizeof(ConPtyNative.CpuLimits))) throw Error("Apply Job CPU hard cap");
        var actual = default(ConPtyNative.ExtendedLimits);
        var actualCpu = default(ConPtyNative.CpuLimits);
        if (!ConPtyNative.QueryInformationJobObject(job, 9, &actual, sizeof(ConPtyNative.ExtendedLimits), out _)
            || !ConPtyNative.QueryInformationJobObject(job, 15, &actualCpu, sizeof(ConPtyNative.CpuLimits), out _)) throw Error("Read applied Job limits");
        if (actual.Basic.LimitFlags != JobFlags || actual.Basic.ActiveProcessLimit != limits.ProcessLimit
            || (ulong)actual.JobMemoryLimit != limits.MemoryBytes || actualCpu.Flags != CpuFlags || actualCpu.Rate != limits.CpuRate)
            throw new InvalidOperationException("Native Job limit readback differs from the requested resource boundary.");
    }

    private static async Task PauseAsync(Stopwatch watch, TimeSpan timeout, CancellationToken cancellationToken) =>
        await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(10, Remaining(watch, timeout).TotalMilliseconds)), cancellationToken).ConfigureAwait(false);

    private static TimeSpan Remaining(Stopwatch watch, TimeSpan timeout) => watch.Elapsed < timeout
        ? timeout - watch.Elapsed : throw new TimeoutException("Owned executor/Job/terminal drain exceeded its deadline; cleanup remains unresolved.");

    private static void ValidateTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(2)) throw new ArgumentOutOfRangeException(nameof(timeout));
    }

    private static void ValidateLimits(ConPtyLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (limits.CpuRate is < 1 or > 10_000 || limits.MemoryBytes is < 16_777_216 or > 2_147_483_648 || limits.ProcessLimit is < 1 or > 64)
            throw new ArgumentOutOfRangeException(nameof(limits), "Probe limits require CPU 1..10000, commit 16MiB..2GiB and processes 1..64.");
    }

    private static void ValidateSize(int columns, int rows)
    {
        if (columns is < 1 or > short.MaxValue) throw new ArgumentOutOfRangeException(nameof(columns));
        if (rows is < 1 or > short.MaxValue) throw new ArgumentOutOfRangeException(nameof(rows));
    }

    private static void ValidatePath(string path, bool directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path) || path.Contains('"', StringComparison.Ordinal) || path.Contains('\0', StringComparison.Ordinal)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 || (directory ? !Directory.Exists(path) : !File.Exists(path)))
            throw new ArgumentException("Expected an existing absolute non-reparse native/control path.", nameof(path));
    }

    // Paths cannot contain literal quotes, but trailing backslashes still need
    // the Windows argv quoting rule when enclosed in quotes.
    private static string Quote(string path) => "\"" + path + new string('\\', path.Length - path.TrimEnd('\\').Length) + "\"";

    private static unsafe string ReadCommandLine(SafeFileHandle process)
    {
        const int capacity = 65_536;
        var buffer = Marshal.AllocHGlobal(capacity);
        try
        {
            if (ConPtyNative.NtQueryInformationProcess(process, 60, buffer, capacity, out _) != 0)
                throw new InvalidOperationException("Unable to read back owned official executor argv.");
            var text = (ConPtyNative.UnicodeString*)buffer;
            if (text->Length % 2 != 0 || text->Buffer < buffer || text->Buffer + text->Length > buffer + capacity)
                throw new InvalidDataException("Invalid owned executor command-line readback.");
            return Marshal.PtrToStringUni(text->Buffer, text->Length / 2) ?? "";
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static Win32Exception Error(string operation) => new(Marshal.GetLastPInvokeError(), operation + " failed.");

    private sealed class AssignmentProbeState(ConPtyAssignmentEvidence evidence) : IAsyncDisposable
    {
        private SafeFileHandle? _parent;
        private SafeFileHandle? _worker;
        private bool _workerAssigned;
        public ConPtyAssignmentEvidence Evidence { get; } = evidence;

        internal unsafe void Prepare(ConPtyLaunchOptions options)
        {
            _parent = ConPtyNative.CreateJobObject(0, null);
            if (_parent.IsInvalid) throw Error("Create owned assignment test Job");
            SetLimits(_parent, options.Limits with { ProcessLimit = 1 });
            var executable = Path.Combine(Path.GetDirectoryName(options.ExecutorPath)!, "arcforges-mxc-probe.exe");
            ValidatePath(executable, false);
            var command = (Quote(executable) + " --windows-workload exit 0\0").ToCharArray();
            var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var environment = ("PATH=\0SystemRoot=" + Directory.GetParent(system)!.FullName + "\0\0").ToCharArray();
            var startup = new ConPtyNative.StartupInfoEx { Info = new() { Cb = sizeof(ConPtyNative.StartupInfoEx), Flags = 0x100 } };
            nint thread = 0;
            try
            {
                ConPtyNative.ProcessInformation information;
                fixed (char* commandPointer = command)
                fixed (char* environmentPointer = environment)
                {
                    if (!ConPtyNative.CreateProcess(executable, commandPointer, 0, 0, false, 0x4 | 0x400 | 0x80000 | 0x8000000,
                        environmentPointer, options.ControlDirectory, ref startup, out information)) throw Error("Create suspended assignment test worker");
                }
                thread = information.Thread;
                _worker = new SafeFileHandle(information.Process, true);
                Evidence.WorkerProcessId = information.ProcessId;
                if (!ConPtyNative.GetProcessTimes(_worker, out var created, out _, out _, out _)) throw Error("Read assignment worker creation identity");
                Evidence.WorkerCreatedUtc = DateTimeOffset.FromFileTime(created);
                if (!ConPtyNative.AssignProcessToJobObject(_parent, _worker)) throw Error("Assign suspended test worker");
                _workerAssigned = true;
                if (!ConPtyNative.IsProcessInJob(_worker.DangerousGetHandle(), _parent.DangerousGetHandle(), out var member) || !member)
                    throw new InvalidOperationException("Suspended test worker membership did not read back.");
                var actual = ObserveJob(_parent);
                if (actual.ActiveProcesses != 1 || actual.ProcessIds.Length != 1 || actual.ProcessIds[0] != Evidence.WorkerProcessId)
                    throw new InvalidOperationException("Owned assignment test Job was not filled by the exact suspended worker.");
                Evidence.ParentBeforeAssignment = actual;
            }
            finally { if (thread != 0) _ = ConPtyNative.CloseHandle(thread); }
        }

        internal void RejectCandidate(SafeFileHandle candidate, uint processId, DateTimeOffset created)
        {
            Evidence.CandidateProcessId = processId;
            Evidence.CandidateCreatedUtc = created;
            if (ConPtyNative.AssignProcessToJobObject(_parent!, candidate))
                throw new InvalidOperationException("The full owned parent unexpectedly accepted the suspended candidate.");
            Evidence.NativeErrorCode = Marshal.GetLastPInvokeError();
            Evidence.AssignmentRejected = true;
            throw new Win32Exception(Evidence.NativeErrorCode, "Assign suspended executor to full owned test Job failed.");
        }

        public async ValueTask DisposeAsync()
        {
            if (_parent is null) return;
            if (!ConPtyNative.TerminateJobObject(_parent, 125)) throw Error("Terminate owned assignment test Job");
            if (_worker is not null)
            {
                if (!_workerAssigned && ConPtyNative.WaitForSingleObject(_worker, 0) == 258 && !ConPtyNative.TerminateProcess(_worker, 125))
                {
                    var error = Marshal.GetLastPInvokeError();
                    if (ConPtyNative.WaitForSingleObject(_worker, 1000) != 0) throw new Win32Exception(error, "Terminate suspended assignment test worker failed.");
                }
                var watch = Stopwatch.StartNew();
                while (ConPtyNative.WaitForSingleObject(_worker, 0) == 258)
                    await PauseAsync(watch, TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
                if (ConPtyNative.WaitForSingleObject(_worker, 0) != 0) throw Error("Wait for assignment test worker");
            }
            var deadline = Stopwatch.StartNew();
            ConPtyJobObservation actual;
            while ((actual = ObserveJob(_parent)).ActiveProcesses != 0 || actual.ProcessIds.Length != 0)
                await PauseAsync(deadline, TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
            Evidence.ParentAfterCleanup = actual;
            Evidence.CleanupCompleted = true;
            _worker?.Dispose();
            _parent.Dispose();
            _worker = null;
            _parent = null;
        }
    }
}
