// SPDX-License-Identifier: AGPL-3.0-only

using System.ComponentModel;
using System.Globalization;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.Node.Platform.Windows.Mxc;

/// <summary>Creates and authenticates a durable Windows supervisor without giving its Job to the workload.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsRunLauncher : IRunLauncher, IRunRecoveryLauncher
{
    private const string BoundaryPrefix = "windows-anonymous-job:";
    private const string PipePrefix = "arcforges-run-";
    private const long MaximumSupervisorBytes = 128L * 1024 * 1024;
    private static readonly TimeSpan BootDeadline = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RecoveryDeadline = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DrainDeadline = TimeSpan.FromSeconds(10);

    /// <summary>Computes the initial Job limits shared by the launcher and its trusted owner.</summary>
    public static WindowsMxcJobLimits Limits(RunLaunchSpec spec) =>
        Limits(spec, WindowsMxcProcess.ResourceProcessorCount());

    private static WindowsMxcJobLimits Limits(RunLaunchSpec spec, uint processors)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.CpuWeight.HasValue)
        {
            throw new RunNativeException("windows_cpu_weight_with_hard_cap", "unsupported",
                boundaryEmptyVerified: true, payloadNotStarted: true);
        }

        var commitBytes = WindowsMxcJob.NormalizeResourceLimit(RunResourceDimension.Memory, spec.MemoryMaxBytes, processors)
            ?? throw new RunNativeException("windows_job_commit_limit", "windows_run_limit_unrepresentable",
                boundaryEmptyVerified: true, payloadNotStarted: true);
        return new(WindowsMxcProcess.CpuRate(spec.CpuMillicores, processors),
            checked((long)commitBytes), checked((int)spec.MaxProcesses));
    }

    /// <inheritdoc />
    public async ValueTask<IRunOwnerLease> PrepareAsync(RunLaunchSpec spec, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(spec);
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(BootDeadline);
        WindowsMxcJob? job = null;
        WindowsMxcPathLease? manifest = null;
        WindowsMxcPathLease? control = null;
        WindowsMxcPathLease.PrivateFileIdentity? createdFile = null;
        LaunchedProcess? process = null;
        NamedPipeClientStream? pipe = null;
        RunControlClient? client = null;
        var phase = "windows_supervisor_limits";
        try
        {
            var processors = WindowsMxcProcess.ResourceProcessorCount();
            var limits = Limits(spec, processors);
            phase = "windows_supervisor_launcher_identity";
            spec = spec with
            {
                LauncherProcessId = Environment.ProcessId,
                LauncherCreationIdentity = WindowsMxcProcess.CurrentCreationFileTime().ToString(CultureInfo.InvariantCulture),
                LauncherPath = WindowsMxcProcess.CurrentImagePath(),
                ControlEndpoint = PipePrefix + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                BoundaryDescriptor = BoundaryPrefix + spec.OwnerId,
            };

            phase = "windows_supervisor_installation";
            using var image = WindowsMxcPathLease.Open(spec.SupervisorPath, directory: false);
            if (image.Hash(MaximumSupervisorBytes) != spec.SupervisorSha256)
            {
                throw new InvalidDataException("The held Windows supervisor image differs from its admitted release digest.");
            }

            phase = "windows_supervisor_control";
            control = WindowsMxcPathLease.Open(spec.ControlDirectory, directory: true, privateObject: true);
            var boot = WindowsMxcProcess.BootIdentity();
            var launchBinding = RunWire.WriteLaunch(spec, file => createdFile = WindowsMxcPathLease.CaptureCreatedPrivateFile(file));
            manifest = WindowsMxcPathLease.Open(RunWire.LaunchPath(spec), directory: false, privateObject: true);
            manifest.RequirePrivateFileIdentity(createdFile ?? throw new InvalidDataException("The created Windows Run manifest identity is unavailable."));
            var directory = Path.GetDirectoryName(image.Path) ?? throw new IOException("The supervisor installation is unavailable.");
            phase = "windows_supervisor_job";
            job = WindowsMxcJob.Create(limits);
            budget.Token.ThrowIfCancellationRequested();
            phase = "windows_supervisor_create";
            process = WindowsMxcProcess.CreateSuspended(image.Path, ["--run-control", manifest.Path], directory,
                WindowsMxcProcess.TrustedEnvironment(control.Path), job);
            var birth = WindowsMxcProcess.RequireIdentity(process, image.Path);
            job.RequireMember(process);
            job.RequireLimits(limits);
            _ = job.RequireOnly(process.ProcessId);
            WindowsMxcProcess.Resume(process);

            phase = "windows_supervisor_authenticate";
            pipe = OpenControlPipe(spec.ControlEndpoint);
            await pipe.ConnectAsync(budget.Token).ConfigureAwait(false);
            WindowsMxcProcess.RequirePeer(pipe.SafePipeHandle, localIsServer: false, process.ProcessId, birth, image.Path);
            client = await RunControlClient.ConnectAsync(pipe, spec, launchBinding, budget.Token).ConfigureAwait(false);
            var identity = client.Identity;
            if (identity.ProcessId != process.ProcessId || identity.CreationIdentity != birth.ToString(CultureInfo.InvariantCulture)
                || identity.BootId != boot || identity.InstanceId != spec.OwnerId || identity.Endpoint != spec.ControlEndpoint
                || identity.BoundaryIdentity != spec.BoundaryDescriptor || identity.BackendId != spec.ProfileId
                || identity.Cohort != spec.ProfileVersion || identity.ControlEpoch != spec.Epoch)
            {
                throw new InvalidDataException("The authenticated supervisor identity differs from its held process or Run.");
            }

            return new Lease(() => RunWire.TryReadObservation(spec, identity), client, process.Process, job, processors, birth);
        }
        catch (Exception error) when (error is IOException or InvalidDataException or Win32Exception or OperationCanceledException
            or UnauthorizedAccessException or ArgumentException or OverflowException)
        {
            var native = (error as RunNativeException)?.NativeCode ?? NativeCode(error);
            var empty = job is null;
            try
            {
                if (job is not null)
                {
                    if (process is not null) job.Terminate();
                    _ = await job.WaitForDrainAsync(null, DrainDeadline, CancellationToken.None).ConfigureAwait(false);
                    empty = true;
                }

                if (empty && createdFile is { } owned)
                {
                    manifest?.Dispose();
                    manifest = null;
                    WindowsMxcPathLease.DeleteCreatedPrivateFile(RunWire.LaunchPath(spec), owned);
                }
            }
            catch (Exception drainError) when (drainError is IOException or InvalidDataException or Win32Exception
                or TimeoutException or UnauthorizedAccessException)
            {
                empty = false;
                native += "/" + NativeCode(drainError);
            }
            finally
            {
                try
                {
                    if (client is not null) await client.DisposeAsync().ConfigureAwait(false);
                    else if (pipe is not null) await pipe.DisposeAsync().ConfigureAwait(false);
                }
                finally
                {
                    process?.Dispose();
                    job?.Dispose();
                }
            }

            throw new RunNativeException((error as RunNativeException)?.Phase ?? phase, native,
                boundaryEmptyVerified: empty, payloadNotStarted: empty);
        }
        finally
        {
            manifest?.Dispose();
            control?.Dispose();
        }
    }

    /// <inheritdoc />
    public async ValueTask<RunRecoveryResult> RecoverAsync(RunRecoverySpec spec, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(spec);
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(RecoveryDeadline);
        WindowsMxcPathLease? control = null;
        SafeKernelHandle? ownerProcess = null;
        WindowsMxcJob? aggregate = null;
        NamedPipeClientStream? pipe = null;
        RunControlClient? client = null;
        var phase = "windows_recovery_binding";
        try
        {
            budget.Token.ThrowIfCancellationRequested();
            var owner = spec.Owner;
            if (spec.ControlKey.Length != RunWire.KeyLength || spec.Generation <= 0 || owner.ProcessId <= 0
                || owner.BoundaryIdentity != BoundaryPrefix + owner.InstanceId || owner.ControlEpoch != spec.Epoch
                || !owner.Endpoint.StartsWith(PipePrefix, StringComparison.Ordinal)
                || !Guid.TryParseExact(owner.Endpoint.AsSpan(PipePrefix.Length), "N", out _)
                || !long.TryParse(owner.CreationIdentity, NumberStyles.None, CultureInfo.InvariantCulture, out var birth) || birth <= 0)
            {
                throw new InvalidDataException("The Windows recovery owner identity is invalid.");
            }

            control = WindowsMxcPathLease.Open(spec.ControlDirectory, directory: true, privateObject: true);
            var boot = WindowsMxcProcess.BootIdentity();
            if (!string.Equals(owner.BootId, boot, StringComparison.Ordinal))
            {
                return new(null, ObserveBootChange(spec, boot));
            }

            phase = "windows_recovery_supervisor";
            using var image = WindowsMxcPathLease.Open(spec.SupervisorPath, directory: false);
            if (image.Hash(MaximumSupervisorBytes) != spec.SupervisorSha256)
            {
                throw new InvalidDataException("The held Windows recovery supervisor image differs from its admitted digest.");
            }

            ownerProcess = WindowsMxcProcess.OpenRecoveryOwner(owner.ProcessId, birth, image.Path);
            phase = "windows_recovery_authenticate";
            pipe = OpenControlPipe(owner.Endpoint);
            await pipe.ConnectAsync(budget.Token).ConfigureAwait(false);
            WindowsMxcProcess.RequireRecoveryOwnerPipe(pipe.SafePipeHandle, ownerProcess, owner.ProcessId, birth, image.Path);
            var requester = WindowsMxcProcess.CurrentCreationFileTime().ToString(CultureInfo.InvariantCulture);
            client = await RunControlClient.ReconnectAsync(pipe, spec, requester, budget.Token).ConfigureAwait(false);
            if (client.Identity != owner || client.RecoveryBoundaryHandle is not { } remoteHandle)
            {
                throw new InvalidDataException("The authenticated Windows Run owner or its standby capability differs.");
            }

            phase = "windows_recovery_job";
            aggregate = WindowsMxcJob.Rebind(ownerProcess, remoteHandle);
            var processors = WindowsMxcProcess.ResourceProcessorCount();
            var receiptSpec = spec with { ControlDirectory = control.Path, ControlKey = spec.ControlKey.ToArray() };
            var lease = new Lease(() => RunWire.TryReadObservation(receiptSpec), client, ownerProcess, aggregate, processors, birth,
                receiptSpec.ControlKey);
            client = null;
            pipe = null;
            ownerProcess = null;
            aggregate = null;
            return new(lease, null);
        }
        catch (Exception error) when (error is IOException or InvalidDataException or Win32Exception or UnauthorizedAccessException
            or ArgumentException or OverflowException || error is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return new(null, UnknownBoundaryObservation(control is null ? null : RunWire.TryReadObservation(spec),
                phase + "/" + NativeCode(error)));
        }
        finally
        {
            try
            {
                if (client is not null) await client.DisposeAsync().ConfigureAwait(false);
                else if (pipe is not null) await pipe.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                aggregate?.Dispose();
                ownerProcess?.Dispose();
                control?.Dispose();
            }
        }
    }

    private static RunOwnerObservation ObserveBootChange(RunRecoverySpec spec, string boot)
    {
        var receipt = RunWire.TryReadObservation(spec);
        var machinePrefix = boot.AsSpan(0, boot.LastIndexOf(':') + 1);
        if (!spec.Owner.BootId.AsSpan().StartsWith(machinePrefix, StringComparison.Ordinal)
            || !long.TryParse(spec.Owner.BootId.AsSpan(machinePrefix.Length), NumberStyles.None, CultureInfo.InvariantCulture,
                out var previousBoot) || previousBoot <= 0
            || !long.TryParse(boot.AsSpan(machinePrefix.Length), NumberStyles.None, CultureInfo.InvariantCulture,
                out var currentBoot) || currentBoot <= 0 || previousBoot == currentBoot)
        {
            return UnknownBoundaryObservation(receipt, "windows_recovery_boot_identity_unverified");
        }

        // A verified same-machine reboot establishes scope emptiness even if the Node never observed the final drain.
        if (receipt is { IsTerminal: true }) return receipt with { GroupEmptyVerified = true };

        return new(RunOwnerState.Exited, receipt?.PayloadStarted ?? RunPayloadStart.Unknown, true,
            receipt?.RawExitCode, receipt?.RawExitCode is null ? RunExitSources.Unknown : receipt.ExitSource ?? RunExitSources.Unknown,
            TerminationReason: "host_reboot", NativeError: receipt?.NativeError);
    }

    private static NamedPipeClientStream OpenControlPipe(string endpoint) => new(".", endpoint, PipeDirection.InOut,
        PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, TokenImpersonationLevel.Identification);

    private static RunOwnerObservation UnknownBoundaryObservation(RunOwnerObservation? known, string diagnostic) =>
        known is not null
            ? known with
            {
                State = RunOwnerState.RecoveryRequired,
                GroupEmptyVerified = false,
                TerminationReason = known.TerminationReason ?? "owner_failure",
                NativeError = known.NativeError ?? diagnostic,
            }
            : new(RunOwnerState.RecoveryRequired, RunPayloadStart.Unknown, false,
                TerminationReason: "owner_failure", NativeError: diagnostic);

    /// <summary>Reports a bounded native code without including paths, configuration or payload output.</summary>
    public static string NativeCode(Exception error) => error is Win32Exception native
        ? "win32:" + native.NativeErrorCode.ToString(CultureInfo.InvariantCulture)
        : error.GetType().Name;

    private sealed class Lease(Func<RunOwnerObservation?> readObservation, RunControlClient client, SafeKernelHandle process,
        WindowsMxcJob aggregate, uint processors, long ownerBirth, byte[]? recoveryKey = null)
        : IRunOwnerLease, IRunResourceSource, IRunResourceControl
    {
        private readonly SemaphoreSlim _boundaryGate = new(1, 1);
        private readonly Lock _resourceGate = new();
        private int _releaseAttempted;
        private int _disposed;
        private bool _resourceOwnerRunning;
        private bool _resourceStopRequested;
        private RunOwnerObservation? _lastOwnerObservation;
        private RunOwnerObservation? _explicitStopOutcome;

        public RunOwnerIdentity Identity => client.Identity;

        public RunResourceObservation? ObserveRunResources()
        {
            var observation = Volatile.Read(ref _disposed) == 0 ? aggregate.ObserveResources() : null;
            return Volatile.Read(ref _disposed) == 0 ? observation : null;
        }

        public RunResourceLimitReading? ReadRunLimits()
        {
            lock (_resourceGate)
            {
                try
                {
                    if (!HasResourceOwner()) return null;
                    var limits = aggregate.ReadResourceLimits();
                    var normalizedCpu = WindowsMxcProcess.ResourceProcessorCount() == processors
                        ? (ulong?)WindowsMxcProcess.ResourceCpuMillicores(limits.CpuRate, processors) : null;
                    return new(Identity.BoundaryIdentity, normalizedCpu, (ulong)limits.CommitBytes, (uint)limits.MaxProcesses, null, null);
                }
                catch (Exception error) when (error is Win32Exception or InvalidDataException or ObjectDisposedException)
                {
                    return null;
                }
            }
        }

        public ulong? NormalizeRunLimit(RunResourceDimension dimension, ulong value)
        {
            try
            {
                return dimension == RunResourceDimension.Cpu && WindowsMxcProcess.ResourceProcessorCount() != processors
                    ? null : WindowsMxcJob.NormalizeResourceLimit(dimension, value, processors);
            }
            catch (Win32Exception)
            {
                return null;
            }
        }

        public RunResourceWriteResult ApplyRunLimit(RunResourceDimension dimension, ulong value)
        {
            lock (_resourceGate)
            {
                try
                {
                    if (!HasResourceOwner())
                    {
                        return new(RunResourceWriteStatus.ScopeLost, Reason: "windows_run_resource_scope_lost");
                    }

                    if (!_resourceOwnerRunning || _resourceStopRequested)
                    {
                        return new(RunResourceWriteStatus.Failed, Reason: "windows_run_resource_owner_not_running");
                    }

                    if (dimension == RunResourceDimension.Cpu && WindowsMxcProcess.ResourceProcessorCount() != processors)
                    {
                        return new(RunResourceWriteStatus.Failed, Reason: "windows_cpu_topology_changed");
                    }

                    return aggregate.ApplyResourceLimit(dimension, value, processors);
                }
                catch (Win32Exception error)
                {
                    const int invalidHandle = 6;
                    return new(error.NativeErrorCode == invalidHandle ? RunResourceWriteStatus.ScopeLost : RunResourceWriteStatus.Failed,
                        Reason: NativeCode(error));
                }
                catch (ObjectDisposedException)
                {
                    return new(RunResourceWriteStatus.ScopeLost, Reason: "windows_run_resource_scope_lost");
                }
                catch (InvalidDataException)
                {
                    return new(RunResourceWriteStatus.Failed, Reason: "windows_run_job_limits_unverified");
                }
            }
        }

        private bool HasResourceOwner()
        {
            if (Volatile.Read(ref _disposed) != 0 || WindowsMxcProcess.PollExit(process) is not null
                || ProcessInfo.CreationFileTime(process) != ownerBirth)
            {
                return false;
            }

            try
            {
                aggregate.RequireMember(process);
                return true;
            }
            catch (InvalidDataException)
            {
                return false;
            }
        }

        public ValueTask<RunTerminalReply> TerminalAsync(RunTerminalRequest request, CancellationToken cancellationToken) =>
            client.TerminalAsync(request, cancellationToken);

        public ValueTask ActivateAsync(CancellationToken cancellationToken)
        {
            if (recoveryKey is not null || Interlocked.Exchange(ref _releaseAttempted, 1) != 0)
            {
                throw new InvalidOperationException("The Windows Run boundary handoff already occurred.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            var handles = WindowsMxcProcess.DuplicateJobsToOwner(aggregate, process);
            return client.ActivateAsync(new RunRelease(handles.Query, RecoveryBoundaryHandle: handles.Recovery), cancellationToken);
        }

        public async ValueTask StopAsync(TimeSpan grace, CancellationToken cancellationToken)
        {
            await _boundaryGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                lock (_resourceGate)
                {
                    _resourceStopRequested = true;
                }

                if (_explicitStopOutcome is not null) return;
                var prior = readObservation();
                if (WindowsMxcProcess.PollExit(process) is not null || prior is { State: RunOwnerState.RecoveryRequired })
                {
                    await StopAtBoundaryAsync(prior).ConfigureAwait(false);
                    return;
                }

                try { await client.StopAsync(grace, cancellationToken).ConfigureAwait(false); }
                catch (Exception error) when (error is IOException and not RunNativeException or InvalidDataException or JsonException)
                {
                    // This is an accepted Stop. Lost private control does not invalidate the original held Job.
                    await StopAtBoundaryAsync(prior).ConfigureAwait(false);
                }
            }
            catch (Exception error) when (error is Win32Exception or TimeoutException)
            {
                throw new RunNativeException("windows_boundary_stop", NativeCode(error));
            }
            finally
            {
                _boundaryGate.Release();
            }
        }

        public async ValueTask<RunOwnerObservation> ObserveAsync(CancellationToken cancellationToken)
        {
            await _boundaryGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            RunOwnerObservation? observed = null;
            try
            {
                observed = _explicitStopOutcome ?? await ObserveBoundaryAsync(cancellationToken).ConfigureAwait(false);
                return observed;
            }
            catch (Win32Exception error)
            {
                throw new RunNativeException("windows_boundary_observation", NativeCode(error));
            }
            finally
            {
                lock (_resourceGate)
                {
                    _resourceOwnerRunning = observed?.State == RunOwnerState.Running;
                }

                _boundaryGate.Release();
            }
        }

        private async ValueTask StopAtBoundaryAsync(RunOwnerObservation? prior)
        {
            if (!aggregate.Observe().Empty)
            {
                // The exact held aggregate remains authoritative when its owner cannot complete the accepted Stop.
                aggregate.Terminate();
                _ = await aggregate.WaitForDrainAsync(null, DrainDeadline, CancellationToken.None).ConfigureAwait(false);
            }

            var settled = readObservation();
            var terminal = SettledOwnerResult(settled) ?? SettledOwnerResult(prior) ?? SettledOwnerResult(_lastOwnerObservation);
            if (terminal is not null)
            {
                _explicitStopOutcome = terminal;
                return;
            }

            var latest = settled ?? prior ?? _lastOwnerObservation;
            var observedExit = latest?.RawExitCode is not null ? latest
                : _lastOwnerObservation?.RawExitCode is not null ? _lastOwnerObservation : prior;
            // The held Job proves cleanup. Only an authenticated terminal report can attribute it to the Stop.
            _explicitStopOutcome = new(RunOwnerState.Exited,
                latest?.PayloadStarted == RunPayloadStart.Confirmed || prior?.PayloadStarted == RunPayloadStart.Confirmed
                    || _lastOwnerObservation?.PayloadStarted == RunPayloadStart.Confirmed ? RunPayloadStart.Confirmed : RunPayloadStart.Unknown,
                true, observedExit?.RawExitCode,
                observedExit?.RawExitCode is not null ? observedExit.ExitSource ?? RunExitSources.Unknown : RunExitSources.Unknown,
                TerminationReason: "owned_scope_drained",
                NativeError: latest?.NativeError ?? (observedExit?.RawExitCode is null ? "windows_official_exit_unobserved" : null));
        }

        private async ValueTask<RunOwnerObservation> ObserveBoundaryAsync(CancellationToken cancellationToken)
        {
            if (WindowsMxcProcess.PollExit(process) is null)
            {
                try
                {
                    var current = await client.ObserveAsync(cancellationToken).ConfigureAwait(false);
                    RememberOwnerObservation(current);
                    if (!current.IsTerminal) return current;
                    return DeferTerminalObservation(current);
                }
                catch (IOException)
                {
                    if (WindowsMxcProcess.PollExit(process) is null)
                    {
                        // The owner commits its final receipt before closing its control pipe.
                        // A terminating owner can therefore still be alive while the pipe returns EOF.
                        if (readObservation() is { IsTerminal: true, GroupEmptyVerified: true } pending)
                        {
                            RememberOwnerObservation(pending);
                            return DeferTerminalObservation(pending);
                        }

                        throw;
                    }
                }
            }

            if (!aggregate.Observe().Empty)
            {
                aggregate.Terminate();
                try
                {
                    _ = await aggregate.WaitForDrainAsync(null, DrainDeadline, cancellationToken).ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    return UnknownBoundaryObservation(readObservation() ?? _lastOwnerObservation,
                        "windows_aggregate_drain_unverified");
                }
            }

            var settled = readObservation() ?? _lastOwnerObservation;
            if (settled is { IsTerminal: true, GroupEmptyVerified: true }) return settled;
            var observedExit = settled?.RawExitCode is not null ? settled : _lastOwnerObservation;
            return new(RunOwnerState.Exited,
                settled?.PayloadStarted == RunPayloadStart.Confirmed || _lastOwnerObservation?.PayloadStarted == RunPayloadStart.Confirmed
                    ? RunPayloadStart.Confirmed : RunPayloadStart.Unknown,
                true, observedExit?.RawExitCode,
                observedExit?.RawExitCode is null ? RunExitSources.Unknown : observedExit.ExitSource ?? RunExitSources.Unknown,
                TerminationReason: "owner_failure", NativeError: settled?.NativeError ?? "windows_settled_owner_record_missing");
        }

        private void RememberOwnerObservation(RunOwnerObservation reported)
        {
            if (_lastOwnerObservation?.RawExitCode is null || reported.RawExitCode is not null || reported.IsTerminal)
            {
                _lastOwnerObservation = reported;
            }
        }

        private static RunOwnerObservation? SettledOwnerResult(RunOwnerObservation? reported) =>
            reported is { IsTerminal: true, GroupEmptyVerified: true } ? reported : null;

        private static RunOwnerObservation DeferTerminalObservation(RunOwnerObservation observation) => observation with
        {
            // A refused start can become FAILED only after this lease observes outer Job drain.
            State = observation is { State: RunOwnerState.Failed, PayloadStarted: RunPayloadStart.NotStarted }
                ? RunOwnerState.Starting
                : RunOwnerState.Draining,
            GroupEmptyVerified = false,
        };

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            try { await client.DisposeAsync().ConfigureAwait(false); }
            finally
            {
                lock (_resourceGate)
                {
                    process.Dispose();
                    aggregate.Dispose();
                    if (recoveryKey is not null) CryptographicOperations.ZeroMemory(recoveryKey);
                }

                _boundaryGate.Dispose();
            }
        }
    }
}
