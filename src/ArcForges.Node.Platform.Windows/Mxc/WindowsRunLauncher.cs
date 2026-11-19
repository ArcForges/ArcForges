// SPDX-License-Identifier: AGPL-3.0-only

using System.ComponentModel;
using System.Globalization;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.Node.Platform.Windows.Mxc;

/// <summary>Creates and authenticates a durable Windows supervisor without giving its Job to the workload.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsRunLauncher : IRunLauncher
{
    private static readonly TimeSpan BootDeadline = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DrainDeadline = TimeSpan.FromSeconds(10);

    /// <summary>Computes the initial Job limits shared by the launcher and its trusted owner.</summary>
    public static WindowsMxcJobLimits Limits(RunLaunchSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.CpuWeight.HasValue)
        {
            throw new RunNativeException("windows_cpu_weight_with_hard_cap", "unsupported",
                boundaryEmptyVerified: true, payloadNotStarted: true);
        }

        return new(WindowsMxcProcess.CpuRate(spec.CpuMillicores),
            checked((long)spec.MemoryMaxBytes), checked((int)spec.MaxProcesses));
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
            var limits = Limits(spec);
            phase = "windows_supervisor_launcher_identity";
            spec = spec with
            {
                LauncherProcessId = Environment.ProcessId,
                LauncherCreationIdentity = WindowsMxcProcess.CurrentCreationFileTime().ToString(CultureInfo.InvariantCulture),
                LauncherPath = WindowsMxcProcess.CurrentImagePath(),
                ControlEndpoint = "arcforges-run-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                BoundaryDescriptor = "windows-anonymous-job:" + spec.OwnerId,
            };

            phase = "windows_supervisor_installation";
            using var image = WindowsMxcPathLease.Open(spec.SupervisorPath, directory: false);
            if (image.Hash(128L * 1024 * 1024) != spec.SupervisorSha256)
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
            pipe = new NamedPipeClientStream(".", spec.ControlEndpoint, PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, TokenImpersonationLevel.Identification);
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

            return new Lease(spec, client, process, job);
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

    /// <summary>Reports a bounded native code without including paths, configuration or payload output.</summary>
    public static string NativeCode(Exception error) => error is Win32Exception native
        ? "win32:" + native.NativeErrorCode.ToString(CultureInfo.InvariantCulture)
        : error.GetType().Name;

    private sealed class Lease(RunLaunchSpec spec, RunControlClient client, LaunchedProcess process, WindowsMxcJob aggregate) : IRunOwnerLease
    {
        private readonly SemaphoreSlim _boundaryGate = new(1, 1);
        private int _releaseAttempted;
        private int _disposed;
        private RunOwnerObservation? _lastOwnerObservation;
        private RunOwnerObservation? _explicitStopOutcome;

        public RunOwnerIdentity Identity => client.Identity;

        public ValueTask ActivateAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _releaseAttempted, 1) != 0)
            {
                throw new InvalidOperationException("The Windows Run boundary handoff already occurred.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            var remoteHandle = WindowsMxcProcess.DuplicateJobToOwner(aggregate, process);
            return client.ActivateAsync(new RunRelease(remoteHandle), cancellationToken);
        }

        public async ValueTask StopAsync(TimeSpan grace, CancellationToken cancellationToken)
        {
            await _boundaryGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_explicitStopOutcome is not null) return;
                var prior = RunWire.TryReadObservation(spec);
                if (WindowsMxcProcess.PollExit(process) is not null || prior is { State: RunOwnerState.RecoveryRequired })
                {
                    await StopAtBoundaryAsync(prior).ConfigureAwait(false);
                    return;
                }

                try { await client.StopAsync(grace, cancellationToken).ConfigureAwait(false); }
                catch (IOException) when (WindowsMxcProcess.PollExit(process) is not null
                    || RunWire.TryReadObservation(spec) is { IsTerminal: true, GroupEmptyVerified: true })
                {
                    if (WindowsMxcProcess.PollExit(process) is not null)
                    {
                        await StopAtBoundaryAsync(prior).ConfigureAwait(false);
                    }
                    // A live owner that already committed its authenticated terminal result is finishing its own drain.
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
            try
            {
                return _explicitStopOutcome ?? await ObserveBoundaryAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Win32Exception error)
            {
                throw new RunNativeException("windows_boundary_observation", NativeCode(error));
            }
            finally
            {
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

            var settled = RunWire.TryReadObservation(spec);
            var terminal = SettledOwnerResult(settled) ?? SettledOwnerResult(prior) ?? SettledOwnerResult(_lastOwnerObservation);
            if (terminal is not null)
            {
                _explicitStopOutcome = terminal;
                return;
            }

            var latest = settled ?? prior ?? _lastOwnerObservation;
            var observedExit = latest?.RawExitCode is not null ? latest
                : _lastOwnerObservation?.RawExitCode is not null ? _lastOwnerObservation : prior;
            _explicitStopOutcome = new(RunOwnerState.Exited,
                latest?.PayloadStarted == RunPayloadStart.Confirmed ? RunPayloadStart.Confirmed : RunPayloadStart.Unknown,
                true, observedExit?.RawExitCode,
                observedExit?.RawExitCode is not null ? observedExit.ExitSource ?? RunExitSources.Unknown : RunExitSources.Unknown,
                TerminationReason: "user_stop",
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
                        if (RunWire.TryReadObservation(spec) is { IsTerminal: true, GroupEmptyVerified: true } pending)
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
                    return UnknownBoundaryObservation(RunWire.TryReadObservation(spec) ?? _lastOwnerObservation,
                        "windows_aggregate_drain_unverified");
                }
            }

            var settled = RunWire.TryReadObservation(spec) ?? _lastOwnerObservation;
            if (settled is { IsTerminal: true, GroupEmptyVerified: true }) return settled;
            return UnknownBoundaryObservation(settled, "windows_settled_owner_record_missing");
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
                process.Dispose();
                aggregate.Dispose();
                _boundaryGate.Dispose();
            }
        }
    }
}
