// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.RunSupervisor.Protocol;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Platform.Linux.Mxc;

/// <summary>Starts V2 Run owners in their dedicated native user service.</summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxRunLauncher : IRunLauncher, IRunRecoveryLauncher
{
    /// <inheritdoc />
    public async ValueTask<IRunOwnerLease> PrepareAsync(RunLaunchSpec spec, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var endpoint = Path.Combine(spec.ControlDirectory, "owner.sock");
        var unit = "arcforges-run-" + Guid.NewGuid().ToString("N") + ".service";
        var nodePid = Environment.ProcessId;
        var nodeStart = ProcFs.Stat(nodePid)?.StartTicks ?? throw new IOException("The launching Node's birth identity is unavailable.");
        spec = spec with
        {
            BoundaryDescriptor = unit,
            ControlEndpoint = endpoint,
            LauncherProcessId = nodePid,
            LauncherCreationIdentity = nodeStart.ToString(CultureInfo.InvariantCulture),
            LauncherPath = LinuxRunNativePeer.Executable(nodePid),
        };

        LinuxRunCgroup? scope = null;
        RunControlClient? controller = null;
        SafeFileHandle? controlDirectory = null;
        var createdLaunch = false;
        var attempted = false;
        try
        {
            controlDirectory = LinuxRunCgroup.OpenPrivateDirectory(spec.ControlDirectory);
            LinuxRunMxcAssets.VerifySupervisor(spec);
            LinuxRunMxcAssets.Verify(spec);
            var launchBinding = RunWire.WriteLaunch(spec, _ => createdLaunch = true);
            attempted = true;
            await LinuxRunSystemd.StartAsync(unit, spec.SupervisorPath, spec.InstallationRoot, RunWire.LaunchPath(spec),
                spec.CpuMillicores, spec.MemoryMaxBytes, spec.MaxProcesses, spec.CpuWeight).ConfigureAwait(false);
            var ready = await LinuxRunSystemd.WaitForReadyAsync(unit, cancellationToken).ConfigureAwait(false);
            scope = ready.Scope;
            controller = await ConnectAsync(ready.State, controlDirectory, spec.ControlDirectory, spec.ControlEndpoint,
                spec.SupervisorPath, spec.SupervisorSha256,
                (stream, token) => RunControlClient.ConnectAsync(stream, spec, launchBinding, token), cancellationToken).ConfigureAwait(false);
            var identity = LinuxRunNativePeer.Identity(spec, ready.State, scope);
            if (identity != controller.Identity)
            {
                throw new IOException("The Run supervisor's authenticated identity differs from the native owner.");
            }

            RequireReadback(spec, ready.State, scope);
            var lease = new LinuxRunLease(ready.State, scope, controller, identity, controlDirectory, launch: spec);
            scope = null;
            controller = null;
            controlDirectory = null;
            return lease;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or OperationCanceledException or InvalidDataException or
            Win32Exception or InvalidOperationException)
        {
            var empty = !attempted || await LinuxRunSystemd.RollbackUnreleasedAsync(unit).ConfigureAwait(false);
            var code = NativeFailure(error);
            if (createdLaunch && empty && !TryRemoveUnreleasedLaunch(spec, controlDirectory!))
            {
                code += "_linux_launch_cleanup_failed";
            }

            throw new RunNativeException("prepare_linux_owner", code, empty, payloadNotStarted: true);
        }
        finally
        {
            try
            {
                if (controller is not null)
                {
                    await controller.DisposeAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                scope?.Dispose();
                controlDirectory?.Dispose();
            }
        }
    }

    /// <inheritdoc />
    public async ValueTask<RunRecoveryResult> RecoverAsync(RunRecoverySpec spec, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var owner = spec.Owner;
        var boundary = owner.BoundaryIdentity.Split('|', 6);
        if (boundary.Length != 5 || boundary[1] != owner.InstanceId || !Guid.TryParseExact(boundary[1], "N", out _)
            || !boundary[2].EndsWith('/' + boundary[0], StringComparison.Ordinal)
            || !ulong.TryParse(boundary[3], NumberStyles.None, CultureInfo.InvariantCulture, out var mount) || mount == 0
            || !ulong.TryParse(boundary[4], NumberStyles.None, CultureInfo.InvariantCulture, out var inode) || inode == 0
            || owner.ProcessId <= 0 || !long.TryParse(owner.CreationIdentity, NumberStyles.None, CultureInfo.InvariantCulture, out var start) || start <= 0
            || !Guid.TryParseExact(owner.BootId, "D", out var boot) || owner.ControlEpoch != spec.Epoch
            || owner.BackendId != "linux-bubblewrap-sdk-v1" || owner.Cohort != owner.BackendId
            || spec.ControlKey.Length != RunWire.KeyLength || spec.Generation <= 0 || !Path.IsPathFullyQualified(spec.ControlDirectory)
            || owner.Endpoint != Path.Combine(spec.ControlDirectory, "owner.sock")
            || !Path.IsPathFullyQualified(spec.SupervisorPath) || Path.GetDirectoryName(spec.SupervisorPath) != spec.InstallationRoot)
        {
            return UnresolvedRecovery("linux_recovery_identity_invalid");
        }

        LinuxRunCgroup? scope = null;
        RunControlClient? controller = null;
        SafeFileHandle? controlDirectory = null;
        bool bootChanged = false;
        try
        {
            bootChanged = Guid.ParseExact(LinuxRunCgroup.BootId(), "D") != boot;
            controlDirectory = LinuxRunCgroup.OpenPrivateDirectory(spec.ControlDirectory);
            if (bootChanged)
            {
                return new(null, VerifiedEnd(RunWire.TryReadObservation(spec), "host_reboot"));
            }

            var state = await LinuxRunSystemd.ReadAsync(boundary[0], cancellationToken).ConfigureAwait(false);
            if (!MatchesRecoveryGeneration(state, owner, boundary[2]))
            {
                return UnresolvedRecovery("linux_recovery_service_generation_unproven");
            }

            scope = LinuxRunCgroup.Open(state.Group);
            if (!scope.MatchesIdentity(mount, inode))
            {
                return UnresolvedRecovery("linux_recovery_cgroup_identity_mismatch");
            }

            if (state.OwnerPid == 0 && LinuxRunCgroup.IsOwnerGone(owner.ProcessId, start))
            {
                // systemd owns this transient unit's failure cleanup. A fallback Stop is scoped to the
                // verified generation and the originally observed cgroup, even though MainPID is gone.
                await LinuxRunSystemd.StopAsync(state with { OwnerPid = owner.ProcessId, OwnerStartTicks = start }, scope,
                    cancellationToken).ConfigureAwait(false);
                return new(null, VerifiedEnd(RunWire.TryReadObservation(spec), "owner_failure"));
            }

            if (state.OwnerPid != owner.ProcessId || state.OwnerStartTicks != start
                || !LinuxRunCgroup.MatchesProcess(owner.ProcessId, start, state.Group))
            {
                return UnresolvedRecovery("linux_recovery_owner_identity_unproven");
            }

            var requester = ProcFs.Stat(Environment.ProcessId)?.StartTicks
                ?? throw new IOException("The recovering Node's birth identity is unavailable.");
            controller = await ConnectAsync(state, controlDirectory, spec.ControlDirectory, owner.Endpoint,
                spec.SupervisorPath, spec.SupervisorSha256,
                (stream, token) => RunControlClient.ReconnectAsync(stream, spec, requester.ToString(CultureInfo.InvariantCulture), token),
                cancellationToken).ConfigureAwait(false);
            var current = await LinuxRunSystemd.ReadAsync(state.Name, cancellationToken).ConfigureAwait(false);
            if (controller.Identity != owner || !MatchesRecoveryGeneration(current, owner, state.Group)
                || current.OwnerPid != owner.ProcessId || current.OwnerStartTicks != start || !scope.MatchesIdentity(mount, inode))
            {
                return UnresolvedRecovery("linux_recovery_authenticated_owner_changed");
            }

            // Core compares the held scope's live limits against the durable effective grant. The independent owner
            // proof also lets Core retain safe Stop authority if that comparison cannot authorize a live rebind.
            var observed = await controller.ObserveAsync(cancellationToken).ConfigureAwait(false);
            if (observed.IsTerminal && scope.IsEmpty())
            {
                return new(null, observed with { GroupEmptyVerified = true });
            }

            var lease = new LinuxRunLease(state, scope, controller, owner, controlDirectory,
                recovery: spec with { ControlKey = spec.ControlKey.ToArray() });
            scope = null;
            controller = null;
            controlDirectory = null;
            return new(lease, observed with { GroupEmptyVerified = false });
        }
        catch (Exception error) when (!cancellationToken.IsCancellationRequested && error is IOException or
            UnauthorizedAccessException or OperationCanceledException or InvalidDataException or Win32Exception or InvalidOperationException)
        {
            return bootChanged ? new(null, VerifiedEnd(null, "host_reboot")) : UnresolvedRecovery(NativeFailure(error));
        }
        finally
        {
            try
            {
                if (controller is not null)
                {
                    await controller.DisposeAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                scope?.Dispose();
                controlDirectory?.Dispose();
            }
        }
    }

    private static bool MatchesRecoveryGeneration(LinuxRunServiceState state, RunOwnerIdentity owner, string group) =>
        state.Loaded && state.Boot == owner.BootId && state.Invocation == owner.InstanceId && state.Group == group;

    private static RunRecoveryResult UnresolvedRecovery(string reason) =>
        new(null, new RunOwnerObservation(RunOwnerState.RecoveryRequired, RunPayloadStart.Unknown, false, NativeError: reason));

    private static RunOwnerObservation VerifiedEnd(RunOwnerObservation? prior, string reason) => prior is { IsTerminal: true }
        ? prior with { GroupEmptyVerified = true }
        : new(RunOwnerState.Exited,
            prior?.PayloadStarted == RunPayloadStart.Confirmed ? RunPayloadStart.Confirmed : RunPayloadStart.Unknown, true,
            prior?.RawExitCode, prior?.ExitSource ?? RunExitSources.Unknown, TerminationReason: reason,
            NativeError: prior?.NativeError ?? (prior?.RawExitCode is null ? "linux_official_exit_unobserved" : null));

    internal static void RequireReadback(RunLaunchSpec spec, LinuxRunServiceState state, LinuxRunCgroup scope)
    {
        if (state.Group != scope.Path || !scope.ContainsOnlyOwner(state.OwnerPid, state.OwnerStartTicks))
        {
            throw new RunNativeException("readback_linux_owner", "linux_owner_cgroup_membership_mismatch");
        }

        LinuxRunSystemd.RequireLimits(spec.CpuMillicores, spec.MemoryMaxBytes, spec.MaxProcesses, spec.CpuWeight, scope.ReadLimits());
    }

    private static async Task<RunControlClient> ConnectAsync(LinuxRunServiceState state, SafeFileHandle directory,
        string controlDirectory, string controlEndpoint, string supervisorPath, string supervisorHash,
        Func<Stream, CancellationToken, ValueTask<RunControlClient>> handshake, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var endpoint = LinuxRunNativePeer.ControlAddress(controlDirectory, controlEndpoint, directory);
        while (true)
        {
            var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            try
            {
                await socket.ConnectAsync(endpoint, deadline.Token).ConfigureAwait(false);
            }
            catch (SocketException error) when (error.SocketErrorCode is SocketError.ConnectionRefused or SocketError.AddressNotAvailable
                or SocketError.HostNotFound or SocketError.AccessDenied or SocketError.AddressFamilyNotSupported or SocketError.SocketError)
            {
                socket.Dispose();
                await Task.Delay(25, deadline.Token).ConfigureAwait(false);
                continue;
            }
            catch
            {
                socket.Dispose();
                throw;
            }

            var stream = new NetworkStream(socket, ownsSocket: true);
            try
            {
                LinuxRunNativePeer.Require(socket, state.OwnerPid, state.OwnerStartTicks, supervisorPath);
                LinuxRunMxcAssets.VerifyRunningSupervisor(supervisorHash, state.OwnerPid, state.OwnerStartTicks);
                return await handshake(stream, deadline.Token).ConfigureAwait(false);
            }
            catch
            {
                await stream.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }

    private static bool TryRemoveUnreleasedLaunch(RunLaunchSpec spec, SafeFileHandle directory)
    {
        try
        {
            File.Delete(Path.Combine(LinuxRunCgroup.DescriptorPath(directory), Path.GetFileName(RunWire.LaunchPath(spec))));
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string NativeFailure(Exception error) => error switch
    {
        RunNativeException native => native.NativeCode,
        Win32Exception native => "linux_errno_" + native.NativeErrorCode.ToString(CultureInfo.InvariantCulture),
        { InnerException: Win32Exception native } => "linux_errno_" + native.NativeErrorCode.ToString(CultureInfo.InvariantCulture),
        OperationCanceledException => "linux_owner_deadline_or_cancellation",
        UnauthorizedAccessException => "linux_owner_access_refused",
        _ => error.GetType().Name,
    };

    private sealed class LinuxRunLease(LinuxRunServiceState native, LinuxRunCgroup scope, RunControlClient controller,
        RunOwnerIdentity identity, SafeFileHandle controlDirectory, RunLaunchSpec? launch = null, RunRecoverySpec? recovery = null)
        : IRunOwnerLease, IRunResourceSource, IRunResourceControl
    {
        private bool _releaseSent = recovery is not null;
        private int _boundaryStopVerified;

        public RunOwnerIdentity Identity { get; } = identity;

        public RunResourceObservation? ObserveRunResources() => scope.ObserveResources();

        public RunResourceLimitReading? ReadRunLimits() =>
            scope.ReadOwnedLimits(Identity.BoundaryIdentity, native.OwnerPid, native.OwnerStartTicks);

        public ulong? NormalizeRunLimit(RunResourceDimension dimension, ulong value) => LinuxRunCgroup.NormalizeRunLimit(dimension, value);

        public RunResourceWriteResult ApplyRunLimit(RunResourceDimension dimension, ulong value) =>
            Volatile.Read(ref _releaseSent) ? scope.ApplyOwnedLimit(dimension, value, native.OwnerPid, native.OwnerStartTicks)
                : new(RunResourceWriteStatus.Unsupported, Reason: "linux_resource_scope_not_released");

        public ValueTask<RunTerminalReply> TerminalAsync(RunTerminalRequest request, CancellationToken cancellationToken) =>
            controller.TerminalAsync(request, cancellationToken);

        public async ValueTask ActivateAsync(CancellationToken cancellationToken)
        {
            if (launch is null)
            {
                throw new RunNativeException("release_linux_owner", "linux_recovery_activation_forbidden");
            }

            var current = await LinuxRunSystemd.ReadAsync(native.Name, cancellationToken).ConfigureAwait(false);
            if (current.Invocation != native.Invocation || current.Boot != native.Boot || current.Group != native.Group ||
                current.OwnerPid != native.OwnerPid || current.OwnerStartTicks != native.OwnerStartTicks)
            {
                throw new RunNativeException("release_linux_owner", "linux_owner_generation_changed");
            }

            RequireReadback(launch, current, scope);
            Volatile.Write(ref _releaseSent, true);
            await controller.ActivateAsync(new RunRelease(), cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask StopAsync(TimeSpan grace, CancellationToken cancellationToken)
        {
            if (scope.IsEmpty())
            {
                // The supervisor may have died and systemd may already have
                // cleaned up. This explicit Stop still proves the held scope empty.
                Volatile.Write(ref _boundaryStopVerified, 1);
                return;
            }

            var started = Stopwatch.GetTimestamp();
            var acknowledged = false;
            try
            {
                await controller.StopAsync(grace, cancellationToken).ConfigureAwait(false);
                acknowledged = true;
            }
            catch (Exception error) when (error is IOException or SocketException)
            {
                // The exact original service can still be stopped if the owner channel is lost.
            }

            if (acknowledged)
            {
                while (!scope.IsEmpty() && Stopwatch.GetElapsedTime(started) < grace + TimeSpan.FromSeconds(4))
                {
                    await Task.Delay(50, cancellationToken).ConfigureAwait(false);
                }
            }

            if (!scope.IsEmpty())
            {
                await LinuxRunSystemd.StopAsync(native, scope, cancellationToken).ConfigureAwait(false);
            }

            Volatile.Write(ref _boundaryStopVerified, 1);
        }

        public async ValueTask<RunOwnerObservation> ObserveAsync(CancellationToken cancellationToken)
        {
            var result = ReadStoredObservation();
            bool ownerContacted = false;
            if (result is not { IsTerminal: true } && Volatile.Read(ref _boundaryStopVerified) == 0)
            {
                try
                {
                    result = await controller.ObserveAsync(cancellationToken).ConfigureAwait(false);
                    ownerContacted = true;
                }
                catch (Exception error) when (error is IOException or SocketException)
                {
                    result = ReadStoredObservation();
                }
            }

            if (Volatile.Read(ref _boundaryStopVerified) != 0 && scope.IsEmpty())
            {
                // The original scope is empty. An authenticated terminal observation supplies any Stop attribution.
                return VerifiedEnd(ReadStoredObservation() ?? result, "owned_scope_drained");
            }

            if (result is { IsTerminal: true })
            {
                if (scope.IsEmpty())
                {
                    return result with { GroupEmptyVerified = true };
                }

                // The signed refusal proves no payload ran, but its owner may
                // still be exiting. Pre-start failure never passes through Draining.
                return result is { State: RunOwnerState.Failed, PayloadStarted: RunPayloadStart.NotStarted }
                    ? new(RunOwnerState.Starting, RunPayloadStart.NotStarted, false)
                    : result with { State = RunOwnerState.Draining, GroupEmptyVerified = false };
            }

            if (ownerContacted)
            {
                return result! with { GroupEmptyVerified = false };
            }

            return LinuxRunCgroup.IsOwnerGone(native.OwnerPid, native.OwnerStartTicks) && scope.IsEmpty()
                ? VerifiedEnd(ReadStoredObservation() ?? result, "owner_failure")
                : new(RunOwnerState.RecoveryRequired,
                    result?.PayloadStarted == RunPayloadStart.Confirmed ? RunPayloadStart.Confirmed : RunPayloadStart.Unknown,
                    false, NativeError: "linux_owner_observation_unavailable");
        }

        private RunOwnerObservation? ReadStoredObservation() => launch is not null
            ? RunWire.TryReadObservation(launch, Identity)
            : RunWire.TryReadObservation(recovery!);

        public async ValueTask DisposeAsync()
        {
            var cleanupFailed = false;
            try
            {
                await controller.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                try
                {
                    cleanupFailed = launch is not null && !_releaseSent
                        && await LinuxRunSystemd.RollbackUnreleasedAsync(native.Name).ConfigureAwait(false)
                        && !TryRemoveUnreleasedLaunch(launch, controlDirectory);
                }
                finally
                {
                    scope.Dispose();
                    controlDirectory.Dispose();
                    if (recovery is not null)
                    {
                        CryptographicOperations.ZeroMemory(recovery.ControlKey);
                    }
                }
            }

            if (cleanupFailed)
            {
                throw new RunNativeException("cleanup_linux_owner", "linux_launch_cleanup_failed",
                    boundaryEmptyVerified: true, payloadNotStarted: true);
            }
        }
    }
}

[SupportedOSPlatform("linux")]
internal static partial class LinuxRunNativePeer
{
    internal static RunOwnerIdentity Identity(RunLaunchSpec spec, LinuxRunServiceState state, LinuxRunCgroup scope) =>
        new(state.Invocation, state.Boot, state.OwnerPid, state.OwnerStartTicks.ToString(CultureInfo.InvariantCulture),
            spec.ControlEndpoint, string.Create(CultureInfo.InvariantCulture,
                $"{state.Name}|{state.Invocation}|{scope.Path}|{scope.MountId}|{scope.Inode}"),
            spec.ProfileId, spec.ProfileVersion, spec.Epoch);

    internal static UnixDomainSocketEndPoint ControlAddress(RunLaunchSpec spec, SafeFileHandle directory) =>
        ControlAddress(spec.ControlDirectory, spec.ControlEndpoint, directory);

    internal static UnixDomainSocketEndPoint ControlAddress(string controlDirectory, string endpoint, SafeFileHandle directory)
    {
        if (endpoint != Path.Combine(controlDirectory, "owner.sock"))
        {
            throw new IOException("The Unix Run endpoint is outside its private directory.");
        }

        // Resolve the endpoint beneath the verified held directory and keep sockaddr_un short,
        // regardless of how deep the configured Node data directory is.
        return new UnixDomainSocketEndPoint(LinuxRunCgroup.DescriptorPath(directory) + "/owner.sock");
    }

    internal static string Executable(int pid) =>
        new FileInfo("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/exe").LinkTarget
            ?? throw new IOException("The native peer's executable identity is unavailable.");

    internal static void Require(Socket socket, int pid, long start, string? expectedExecutable)
    {
        var owned = false;
        try
        {
            socket.SafeHandle.DangerousAddRef(ref owned);
            uint length = 12;
            if (GetPeerCredentials(socket.SafeHandle.DangerousGetHandle().ToInt32(), 1, 17, out var peer, ref length) != 0)
            {
                throw new IOException("The local Run peer identity is unavailable.", new Win32Exception(Marshal.GetLastPInvokeError()));
            }

            if (length != 12 || pid <= 0 || pid != peer.ProcessId || LinuxRunCgroup.UserId != peer.UserId ||
                ProcFs.Stat(pid) is not { State: not ('Z' or 'X') } process || process.StartTicks != start ||
                expectedExecutable is not null && Executable(pid) != expectedExecutable)
            {
                throw new IOException("The local Run peer does not match its expected native identity.");
            }

            if (ProcFs.Stat(pid) is not { State: not ('Z' or 'X') } confirmed || confirmed.StartTicks != start)
            {
                throw new IOException("The local Run peer changed while its executable was checked.");
            }
        }
        finally
        {
            if (owned)
            {
                socket.SafeHandle.DangerousRelease();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Peer
    {
        internal int ProcessId;
        internal uint UserId;
        internal uint GroupId;
    }

    [LibraryImport("libc", EntryPoint = "getsockopt", SetLastError = true)]
    private static partial int GetPeerCredentials(int descriptor, int level, int option, out Peer peer, ref uint length);
}
