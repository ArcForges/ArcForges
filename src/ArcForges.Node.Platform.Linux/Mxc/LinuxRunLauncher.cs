// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.RunSupervisor.Protocol;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Platform.Linux.Mxc;

/// <summary>Starts V2 Run owners in their dedicated native user service.</summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxRunLauncher : IRunLauncher
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
            controller = await ConnectAsync(spec, ready.State, launchBinding, cancellationToken).ConfigureAwait(false);
            var identity = LinuxRunNativePeer.Identity(spec, ready.State, scope);
            if (identity != controller.Identity)
            {
                throw new IOException("The Run supervisor's authenticated identity differs from the native owner.");
            }

            RequireReadback(spec, ready.State, scope);
            var lease = new LinuxRunLease(spec, ready.State, scope, controller, identity, controlDirectory);
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

    internal static void RequireReadback(RunLaunchSpec spec, LinuxRunServiceState state, LinuxRunCgroup scope)
    {
        if (state.Group != scope.Path || !scope.ContainsOnlyOwner(state.OwnerPid, state.OwnerStartTicks))
        {
            throw new RunNativeException("readback_linux_owner", "linux_owner_cgroup_membership_mismatch");
        }

        LinuxRunSystemd.RequireLimits(spec.CpuMillicores, spec.MemoryMaxBytes, spec.MaxProcesses, spec.CpuWeight, scope.ReadLimits());
    }

    private static async Task<RunControlClient> ConnectAsync(RunLaunchSpec spec, LinuxRunServiceState state, string launchBinding,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        using var directory = LinuxRunCgroup.OpenPrivateDirectory(spec.ControlDirectory);
        var endpoint = LinuxRunNativePeer.ControlAddress(spec, directory);
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
                LinuxRunNativePeer.Require(socket, state.OwnerPid, state.OwnerStartTicks, spec.SupervisorPath);
                LinuxRunMxcAssets.VerifyRunningSupervisor(spec, state.OwnerPid, state.OwnerStartTicks);
                return await RunControlClient.ConnectAsync(stream, spec, launchBinding, deadline.Token).ConfigureAwait(false);
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

    private sealed class LinuxRunLease(RunLaunchSpec spec, LinuxRunServiceState native, LinuxRunCgroup scope,
        RunControlClient controller, RunOwnerIdentity identity, SafeFileHandle controlDirectory) : IRunOwnerLease
    {
        private bool _releaseSent;
        private int _boundaryStopVerified;

        public RunOwnerIdentity Identity { get; } = identity;

        public async ValueTask ActivateAsync(CancellationToken cancellationToken)
        {
            var current = await LinuxRunSystemd.ReadAsync(native.Name, cancellationToken).ConfigureAwait(false);
            if (current.Invocation != native.Invocation || current.Boot != native.Boot || current.Group != native.Group ||
                current.OwnerPid != native.OwnerPid || current.OwnerStartTicks != native.OwnerStartTicks)
            {
                throw new RunNativeException("release_linux_owner", "linux_owner_generation_changed");
            }

            RequireReadback(spec, current, scope);
            _releaseSent = true;
            await controller.ActivateAsync(new RunRelease(), cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask StopAsync(TimeSpan grace, CancellationToken cancellationToken)
        {
            if (scope.IsEmpty())
            {
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
                Volatile.Write(ref _boundaryStopVerified, 1);
            }
        }

        public async ValueTask<RunOwnerObservation> ObserveAsync(CancellationToken cancellationToken)
        {
            var result = RunWire.TryReadObservation(spec);
            if (result is not { IsTerminal: true } && Volatile.Read(ref _boundaryStopVerified) == 0)
            {
                try
                {
                    result = await controller.ObserveAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception error) when (error is IOException or SocketException)
                {
                    result = RunWire.TryReadObservation(spec);
                }
            }

            if (Volatile.Read(ref _boundaryStopVerified) != 0 && scope.IsEmpty())
            {
                // The original owner is gone. Its signed sidecar can no longer change.
                var settled = RunWire.TryReadObservation(spec) ?? result;
                return settled is { IsTerminal: true } ? settled with { GroupEmptyVerified = true } : BoundaryStopObservation(settled);
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

            return result is null
                ? new(RunOwnerState.RecoveryRequired, RunPayloadStart.Unknown, scope.IsEmpty(),
                    NativeError: "linux_owner_observation_unavailable")
                : result with { GroupEmptyVerified = false };
        }

        private static RunOwnerObservation BoundaryStopObservation(RunOwnerObservation? previous)
        {
            // The explicit Stop and held-scope proof establish that execution
            // ended. Only an independent observation can supply executor exit data.
            return new(RunOwnerState.Exited,
                previous?.PayloadStarted == RunPayloadStart.Confirmed ? RunPayloadStart.Confirmed : RunPayloadStart.Unknown,
                true, previous?.RawExitCode, previous?.ExitSource ?? RunExitSources.Unknown, TerminationReason: "user_stop",
                NativeError: previous?.NativeError ?? (previous?.RawExitCode is null ? "linux_official_exit_unobserved" : null));
        }

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
                    cleanupFailed = !_releaseSent && await LinuxRunSystemd.RollbackUnreleasedAsync(native.Name).ConfigureAwait(false)
                        && !TryRemoveUnreleasedLaunch(spec, controlDirectory);
                }
                finally
                {
                    scope.Dispose();
                    controlDirectory.Dispose();
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

    internal static UnixDomainSocketEndPoint ControlAddress(RunLaunchSpec spec, SafeFileHandle directory)
    {
        if (spec.ControlEndpoint != Path.Combine(spec.ControlDirectory, "owner.sock"))
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

            if (length != 12 || pid != peer.ProcessId || LinuxRunCgroup.UserId != peer.UserId ||
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
