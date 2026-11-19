// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Globalization;
using System.Net.Sockets;
using System.Runtime.Versioning;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.RunSupervisor.Protocol;
using Microsoft.Mxc.Sdk.V1;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("linux")]
internal static class LinuxRunWorker
{
    private static PreparedOwner? s_prepared;
    private static SafeFileHandle? s_controlDirectory;
    private static string? s_launcherImageHash;

    internal static Socket BindControl(RunLaunchSpec spec)
    {
        if (s_controlDirectory is not null)
        {
            throw new InvalidOperationException("The Linux Run control listener is already bound.");
        }

        var directory = LinuxRunCgroup.OpenPrivateDirectory(spec.ControlDirectory);
        Socket? listener = null;
        try
        {
            listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(LinuxRunNativePeer.ControlAddress(spec, directory));
            listener.Listen(4);
            // Socket.Dispose unlinks the bound name. Hold the pathname descriptor
            // through listener disposal so that its fd alias cannot be reused.
            s_controlDirectory = directory;
            return listener;
        }
        catch
        {
            listener?.Dispose();
            directory.Dispose();
            throw;
        }
    }

    internal static void ReleaseControlDirectory()
    {
        s_controlDirectory?.Dispose();
        s_controlDirectory = null;
        s_prepared?.Scope.Dispose();
        s_prepared = null;
        s_launcherImageHash = null;
    }

    internal static void RequireControlPeer(RunLaunchSpec spec, Socket socket)
    {
        if (spec.LauncherProcessId <= 0 || !long.TryParse(spec.LauncherCreationIdentity, NumberStyles.None,
            CultureInfo.InvariantCulture, out var creation) || creation <= 0 || string.IsNullOrEmpty(spec.LauncherPath))
        {
            throw new IOException("The Run handoff did not bind the launching Node's native identity.");
        }

        LinuxRunNativePeer.Require(socket, spec.LauncherProcessId, creation, spec.LauncherPath);
        s_launcherImageHash ??= LinuxRunMxcAssets.ReadRunningImageHash(spec.LauncherProcessId, creation);
    }

    internal static void RequireRecoveryPeer(RunLaunchSpec spec, Socket socket, int processId, string creationIdentity)
    {
        if (s_launcherImageHash is not { } expectedImage || string.IsNullOrEmpty(spec.LauncherPath)
            || !long.TryParse(creationIdentity, NumberStyles.None, CultureInfo.InvariantCulture, out var creation) || creation <= 0)
        {
            throw new IOException("The Node recovery peer's native identity is unavailable.");
        }

        LinuxRunNativePeer.Require(socket, processId, creation, spec.LauncherPath);
        if (LinuxRunMxcAssets.ReadRunningImageHash(processId, creation) != expectedImage)
        {
            throw new IOException("The Node recovery peer's executable differs from the original launcher.");
        }
    }

    internal static async ValueTask<RunOwnerIdentity> ReadyAsync(RunLaunchSpec spec, CancellationToken cancellationToken)
    {
        if (s_prepared is not null)
        {
            throw new InvalidOperationException("The Linux Run owner was already prepared.");
        }

        var ready = await ReadScopeAsync(spec, cancellationToken).ConfigureAwait(false);
        try
        {
            var identity = LinuxRunNativePeer.Identity(spec, ready.State, ready.Scope);
            s_prepared = new PreparedOwner(identity, ready.State, ready.Scope);
            return identity;
        }
        catch
        {
            ready.Scope.Dispose();
            throw;
        }
    }

    internal static async ValueTask<IRunWorkerSession> StartAsync(RunLaunchSpec spec, RunRelease release, CancellationToken cancellationToken)
    {
        var prepared = s_prepared;
        s_prepared = null;
        if (prepared is null)
        {
            throw new RunNativeException("release_linux_owner", "linux_owner_was_not_prepared", payloadNotStarted: true);
        }

        var transferred = false;
        try
        {
            var request = await PreparePayloadAsync(spec, release, prepared, cancellationToken).ConfigureAwait(false);
            var session = await LinuxSdkWorkerSession.StartAsync(spec, request, prepared.State, prepared.Scope, cancellationToken).ConfigureAwait(false);
            transferred = true;
            return session;
        }
        finally
        {
            if (!transferred)
            {
                prepared.Scope.Dispose();
            }
        }
    }

    private static async ValueTask<ContainerRequest> PreparePayloadAsync(RunLaunchSpec spec, RunRelease release,
        PreparedOwner prepared, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (release.NativeBoundaryHandle.HasValue)
            {
                throw new RunNativeException("release_linux_owner", "unexpected_linux_boundary_handle");
            }

            var current = await LinuxRunSystemd.ReadAsync(prepared.State.Name, cancellationToken).ConfigureAwait(false);
            if (prepared.Identity != LinuxRunNativePeer.Identity(spec, current, prepared.Scope))
            {
                throw new RunNativeException("release_linux_owner", "linux_owner_generation_changed");
            }

            LinuxRunLauncher.RequireReadback(spec, current, prepared.Scope);
            var request = LinuxSdkRequest.Build(spec);
            // These are exact official 1.0.1 assets and fixed system helpers on this host.
            LinuxRunMxcAssets.Verify(spec);
            return request;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or OperationCanceledException
            or Win32Exception or InvalidOperationException or ArgumentException)
        {
            var empty = prepared.Scope.TryContainsOnlyOwner(prepared.State.OwnerPid, prepared.State.OwnerStartTicks);
            if (error is RunNativeException native)
            {
                throw new RunNativeException(native.Phase, native.NativeCode, empty, payloadNotStarted: true);
            }

            var code = error is OperationCanceledException ? "linux_worker_startup_cancelled" : error.GetType().Name;
            throw new RunNativeException("prepare_linux_payload", code, empty, payloadNotStarted: true);
        }
    }

    private sealed record PreparedOwner(RunOwnerIdentity Identity, LinuxRunServiceState State, LinuxRunCgroup Scope);

    private static async Task<(LinuxRunServiceState State, LinuxRunCgroup Scope)> ReadScopeAsync(RunLaunchSpec spec, CancellationToken cancellationToken)
    {
        var unit = spec.BoundaryDescriptor ?? throw new IOException("The Linux owner was not assigned a Run unit.");
        var state = await LinuxRunSystemd.ReadAsync(unit, cancellationToken).ConfigureAwait(false);
        if (state.OwnerPid != Environment.ProcessId || state.ActiveState != "active" || state.SubState != "running")
        {
            throw new IOException("The supervisor is not the actual executing Run unit owner.");
        }

        var scope = LinuxRunSystemd.OpenOwnerScope(state);
        try
        {
            LinuxRunLauncher.RequireReadback(spec, state, scope);
            return (state, scope);
        }
        catch
        {
            scope.Dispose();
            throw;
        }
    }
}
