// SPDX-License-Identifier: AGPL-3.0-only
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.Versioning;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.RunSupervisor;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args is not ["--run-control", var path])
        {
            return 2;
        }

        try
        {
            return await RunAsync(path).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            // Launch input, private paths and environment values never enter diagnostics.
            Console.Error.WriteLine("run_owner_startup_failed " + error.GetType().Name);
            return 2;
        }
    }

    private static async Task<int> RunAsync(string path)
    {
        using var admission = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        if (OperatingSystem.IsWindows())
        {
            return await RunWindowsAsync(path, admission.Token).ConfigureAwait(false);
        }

        return OperatingSystem.IsLinux() ? await RunLinuxAsync(path, admission.Token).ConfigureAwait(false) : 2;
    }

    [SupportedOSPlatform("windows")]
    private static async Task<int> RunWindowsAsync(string path, CancellationToken cancellationToken)
    {
        using var manifest = WindowsMxcPathLease.Open(path, directory: false, privateObject: true);
        var launch = RunWire.ReadLaunch(path, out var launchBinding);
        var identity = await WindowsRunWorker.ReadyAsync(launch, cancellationToken).ConfigureAwait(false);
        try
        {
            return await new RunWorkerController(launch, launchBinding, identity, token => AcceptWindowsAsync(launch, token),
                WindowsRunWorker.StartAsync, manifest.DeletePrivateFile, () => WindowsRunWorker.RecoveryBoundaryHandle)
                .RunAsync().ConfigureAwait(false);
        }
        finally
        {
            WindowsRunWorker.ReleaseRecoveryBoundary();
        }
    }

    [SupportedOSPlatform("windows")]
    private static async ValueTask<RunControlConnection> AcceptWindowsAsync(RunLaunchSpec launch, CancellationToken cancellationToken)
    {
        var pipe = new NamedPipeServerStream(launch.ControlEndpoint, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        try
        {
            await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            return new(pipe, reconnect =>
            {
                if (reconnect is null)
                {
                    WindowsRunWorker.RequireControlPeer(launch, pipe.SafePipeHandle);
                }
                else
                {
                    WindowsRunWorker.RequireRecoveryPeer(launch, pipe.SafePipeHandle, reconnect.ProcessId, reconnect.CreationIdentity);
                }
            });
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    [SupportedOSPlatform("linux")]
    private static async Task<int> RunLinuxAsync(string path, CancellationToken cancellationToken)
    {
        var launch = RunWire.ReadLaunch(path, out var launchBinding);
        var identity = await LinuxRunWorker.ReadyAsync(launch, cancellationToken).ConfigureAwait(false);
        try
        {
            using var server = LinuxRunWorker.BindControl(launch);
            return await new RunWorkerController(launch, launchBinding, identity, token => AcceptLinuxAsync(launch, server, token),
                LinuxRunWorker.StartAsync, () => File.Delete(RunWire.LaunchPath(launch))).RunAsync().ConfigureAwait(false);
        }
        finally
        {
            LinuxRunWorker.ReleaseControlDirectory();
        }
    }

    [SupportedOSPlatform("linux")]
    private static async ValueTask<RunControlConnection> AcceptLinuxAsync(RunLaunchSpec launch, Socket server, CancellationToken cancellationToken)
    {
        var peer = await server.AcceptAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return new(new NetworkStream(peer, ownsSocket: true), reconnect =>
            {
                if (reconnect is null)
                {
                    LinuxRunWorker.RequireControlPeer(launch, peer);
                }
                else
                {
                    LinuxRunWorker.RequireRecoveryPeer(launch, peer, reconnect.ProcessId, reconnect.CreationIdentity);
                }
            });
        }
        catch
        {
            peer.Dispose();
            throw;
        }
    }
}
