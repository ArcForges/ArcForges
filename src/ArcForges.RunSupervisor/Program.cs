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
        await using var pipe = new NamedPipeServerStream(launch.ControlEndpoint, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        return await new RunWorkerController(launch, launchBinding, identity, token => AcceptWindowsAsync(launch, pipe, token),
            WindowsRunWorker.StartAsync, manifest.DeletePrivateFile).RunAsync().ConfigureAwait(false);
    }

    [SupportedOSPlatform("windows")]
    private static async ValueTask<Stream> AcceptWindowsAsync(RunLaunchSpec launch, NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
        WindowsRunWorker.RequireControlPeer(launch, pipe.SafePipeHandle);
        return pipe;
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
    private static async ValueTask<Stream> AcceptLinuxAsync(RunLaunchSpec launch, Socket server, CancellationToken cancellationToken)
    {
        var peer = await server.AcceptAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            LinuxRunWorker.RequireControlPeer(launch, peer);
            return new NetworkStream(peer, ownsSocket: true);
        }
        catch
        {
            peer.Dispose();
            throw;
        }
    }
}
