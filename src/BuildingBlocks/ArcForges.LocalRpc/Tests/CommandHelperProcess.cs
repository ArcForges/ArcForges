// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.LocalRpc.Platform.V1;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// The helper process of the opt-in command checks: a real <see cref="LocalRpcServer"/> over a real Named Pipe or Unix socket that serves the
/// broker double and the cancel probe, with its receipt table in this process's memory (so killing the process loses it) and the owner store as
/// files (so the parent sees what the process committed). Arguments: <c>command|pipe or unix|address|store directory|park before, park after or run</c>.
/// </summary>
internal static class CommandHelperProcess
{
    internal static async Task<int> RunAsync(string[] arguments)
    {
        var kind = arguments[1];
        var address = arguments[2];
        var store = new OwnerStore(arguments[3]);
        var mode = arguments[4];
        var endpoint = string.Equals(kind, "pipe", StringComparison.Ordinal)
            ? LocalRpcEndpoint.NamedPipe(address)
            : LocalRpcEndpoint.UnixDomainSocket(address);
        await using var receipts = new LocalRpcCommandReceipts();
        var broker = new BrokerDouble(store, receipts)
        {
            ParkBeforeCommit = string.Equals(mode, "before", StringComparison.Ordinal),
            ParkAfterCommit = string.Equals(mode, "after", StringComparison.Ordinal),
            OnReached = (point, id) => Console.Out.WriteLine("REACHED " + point + " " + id.ToString("N")),
        };
        var server = LocalRpcServer.CreateBuilder(endpoint)
            .AddService(broker)
            .AddService(new CommandProbeService(receipts))
            .AddService(new RecordingBootstrapService())
            .RegisterControl(LocalRpcControlOperation.Bootstrap, LocalBootstrapService.Descriptor.FullName, "Challenge")
            .RegisterControl(LocalRpcControlOperation.Cancellation, CommandProbe.Cancel)
            .RegisterControl(LocalRpcControlOperation.Health, CommandProbe.Health)
            .Build();
        await server.StartAsync().ConfigureAwait(false);
        await Console.Out.WriteLineAsync("READY").ConfigureAwait(false);
        await Console.Out.FlushAsync().ConfigureAwait(false);
        await Task.Delay(Timeout.InfiniteTimeSpan).ConfigureAwait(false);
        GC.KeepAlive(server);
        return 0;
    }
}
