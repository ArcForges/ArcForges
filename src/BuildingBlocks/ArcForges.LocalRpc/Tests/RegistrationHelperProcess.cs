// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using Grpc.Core;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// The child side of the opt-in process checks: a real process that reads its private bootstrap resource from its inherited standard
/// input (never argv, environment or a file), connects to the endpoint the descriptor names, registers, calls an ordinary service and
/// keeps its lease with a lease keeper until it is killed. Never started in a normal test run.
/// </summary>
internal static class RegistrationHelperProcess
{
    [SuppressMessage("Design", "CA1031", Justification = "A helper reports any failure on its output and through its exit code.")]
    internal static async Task<int> RunAsync()
    {
        var line = await Console.In.ReadLineAsync().ConfigureAwait(false) ?? throw new InvalidOperationException("No bootstrap resource arrived.");
        using var bootstrap = LocalRpcChildBootstrap.FromResource(Convert.FromBase64String(line));
        await using var channel = LocalRpcClientChannel.Create(bootstrap.Descriptor.Endpoint!, new LocalRpcLimits { ConnectTimeout = TimeSpan.FromSeconds(5) });
        RegisteredChild child;
        try
        {
            child = await ChildClient.RegisterAsync(channel.CallInvoker, bootstrap, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is RpcException or IOException or HttpRequestException)
        {
            await Say("REFUSED " + exception.GetType().Name).ConfigureAwait(false);
            return 3;
        }

        await Say("REGISTERED " + Convert.ToHexStringLower(child.Nonce)).ConfigureAwait(false);
        var status = await ChildClient.ListStatusAsync(child.Authenticated, CancellationToken.None).ConfigureAwait(false);
        await Say("CALL " + status.StatusCode).ConfigureAwait(false);
        await using var keeper = LocalRpcLeaseKeeper.Start(
            (command, token) => ChildClient.RenewAsync(child.Authenticated, command, token),
            TimeProvider.System,
            TimeSpan.FromMilliseconds(500),
            TimeSpan.FromSeconds(2));
        await Say("ALIVE").ConfigureAwait(false);
        await Task.Delay(Timeout.InfiniteTimeSpan, keeper.Lost).ConfigureAwait(false);
        return 0;
    }

    private static async Task Say(string line)
    {
        await Console.Out.WriteLineAsync(line).ConfigureAwait(false);
        await Console.Out.FlushAsync().ConfigureAwait(false);
    }
}
