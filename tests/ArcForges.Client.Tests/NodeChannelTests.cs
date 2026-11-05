// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;

namespace ArcForges.Client.Tests;

/// <summary>The generated clients a node channel exposes (AF-CTR-04 N1, node-12 item 1: AccountService for the CLI, Desktop and tests).</summary>
public sealed class NodeChannelTests
{
    [Fact]
    public async Task TheChannelExposesTheAccountServiceClient()
    {
        // Creating a channel opens nothing: the endpoint is reached on the first call.
        await using var channel = NodeChannel.Create(OperatingSystem.IsWindows()
            ? LocalRpcEndpoint.NamedPipe("af-client-test-" + Guid.NewGuid().ToString("N")[..12])
            : LocalRpcEndpoint.UnixDomainSocket(Path.Combine(Path.GetTempPath(), "af-client-test-" + Guid.NewGuid().ToString("N")[..12], "node.sock")));
        Assert.IsType<AccountService.AccountServiceClient>(channel.Account);
        Assert.False(channel.EverConnected);
    }
}
