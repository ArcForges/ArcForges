// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// The actual Node proves its connection to the configured loopback Center, refreshes its credential,
/// and closes the authenticated channel on sign-out.
/// </summary>
[Trait("loop", "local")]
public sealed class CloudChannelTests
{
    [Fact]
    public async Task TheNodeProcessHoldsAProvedChannelAndLeavesNoCredentialInItsFiles()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        await using var node = TestNode.Create();
        var connectLog = Path.Combine(node.Root, "connect.log");
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        node.Environment[CloudLinkTestHooks.ConnectLog] = connectLog;
        node.Environment[CloudLinkTestHooks.RefreshSeconds] = "15";

        var initialNode = await node.StartNodeAsync();
        byte[] nodeId;
        await using (var human = await node.HumanChannelAsync())
        {
            nodeId = (await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct)).Value.Node.Node.NodeId.Value.ToByteArray();
        }

        await node.StopNodeAsync();
        // The stop command observes the endpoint. The original process still owns the instance guard until its shutdown finishes.
        await initialNode.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(30), ct);
        var issued = center.Issue(nodeId, "Closed Loop");
        CloudLinkHostTests.Seed(node.DataRoot, nodeId, center, issued);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.Channel.RegisterNodeKey(issued.AccessToken, key.PublicKey);
        }

        await node.StartNodeAsync();
        var connection = await center.Channel.ProvedAsync();
        await using (var human = await node.HumanChannelAsync())
        {
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.Relay == RelayState.Connected,
                TimeSpan.FromSeconds(30), "the channel is connected");
            Assert.Contains(CloudLinkService.ChannelFeature, (await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct)).Value.Node.Features);
        }

        // The node's refreshes on the hook's cadence each send TokenRefresh on the open channel.
        await TestNode.WaitAsync(() => connection.TokenRefreshes.Count >= 1, TimeSpan.FromSeconds(60), "TokenRefresh after a refresh");
        Assert.Equal(CloudLinkHostTests.Stored(node.DataRoot, nodeId, center)!.AccessToken, connection.TokenRefreshes[^1]);

        // A HUMAN sign-out ends the credential (nothing is left in the isolated store) and closes the channel.
        await using (var human = await node.HumanChannelAsync())
        {
            var signedOut = await human.Account.SignOutAsync(new AccountServiceSignOutRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            }, cancellationToken: ct);
            Assert.Null(signedOut.Error);
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.Relay == RelayState.Disabled,
                TimeSpan.FromSeconds(15), "the channel is disabled after the sign-out");
        }

        await connection.Done.WaitAsync(TimeSpan.FromSeconds(15), ct);
        await node.StopNodeAsync();

        var lines = File.ReadAllLines(connectLog);
        Assert.All(lines, line => Assert.StartsWith("127.0.0.1:" + center.Endpoint.Port + " sent ", line, StringComparison.Ordinal));
        var log = TestNode.ReadShared(node.NodeLog);
        Assert.Contains("cloud.channel.connected", log, StringComparison.Ordinal);

        // N1-22: no token of the center reaches a file outside the secret store.
        await TestNode.WaitAsync(() => node.LiveProcesses().Count == 0, TimeSpan.FromSeconds(30), "the node and its supervisor to exit");
        var secrets = Path.Combine(node.DataRoot, "run", "test-secrets") + Path.DirectorySeparatorChar;
        var read = new List<string>();
        foreach (var file in Directory.EnumerateFiles(node.Root, "*", SearchOption.AllDirectories)
            .Where(file => !file.StartsWith(secrets, StringComparison.Ordinal) && !file.EndsWith(".lock", StringComparison.Ordinal)).ToList())
        {
            if (CloudLinkHostTests.ReadAllShared(file) is not { } bytes)
            {
                continue;
            }

            read.Add(file);
            var text = System.Text.Encoding.Latin1.GetString(bytes);
            Assert.False(text.Contains("afr1.", StringComparison.Ordinal) || text.Contains("afa1.", StringComparison.Ordinal), "a token in " + file);
        }

        Assert.Contains(read, file => file.EndsWith("node.db", StringComparison.Ordinal));
    }
}
