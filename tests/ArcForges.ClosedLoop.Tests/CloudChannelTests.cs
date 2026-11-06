// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// AF-CTR-05 N1 (G.2 rows N1-15 and N1-22, process level): a REAL <c>arcforges node run --test-mode</c> process holds a proved channel to
/// FakeCenter's channel peer (MOCKED center, compiled in from the cloud-link test project), answers a call with a result signed by its node
/// key, sends TokenRefresh after its refreshes, and leaves no access token, refresh token or call payload in any file outside its secret
/// store (log, journal, connect log, node.db). The credential and the key are seeded test-side as in <see cref="CloudLinkHostTests"/>.
/// </summary>
[Trait("loop", "local")]
public sealed class CloudChannelTests
{
    [Fact]
    public async Task TheNodeProcessHoldsAProvedChannelAndLeavesNoSecretOrPayloadInItsFiles()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        await using var node = TestNode.Create();
        var connectLog = Path.Combine(node.Root, "connect.log");
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        node.Environment[CloudLinkTestHooks.ConnectLog] = connectLog;
        node.Environment[CloudLinkTestHooks.RefreshSeconds] = "15";

        await node.StartNodeAsync();
        byte[] nodeId;
        await using (var human = await node.HumanChannelAsync())
        {
            nodeId = (await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct)).Value.Node.Node.NodeId.Value.ToByteArray();
        }

        await node.StopNodeAsync();
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

        // A call whose payload carries a marker: verified, refused by part N1's dispatcher, signed; the payload is never parsed or stored.
        var marker = "N1MARKER" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        var submit = new TaskServiceSubmitTaskRequest { Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() } };
        submit.Spec = new TaskSpec { WorkingDirectory = "/srv/" + marker };
        var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec { Method = RoutedMethod.SubmitNodeTask, Payload = submit.ToByteArray() });
        await connection.SendCallAsync(call);
        await TestNode.WaitAsync(() => !connection.VerifiedResults.IsEmpty, TimeSpan.FromSeconds(15), "the signed result");
        Assert.Empty(connection.UnverifiedResults);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, connection.VerifiedResults.Single().Header.Outcome);

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
        Assert.Contains("cloud.channel.call_answered", log, StringComparison.Ordinal);

        // N1-22: no token of the center and no payload byte string reaches a file outside the secret store.
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
            Assert.False(text.Contains(marker, StringComparison.Ordinal), "the call payload in " + file);
        }

        Assert.Contains(read, file => file.EndsWith("node.db", StringComparison.Ordinal));
    }
}
