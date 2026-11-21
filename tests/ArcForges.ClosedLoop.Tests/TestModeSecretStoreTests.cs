// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>The real test-mode Node protects its durable V2 owner key in the fixture's isolated store.</summary>
[Trait("loop", "local")]
public sealed class TestModeSecretStoreTests
{
    [Fact(Timeout = 120_000)]
    public async Task ATestModeNodeKeepsItsOwnerKeyInItsDataRootAcrossARestartAndNeverSelectsAnOsStore()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.Null(Environment.GetEnvironmentVariable(OsSecretStoreGuard.OptInVariable));
        Assert.False(NodeSecretStores.UsesOsSecretStore(testMode: true, optIn: null));
        await using var node = TestNode.Create();
        var secrets = new TestDataRootSecretStore(node.DataRoot);
        string? key = null;
        try
        {
            using var first = await node.StartNodeAsync();
            var starting = Assert.Single(TestNode.LogEvents(node.NodeLog, "node.starting")).GetProperty("fields");
            Assert.True(starting.GetProperty("testMode").GetBoolean());
            Assert.True(starting.GetProperty("osStoresDenied").GetBoolean());
            Assert.Empty(secrets.Names());
            var owner = await OwnerEpochAsync(node);
            key = Assert.Single(secrets.Names());
            Assert.StartsWith(NodeSecretStores.TargetPrefix, key, StringComparison.Ordinal);
            await node.StopNodeAsync();
            Assert.True(first.WaitForExit(TimeSpan.FromSeconds(15)));

            using var second = await node.StartNodeAsync();
            Assert.Equal(owner, await OwnerEpochAsync(node));
            Assert.Equal([key], secrets.Names());
            await node.StopNodeAsync();
            Assert.True(second.WaitForExit(TimeSpan.FromSeconds(15)));
        }
        finally
        {
            if (key is not null)
            {
                Assert.True(secrets.Delete(key));
            }
        }
    }

    private static async Task<ArcForges.Contracts.Foundation.V1.Id> OwnerEpochAsync(TestNode fixture)
    {
        await using var channel = CloudLinkCenterControlTests.OpenChannel(fixture);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var reply = await node.HandshakeAsync(new NodeServiceHandshakeRequest
        {
            Meta = new() { CorrelationId = CommandIds.New() },
        }, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(reply.Error);
        Assert.Equal(16, reply.Value.OwnerEpoch.Value.Length);
        return reply.Value.OwnerEpoch;
    }
}
