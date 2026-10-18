// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// The <c>--test-mode</c> rule of 02-node-service section 4 in a real <c>arcforges node run --test-mode</c> process (the third path of
/// the OS secret-store guard's negative test, 16-testing-strategy section 1 item 4): without the tier's opt-in the node never selects an
/// OS-wide secret store; it keeps its node data key in the file-backed isolated store of its data root, which survives its restart, and
/// the environment's cleanup removes it (and verifies its absence). The child node carries no tripwire switch (it is a production
/// binary), so this rule is what keeps it away from the user's Credential Manager or Secret Service.
/// </summary>
[Trait("loop", "local")]
public sealed class TestModeSecretStoreTests
{
    [Fact(Timeout = 120_000)]
    public async Task ATestModeNodeKeepsItsDataKeyInItsDataRootAcrossARestartAndNeverSelectsAnOsStore()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();

        // The precondition: this routine process carries no opt-in (the test scripts remove it, and TestNode never passes it on).
        Assert.Null(Environment.GetEnvironmentVariable(OsSecretStoreGuard.OptInVariable));
        Assert.False(NodeSecretStores.UsesOsSecretStore(testMode: true, optIn: null));
        await using var node = TestNode.Create();
        using (var first = await node.StartNodeAsync())
        {
            var loaded = await DataKeyLoadedAsync(node, 1);
            Assert.True(loaded.GetProperty("isolated").GetBoolean(), loaded.ToString());
            Assert.Equal(NodeSecretStores.TestBackend.ToString(), loaded.GetProperty("backend").GetString());
            Assert.Equal("1", loaded.GetProperty("keyId").GetString());
            await node.StopNodeAsync();
            Assert.True(first.WaitForExit(TimeSpan.FromSeconds(15)));
        }

        var files = new TestDataRootSecretStore(node.DataRoot);
        var key = Assert.Single(files.Names());
        Assert.StartsWith(NodeSecretStores.TargetPrefix, key, StringComparison.Ordinal);

        // A restart loads the same key version from the data root: no new version, nothing written elsewhere.
        using (var second = await node.StartNodeAsync())
        {
            var reloaded = await DataKeyLoadedAsync(node, 2);
            Assert.True(reloaded.GetProperty("isolated").GetBoolean(), reloaded.ToString());
            Assert.Equal("1", reloaded.GetProperty("keyId").GetString());
            await node.StopNodeAsync();
            Assert.True(second.WaitForExit(TimeSpan.FromSeconds(15)));
        }

        Assert.Equal([key], files.Names());
    }

    private static async Task<System.Text.Json.JsonElement> DataKeyLoadedAsync(TestNode node, int count)
    {
        await TestNode.WaitAsync(() => TestNode.LogEvents(node.NodeLog, "node.data_key.loaded").Count >= count, TimeSpan.FromSeconds(30),
            "the node data key to load");
        return TestNode.LogEvents(node.NodeLog, "node.data_key.loaded")[count - 1].GetProperty("fields");
    }
}
