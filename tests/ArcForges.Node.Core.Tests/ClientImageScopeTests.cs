// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Node.Api;

namespace ArcForges.Node.Core.Tests;

public sealed class ClientImageScopeTests
{
    /// <summary>
    /// 11 section 1 (review round 1): the client-image test hook applies only in test mode on an isolated test node, where the endpoint, the
    /// configuration file and the data root are all overridden; on the user's real endpoint, configuration or data root it is ignored.
    /// </summary>
    [Fact]
    public void TheClientImageTestHookAppliesOnlyToAnIsolatedTestNode()
    {
        var root = Path.Combine(Path.GetTempPath(), "arcforges-isolated");
        var endpoint = OperatingSystem.IsWindows() ? "af-test-pipe" : Path.Combine(root, "node.sock");
        var config = Path.Combine(root, "config", "node.json");
        var data = Path.Combine(root, "data");
        var realRoot = NodeLocations.DefaultDataRoot();
        var realEndpoint = NodeLocations.Endpoint(testMode: false, realRoot).Address;
        var realConfig = NodeLocations.ConfigFile(testMode: false);
        Assert.True(ClientImages.TestHookApplies(testMode: true, endpoint, config, data));
        Assert.False(ClientImages.TestHookApplies(testMode: false, endpoint, config, data));
        Assert.False(ClientImages.TestHookApplies(testMode: true, realEndpoint, config, data));
        Assert.False(ClientImages.TestHookApplies(testMode: true, endpoint, realConfig, data));
        Assert.False(ClientImages.TestHookApplies(testMode: true, endpoint, config, realRoot));
    }
}
