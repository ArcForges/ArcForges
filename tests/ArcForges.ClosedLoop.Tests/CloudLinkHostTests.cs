// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using ArcForges.Node.Store;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// N1-21: a REAL <c>arcforges node run --test-mode</c> process whose center is FakeCenter (MOCKED center; compiled in from the cloud-link
/// test project, its one other consumer) through the test-mode hook <c>ARCFORGES_TEST_CENTER_URL</c>. The credential is seeded test-side:
/// FakeCenter issues it as a completed sign-in would, and the test writes it into the node's isolated test store and link file before the
/// node starts (no hook, flag or RPC of the node imports a credential). What it proves: the host starts the link at step 8, refreshes on the
/// hook's cadence, keeps the credential across a restart, turns a revocation into the signed-out state with a notification, contacts no
/// authority but its configured center, and writes no token to its log.
/// </summary>
[Trait("loop", "local")]
public sealed class CloudLinkHostTests
{
    [Fact]
    public async Task TheNodeProcessRunsTheLinkAgainstItsConfiguredCenterOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        await using var node = TestNode.Create();
        var connectLog = Path.Combine(node.Root, "connect.log");
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        node.Environment[CloudLinkTestHooks.ConnectLog] = connectLog;
        node.Environment[CloudLinkTestHooks.RefreshSeconds] = "15";

        // The first start creates the store (and its node ID); the test then seeds the credential while the node is stopped.
        await node.StartNodeAsync();
        byte[] nodeId;
        await using (var human = await node.HumanChannelAsync())
        {
            nodeId = (await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct)).Value.Node.Node.NodeId.Value.ToByteArray();
            var settings = (await human.Node.GetNodeSettingsAsync(new NodeServiceGetNodeSettingsRequest(), cancellationToken: ct)).Value.Settings;
            Assert.Equal(center.Endpoint.Url, settings.CenterUrl);
            Assert.False((await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.SignedIn);
        }

        await node.StopNodeAsync();
        var issued = center.Issue(nodeId, "Closed Loop");
        Seed(node.DataRoot, nodeId, center, issued);

        await node.StartNodeAsync();
        await using (var human = await node.HumanChannelAsync())
        {
            var status = (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status;
            Assert.True(status.SignedIn);
            Assert.Equal("Closed Loop", status.AccountDisplayName);
            Assert.Contains("isolated_test_backend", status.Warnings);
            Assert.False(status.CredentialInOsStore);
            Assert.True((await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct)).Value.Node.AccountLinked);
        }

        // The hook's 15 s cadence: the node rotates its credential.
        await TestNode.WaitAsync(() => center.CallsOf("RefreshNodeSession").Count >= 1, TimeSpan.FromSeconds(45), "a refresh by the node process");
        await TestNode.WaitAsync(() => Stored(node.DataRoot, nodeId, center) is { } record && record.RefreshToken != issued.RefreshToken,
            TimeSpan.FromSeconds(15), "the rotated credential is stored");
        await TestNode.WaitAsync(() => center.CallsOf("ReportNodeInfo").Count >= 1, TimeSpan.FromSeconds(30), "the node reports itself");

        // A restart keeps the rotated credential.
        await node.StopNodeAsync();
        var kept = Stored(node.DataRoot, nodeId, center)!;
        Assert.True(center.IsLive(kept.RefreshToken));
        await node.StartNodeAsync();
        await using (var human = await node.HumanChannelAsync())
        {
            Assert.True((await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.SignedIn);
        }

        // The account revokes the device on the web: the next refresh signs the node out, with a notification, and its credential is gone.
        center.Revoke(kept.RefreshToken);
        await using (var human = await node.HumanChannelAsync())
        {
            await TestNode.WaitAsync(async () => !(await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.SignedIn,
                TimeSpan.FromSeconds(45), "signed out after the revocation");
            var notifications = await human.Node.ListNotificationsAsync(new NodeServiceListNotificationsRequest(), cancellationToken: ct);
            Assert.Contains(notifications.Value.Notifications, item => item.Kind == "account_signed_out");
            Assert.False((await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct)).Value.Node.AccountLinked);
        }

        Assert.Null(Stored(node.DataRoot, nodeId, center));
        Assert.False(File.Exists(Path.Combine(node.DataRoot, "run", "cloud-link.json")));
        await node.StopNodeAsync();

        // TestCredentialIsNeverSentToAnotherCenter, process level: every attempted authority is the configured center's (self-reported by the
        // seam; the FakeCenter call list is the center side).
        var lines = File.ReadAllLines(connectLog);
        Assert.NotEmpty(lines);
        Assert.All(lines, line => Assert.Equal("127.0.0.1:" + center.Endpoint.Port + " sent", line));

        // TestNoSecretReachesTheNodeLog: no token the center issued, no token prefix.
        var log = File.ReadAllText(node.NodeLog);
        Assert.DoesNotContain("afr1.", log, StringComparison.Ordinal);
        Assert.DoesNotContain("afa1.", log, StringComparison.Ordinal);
        Assert.Contains("cloud.credential_ended", log, StringComparison.Ordinal);
    }

    private static void Seed(string dataRoot, byte[] nodeId, FakeCenter center, ArcForges.Contracts.Fleet.V1.NodeCredentials issued)
    {
        var secrets = NodeSecretStores.ForTestDataRoot(dataRoot);
        var storage = new CloudCredentialStore(dataRoot, secrets);
        var target = CloudCredentialStore.Target(nodeId, center.Endpoint.Origin);
        storage.WriteRecord(target, new CloudCredentialRecord
        {
            NodeId = Convert.ToHexStringLower(nodeId),
            CenterUrl = center.Endpoint.Url,
            DisplayName = issued.Account.DisplayName,
            InstallationId = Convert.ToHexStringLower(issued.InstallationId.Value.Span),
            AccessToken = issued.AccessToken,
            AccessExpiresAtMs = ProtoTime.ToDateTimeOffset(issued.AccessExpiresAt)!.Value.ToUnixTimeMilliseconds(),
            AccessLifetimeMs = (long)issued.AccessLifetimeMs,
            RefreshToken = issued.RefreshToken,
            SessionExpiresAtMs = ProtoTime.ToDateTimeOffset(issued.SessionExpiresAt)!.Value.ToUnixTimeMilliseconds(),
            WrittenAtMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });
        storage.WriteLink(new CloudLinkFile
        {
            State = LinkStates.SignedIn,
            Backend = secrets.Backend.ToString(),
            Protection = secrets.Protection.ToString(),
            Isolated = true,
            Target = target,
            CenterUrl = center.Endpoint.Url,
            NodeId = Convert.ToHexStringLower(nodeId),
        });
    }

    private static CloudCredentialRecord? Stored(string dataRoot, byte[] nodeId, FakeCenter center) =>
        new CloudCredentialStore(dataRoot, NodeSecretStores.ForTestDataRoot(dataRoot)).ReadRecord(CloudCredentialStore.Target(nodeId, center.Endpoint.Origin));
}
