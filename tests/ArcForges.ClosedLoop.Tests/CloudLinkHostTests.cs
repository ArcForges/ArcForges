// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using ArcForges.Node.Store;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// N1-21: a REAL <c>arcforges node run --test-mode</c> process whose center is FakeCenter (MOCKED center; compiled in from the cloud-link
/// test project, its one other consumer) through the test-mode hook <c>ARCFORGES_TEST_CENTER_URL</c>. The credential is seeded test-side:
/// FakeCenter issues it as a completed sign-in would, and the test writes it into the node's isolated test store and link file before the
/// node starts (no hook, flag or RPC of the node imports a credential); so is the node key, as a sign-in creates it. What it proves: the
/// test-center override refuses a HUMAN <c>center_url</c> update (N1 decision G-6); the host starts the link at step 8, shows the node key,
/// refreshes on the hook's cadence, keeps the credential across a restart, turns a revocation into the signed-out state with a notification
/// and deletes the key, signs out over the API, contacts no authority but its configured center, and writes no token to any file outside
/// its secret store (log, journal and notifications, connect log).
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

            // G-6: while the test-center override names the center, a HUMAN center_url update is refused and nothing is written.
            var config = Path.Combine(node.ConfigDirectory, "node.json");
            var before = File.ReadAllBytes(config);
            var refused = await human.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                CenterUrl = "https://other.example.test",
            }, cancellationToken: ct);
            Assert.Equal("invalid_state", refused.Error.Code);
            Assert.Equal(ErrorCategory.State, refused.Error.Category);
            Assert.Equal("test_override", refused.Error.Details.State.State);
            Assert.Equal(before, File.ReadAllBytes(config));
        }

        await node.StopNodeAsync();
        var issued = center.Issue(nodeId, "Closed Loop");
        Seed(node.DataRoot, nodeId, center, issued);
        var keys = NodeKeyStores.ForTestDataRoot(node.DataRoot);
        using (keys.Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
        }

        var fingerprint = keys.Recorded()!.Fingerprint;

        await node.StartNodeAsync();
        await using (var human = await node.HumanChannelAsync())
        {
            var status = (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status;
            Assert.True(status.SignedIn);
            Assert.Equal(fingerprint, status.NodeKeyFingerprint);
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
        Assert.Null(keys.Recorded());
        Assert.Empty(Directory.GetFiles(((FileNodeKeyBackend)keys.Backend).Directory));
        await node.StopNodeAsync();

        // A new credential, then a HUMAN sign-out over the API: revoked at the center, everything deleted locally.
        var second = center.Issue(nodeId, "Closed Loop");
        Seed(node.DataRoot, nodeId, center, second);
        using (keys.Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
        }

        await node.StartNodeAsync();
        await using (var human = await node.HumanChannelAsync())
        {
            Assert.True((await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.SignedIn);
            var signedOut = await human.Account.SignOutAsync(new AccountServiceSignOutRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            }, cancellationToken: ct);
            Assert.Null(signedOut.Error);
            Assert.False((await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.SignedIn);
            var notifications = await human.Node.ListNotificationsAsync(new NodeServiceListNotificationsRequest(), cancellationToken: ct);
            Assert.All(notifications.Value.Notifications, item => Assert.DoesNotContain("afr1.", item.ToString(), StringComparison.Ordinal));
        }

        Assert.Single(center.CallsOf("SignOutNode"));
        Assert.False(center.IsLive(second.RefreshToken));
        Assert.Null(Stored(node.DataRoot, nodeId, center));
        Assert.Null(keys.Recorded());
        await node.StopNodeAsync();

        // TestCredentialIsNeverSentToAnotherCenter, process level: every attempted authority is the configured center's (self-reported by the
        // seam; the FakeCenter call list is the center side).
        var lines = File.ReadAllLines(connectLog);
        Assert.NotEmpty(lines);
        Assert.All(lines, line => Assert.Equal("127.0.0.1:" + center.Endpoint.Port + " sent", line));

        // TestNoSecretReachesTheNodeLog: no token the center issued, no token prefix (read as the node shares it: Windows keeps it open).
        var log = TestNode.ReadShared(node.NodeLog);
        Assert.DoesNotContain("afr1.", log, StringComparison.Ordinal);
        Assert.DoesNotContain("afa1.", log, StringComparison.Ordinal);
        Assert.Contains("cloud.credential_ended", log, StringComparison.Ordinal);

        // SEC-14 beyond the log: no file of the node outside its secret store (the journal with its events and notifications, the
        // supervisor log, the link and key-set files, the connect log) holds a token. Lock files (a process ID, held locked) are skipped.
        var secrets = Path.Combine(node.DataRoot, "run", "test-secrets") + Path.DirectorySeparatorChar;
        var scanned = Directory.EnumerateFiles(node.Root, "*", SearchOption.AllDirectories)
            .Where(file => !file.StartsWith(secrets, StringComparison.Ordinal) && !file.EndsWith(".lock", StringComparison.Ordinal)).ToList();
        Assert.Contains(scanned, file => file.EndsWith("node.db", StringComparison.Ordinal));
        foreach (var file in scanned)
        {
            var text = System.Text.Encoding.Latin1.GetString(ReadAllShared(file));
            Assert.False(text.Contains("afr1.", StringComparison.Ordinal) || text.Contains("afa1.", StringComparison.Ordinal), "a token in " + file);
        }
    }

    private static byte[] ReadAllShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
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
