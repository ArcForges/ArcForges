// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using Grpc.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N1-9 and N1-2: AccountService and the center setting on a real node in the test process, published through the real LocalRpc endpoint
/// (a named pipe or a Unix socket) and reached through the real client library. MOCKED center (FakeCenter); ISOLATED store
/// (IsolatedSecretStore, with a scripted delay where named).
/// </summary>
public sealed class AccountServiceTests
{
    [Fact]
    public async Task GetAccountStatusReportsEveryFieldItCanForEveryOrigin()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        foreach (var origin in new[] { Origin.Human, Origin.Script, Origin.Agent })
        {
            await using var channel = await node.ChannelAsync(origin);
            var status = (await channel.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: TestContext.Current.CancellationToken)).Value.Status;
            Assert.False(status.SignedIn);
            Assert.Equal(center.Endpoint.Url, status.CenterUrl);
            Assert.Equal(RelayState.Disabled, status.Relay);
            Assert.Equal("not_delivered", status.RelayReason);
            Assert.False(status.CloudLinkEnabled);
            Assert.Null(status.Entitlement);
            Assert.False(status.HasNodeKeyFingerprint);
        }

        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(node.Runtime.NodeId.Span, center.Endpoint.Origin, TimeProvider.System))
        {
            await node.Cloud.AdoptAsync(center.Issue(node.Runtime.NodeId.Span, "Ada"), center.Endpoint);
            await using var channel = await node.ChannelAsync(Origin.Agent);
            var status = (await channel.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: TestContext.Current.CancellationToken)).Value.Status;
            Assert.True(status.SignedIn);
            Assert.True(status.NodeEnrolled);
            Assert.Equal("Ada", status.AccountDisplayName);
            Assert.Equal("t***@example.test", status.AccountEmailMasked);
            Assert.Equal(CloudIdentity.Fingerprint(key.PublicKey), status.NodeKeyFingerprint);
            Assert.NotNull(status.CredentialExpiresAt);
            Assert.False(status.CredentialInOsStore);
            Assert.Contains("isolated_test_backend", status.Warnings);
            var info = (await channel.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: TestContext.Current.CancellationToken)).Value.Node;
            Assert.True(info.AccountLinked);
        }
    }

    [Fact]
    public async Task SignOutRevokesRemotelyDeletesEverythingLocallyAndIsJournaled()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        var issued = center.Issue(node.Runtime.NodeId.Span);
        await node.Cloud.AdoptAsync(issued, center.Endpoint);
        using (NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(node.Runtime.NodeId.Span, center.Endpoint.Origin, TimeProvider.System))
        {
        }

        await using var human = await node.ChannelAsync(Origin.Human);
        var response = await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(response.Error);
        Assert.Empty(response.Meta.Warnings);
        Assert.Equal(EffectCertainty.Happened, response.Value.Receipt.Effect);
        Assert.False(center.IsLive(issued.RefreshToken));
        Assert.Single(center.CallsOf("SignOutNode"));
        Assert.False(node.Cloud.AccountLinked);
        Assert.DoesNotContain(CredentialTarget(node, center), node.Secrets.Names());
        Assert.False(File.Exists(node.Cloud.Storage.LinkPath));
        Assert.Null(NodeKeyStores.ForTestDataRoot(node.DataRoot).Recorded());
        var journal = node.Runtime.Store.Read(reader => node.Runtime.Journal.ReadAfter(reader, 0, node.Runtime.Journal.Latest,
            new HashSet<EventTopic> { EventTopic.Account }, 1000));
        Assert.Contains(journal, item => item.Account is { SignedIn: true });
        Assert.False(journal.Last().Account.SignedIn);
        Assert.False((await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: TestContext.Current.CancellationToken)).Value.Node.AccountLinked);
    }

    [Fact]
    public async Task SignOutAnsweredCredentialRevokedDeletesTheKeyAndIsConfirmed()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        await node.Cloud.AdoptAsync(center.Issue(node.Runtime.NodeId.Span), center.Endpoint);
        using (NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(node.Runtime.NodeId.Span, center.Endpoint.Origin, TimeProvider.System))
        {
        }

        center.Script("SignOutNode", new FakeFault.Transport(16, "auth.credential_revoked"));
        await using var human = await node.ChannelAsync(Origin.Human);
        var response = await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(response.Error);
        Assert.Empty(response.Meta.Warnings);
        Assert.Null(NodeKeyStores.ForTestDataRoot(node.DataRoot).Recorded());
    }

    [Theory]
    [InlineData(502)]
    [InlineData(404)]
    public async Task AnUnreachableCenterStillSignsOutLocallyAndSaysTheRevocationWasNotConfirmed(int status)
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        var issued = center.Issue(node.Runtime.NodeId.Span);
        await node.Cloud.AdoptAsync(issued, center.Endpoint);
        center.Script("SignOutNode", new FakeFault.HttpStatus(status));
        await using var human = await node.ChannelAsync(Origin.Human);
        var response = await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(response.Error);
        Assert.Equal(["remote_sign_out_unconfirmed"], response.Meta.Warnings);
        Assert.True(center.IsLive(issued.RefreshToken));
        Assert.False(node.Cloud.AccountLinked);
        Assert.DoesNotContain(CredentialTarget(node, center), node.Secrets.Names());
    }

    [Fact]
    public async Task SignOutLocalOnlyLeavesTheCenterSessionAlone()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        var issued = center.Issue(node.Runtime.NodeId.Span);
        await node.Cloud.AdoptAsync(issued, center.Endpoint);
        await using var human = await node.ChannelAsync(Origin.Human);
        var response = await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command(), RevokeRemote = false }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(response.Error);
        Assert.Empty(center.CallsOf("SignOutNode"));
        Assert.True(center.IsLive(issued.RefreshToken));
        Assert.DoesNotContain(CredentialTarget(node, center), node.Secrets.Names());
    }

    [Fact]
    public async Task SignOutDuringARefreshWhoseReplyCommitsSignsOutWithTheRotatedCredential()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        var issued = center.Issue(node.Runtime.NodeId.Span);
        await node.Cloud.AdoptAsync(issued, center.Endpoint);

        // A refresh is in flight (held at the center); SignOut waits for it (it never cancels it), then revokes the rotated credential.
        var release = new TaskCompletionSource();
        center.Script("RefreshNodeSession", new FakeFault.Hold(release));
        var refresh = node.Cloud.RefreshAsync(node.Cloud.Generation, CancellationToken.None);
        await Eventually.TrueAsync(() => center.CallsOf("RefreshNodeSession").Count == 1, "the refresh in flight");
        await using var human = await node.ChannelAsync(Origin.Human);
        var signOut = human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken).ResponseAsync;
        await Task.Delay(300, TestContext.Current.CancellationToken);
        Assert.False(signOut.IsCompleted);
        release.SetResult();
        await refresh;
        var response = await signOut;
        Assert.Null(response.Error);
        Assert.Empty(response.Meta.Warnings);
        var signOutCall = Assert.Single(center.CallsOf("SignOutNode"));
        Assert.NotEqual("Bearer " + issued.AccessToken, signOutCall.Authorization);
        Assert.False(center.IsLive(issued.RefreshToken));
    }

    [Fact]
    public async Task NotSignedInIsRefusedAndRecorded()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        await using var human = await node.ChannelAsync(Origin.Human);
        var meta = CloudNode.Command();
        var response = await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = meta }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("not_signed_in", response.Error.Code);
        Assert.Equal(ErrorCategory.State, response.Error.Category);
    }

    [Theory]
    [InlineData(Origin.Script)]
    [InlineData(Origin.Agent)]
    public async Task OnlyAHumanMaySignTheNodeOut(Origin origin)
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        await node.Cloud.AdoptAsync(center.Issue(node.Runtime.NodeId.Span), center.Endpoint);
        await using var channel = await node.ChannelAsync(origin);
        var response = await channel.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("permission_denied", response.Error.Code);
        Assert.True(node.Cloud.AccountLinked);
        Assert.DoesNotContain(center.Calls, call => call.Method == "SignOutNode");
    }

    [Fact]
    public async Task TestSignOutReplayDoesNotCallTheCenterTwice()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        await node.Cloud.AdoptAsync(center.Issue(node.Runtime.NodeId.Span), center.Endpoint);
        await using var human = await node.ChannelAsync(Origin.Human);
        var meta = CloudNode.Command();
        var calls = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = meta }, cancellationToken: TestContext.Current.CancellationToken).ResponseAsync));
        var again = await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = meta }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.All(calls.Append(again), response => Assert.Null(response.Error));
        Assert.Single(center.CallsOf("SignOutNode"));
    }

    [Fact]
    public async Task TestTransientErrorsAreNotRecorded()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        await node.Cloud.AdoptAsync(center.Issue(node.Runtime.NodeId.Span), center.Endpoint);

        // A refusal before the command (here the permission gate) records nothing under the command ID: the same ID later runs.
        var meta = CloudNode.Command();
        await using var script = await node.ChannelAsync(Origin.Script);
        Assert.Equal("permission_denied", (await script.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = meta }, cancellationToken: TestContext.Current.CancellationToken)).Error.Code);
        await using var human = await node.ChannelAsync(Origin.Human);
        var response = await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = meta }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(response.Error);
        Assert.Single(center.CallsOf("SignOutNode"));
    }

    [Fact]
    public async Task SignOutAnswersWithinItsDeadlineWhileASlowRefreshIsInFlight()
    {
        // R-5 (proto finding 3): a refresh meets a cold start (8 s), the sign-out's remote part is slow (9 s); one 15 s budget from the
        // handler's entry covers the wait for the refresh, the remote part and the local ending.
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        var issued = center.Issue(node.Runtime.NodeId.Span);
        await node.Cloud.AdoptAsync(issued, center.Endpoint);
        await Eventually.TrueAsync(() => center.CallsOf("ReportNodeInfo").Count == 1, "the first report");
        center.Script("RefreshNodeSession", new FakeFault.Delay(TimeSpan.FromSeconds(8)));
        center.Script("SignOutNode", new FakeFault.Delay(TimeSpan.FromSeconds(9)));
        var refresh = node.Cloud.RefreshAsync(node.Cloud.Generation, CancellationToken.None);
        await Eventually.TrueAsync(() => center.CallsOf("RefreshNodeSession").Count == 1, "the refresh in flight");
        await using var human = await node.ChannelAsync(Origin.Human);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var response = await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(15), "the sign-out answered after " + watch.Elapsed);
        Assert.Null(response.Error);
        Assert.Contains(AccountServiceHandlerWarning, response.Meta.Warnings);
        Assert.False(node.Cloud.AccountLinked);
        Assert.DoesNotContain(CredentialTarget(node, center), node.Secrets.Names());
        Assert.False(File.Exists(node.Cloud.Storage.LinkPath));
        await refresh;
    }

    [Fact]
    public async Task ANodeJsonEditedWhileSignedInSendsTheCredentialNowhere()
    {
        // Proto probe E through the real host: node.json is rewritten to another center while the node is signed in.
        await using var center = await FakeCenter.StartAsync();
        await using var other = await FakeCenter.StartAsync("/other");
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        var issued = center.Issue(node.Runtime.NodeId.Span);
        await node.Cloud.AdoptAsync(issued, center.Endpoint);
        await Eventually.TrueAsync(() => center.CallsOf("ReportNodeInfo").Count == 1, "the first report");
        File.WriteAllText(node.ConfigPath, File.ReadAllText(node.ConfigPath).Replace(center.Endpoint.Url, other.Endpoint.Url, StringComparison.Ordinal));
        await node.Cloud.RefreshAsync(node.Cloud.Generation, CancellationToken.None);
        Assert.Empty(other.Calls);
        Assert.Empty(center.CallsOf("RefreshNodeSession"));
        Assert.False(node.Cloud.AccountLinked);
        Assert.Contains("credential_for_other_center", node.Cloud.Status().Warnings);
        Assert.Contains(CredentialTarget(node, center), node.Secrets.Names());
        Assert.True(center.IsLive(issued.RefreshToken));
    }

    [Fact]
    public async Task TestSignOutInFlightDoesNotBlockTheWriter()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        await node.Cloud.AdoptAsync(center.Issue(node.Runtime.NodeId.Span), center.Endpoint);

        // A slow center (8 s) and a slow keyring (2 s per delete): the sign-out's I/O runs outside the single writer.
        node.Secrets.DeleteDelay = TimeSpan.FromSeconds(2);
        center.Script("SignOutNode", new FakeFault.Delay(TimeSpan.FromSeconds(8)));
        await using var human = await node.ChannelAsync(Origin.Human);
        var signOut = human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken).ResponseAsync;
        await Eventually.TrueAsync(() => center.CallsOf("SignOutNode").Count == 1, "the sign-out in flight");
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var renamed = await human.Node.RenameNodeAsync(new NodeServiceRenameNodeRequest { Meta = CloudNode.Command(), Name = "while-signing-out" }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(renamed.Error);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(4), "the rename waited " + watch.Elapsed);
        Assert.False(signOut.IsCompleted);
        Assert.Null((await signOut).Error);
    }

    [Theory]
    [InlineData("BeginSignIn")]
    [InlineData("GetSignInFlow")]
    [InlineData("CancelSignIn")]
    [InlineData("SetCloudLink")]
    [InlineData("CreatePhonePairing")]
    [InlineData("GetPhonePairing")]
    [InlineData("ConfirmPhonePairing")]
    [InlineData("RefreshEntitlement")]
    public async Task TheMethodsOfLaterPartsAnswerUnimplemented(string method)
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        await using var human = await node.ChannelAsync(Origin.Human);
        var call = method switch
        {
            "BeginSignIn" => human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken).ResponseAsync,
            "SetCloudLink" => human.Account.SetCloudLinkAsync(new AccountServiceSetCloudLinkRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken).ResponseAsync,
            "CreatePhonePairing" => human.Account.CreatePhonePairingAsync(new AccountServiceCreatePhonePairingRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken).ResponseAsync,
            "GetSignInFlow" => human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest(), cancellationToken: TestContext.Current.CancellationToken).ResponseAsync,
            "CancelSignIn" => human.Account.CancelSignInAsync(new AccountServiceCancelSignInRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken).ResponseAsync,
            "GetPhonePairing" => human.Account.GetPhonePairingAsync(new AccountServiceGetPhonePairingRequest(), cancellationToken: TestContext.Current.CancellationToken).ResponseAsync,
            "ConfirmPhonePairing" => human.Account.ConfirmPhonePairingAsync(new AccountServiceConfirmPhonePairingRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken).ResponseAsync,
            _ => (Task)human.Account.RefreshEntitlementAsync(new AccountServiceRefreshEntitlementRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken).ResponseAsync,
        };
        var failed = await Assert.ThrowsAsync<RpcException>(() => call);
        Assert.Equal(StatusCode.Unimplemented, failed.StatusCode);
    }

    [Fact]
    public async Task TheCenterUrlIsPersistedHumanOnlyAndRefusedWhileSignedIn()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(null);
        await node.StartAsync();
        await using var human = await node.ChannelAsync(Origin.Human);

        // Not test mode: the official default when none is configured.
        var settings = (await human.Node.GetNodeSettingsAsync(new NodeServiceGetNodeSettingsRequest(), cancellationToken: TestContext.Current.CancellationToken)).Value.Settings;
        Assert.Equal(CenterEndpoint.OfficialDefault, settings.CenterUrl);

        // SCRIPT and AGENT are refused without an approval (HUMAN only, no approval path).
        foreach (var origin in new[] { Origin.Script, Origin.Agent })
        {
            await using var other = await node.ChannelAsync(origin);
            var refused = await other.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = CloudNode.Command(), CenterUrl = center.Endpoint.Url }, cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal("permission_denied", refused.Error.Code);
            Assert.Contains("center_url (HUMAN only)", refused.Error.Details.State.Reason, StringComparison.Ordinal);
            var approvals = await human.Approvals.ListApprovalsAsync(new ApprovalServiceListApprovalsRequest(), cancellationToken: TestContext.Current.CancellationToken);
            Assert.Empty(approvals.Value.Approvals);
        }

        var invalid = await human.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = CloudNode.Command(), CenterUrl = "http://example.org" }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_argument", invalid.Error.Code);

        var updated = await human.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = CloudNode.Command(), CenterUrl = center.Endpoint.Url }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(updated.Error);
        Assert.Equal(center.Endpoint.Url, updated.Value.Settings.CenterUrl);
        Assert.Contains("\"centerUrl\": \"" + center.Endpoint.Url + "\"", File.ReadAllText(node.ConfigPath), StringComparison.Ordinal);

        // Signed in: refused with the contract's details, nothing written.
        await node.Cloud.AdoptAsync(center.Issue(node.Runtime.NodeId.Span), center.Endpoint);
        var before = File.ReadAllText(node.ConfigPath);
        var signedIn = await human.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = CloudNode.Command(), CenterUrl = "https://other.example.test" }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_state", signedIn.Error.Code);
        Assert.Equal("signed_in", signedIn.Error.Details.State.State);
        Assert.Equal("center_url", signedIn.Error.Details.State.Reason);
        Assert.Equal(before, File.ReadAllText(node.ConfigPath));

        // After a restart the setting holds; empty resets to the official default once signed out.
        await node.StopAsync();
        await node.StartAsync();
        await using var again = await node.ChannelAsync(Origin.Human);
        Assert.Equal(center.Endpoint.Url, (await again.Node.GetNodeSettingsAsync(new NodeServiceGetNodeSettingsRequest(), cancellationToken: TestContext.Current.CancellationToken)).Value.Settings.CenterUrl);
        Assert.Null((await again.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command(), RevokeRemote = false }, cancellationToken: TestContext.Current.CancellationToken)).Error);
        var reset = await again.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = CloudNode.Command(), CenterUrl = string.Empty }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(reset.Error);
        Assert.Equal(CenterEndpoint.OfficialDefault, reset.Value.Settings.CenterUrl);
    }

    [Fact]
    public async Task ACenterChangeClearsTheOldCentersKeyAndKeySets()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        using (NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(node.Runtime.NodeId.Span, center.Endpoint.Origin, TimeProvider.System))
        {
        }

        node.Cloud.Storage.WriteKeys(new CloudKeySetFile { CenterUrl = center.Endpoint.Url, InstallationId = new string('0', 32) });
        await using var human = await node.ChannelAsync(Origin.Human);
        var updated = await human.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = CloudNode.Command(), CenterUrl = "https://other.example.test" }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(updated.Error);
        Assert.Null(NodeKeyStores.ForTestDataRoot(node.DataRoot).Recorded());
        Assert.False(File.Exists(node.Cloud.Storage.KeysPath));
    }

    [Fact]
    public async Task ACenterChangeEndsARejectedCredentialAndTheNewCenterReceivesNothing()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var other = await FakeCenter.StartAsync("/other");
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        await node.Cloud.AdoptAsync(center.Issue(node.Runtime.NodeId.Span), center.Endpoint);
        await Eventually.TrueAsync(() => center.CallsOf("ReportNodeInfo").Count == 1, "the first report");
        center.Forget();
        await node.Cloud.RefreshAsync(node.Cloud.Generation, CancellationToken.None);
        Assert.Contains("center_rejected_credential", node.Cloud.Status().Warnings);

        // A rejected credential is held signed out, so a HUMAN may change the center: the change ends it (record, key sets, link file).
        await using var human = await node.ChannelAsync(Origin.Human);
        var updated = await human.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = CloudNode.Command(), CenterUrl = other.Endpoint.Url }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(updated.Error);
        Assert.DoesNotContain(CredentialTarget(node, center), node.Secrets.Names());
        Assert.False(File.Exists(node.Cloud.Storage.LinkPath));
        Assert.False(File.Exists(node.Cloud.Storage.KeysPath));
        await node.Cloud.RefreshAsync(node.Cloud.Generation, CancellationToken.None);
        Assert.Empty(other.Calls);
    }

    private const string AccountServiceHandlerWarning = "remote_sign_out_unconfirmed";

    private static string CredentialTarget(CloudNode node, FakeCenter center) => CloudCredentialStore.Target(node.Runtime.NodeId.Span, center.Endpoint.Origin);
}
