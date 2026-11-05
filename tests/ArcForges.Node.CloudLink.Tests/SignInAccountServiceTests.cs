// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Tests;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N2-11 and N2-14: AccountService BeginSignIn, GetSignInFlow and CancelSignIn, the permission matrix (HUMAN/SCRIPT/AGENT), the
/// <c>signing_in</c> refusal of <c>center_url</c>, the feature token, a sign-out during a flow (N2 decision N-2) and the explicit abandon of a
/// stranded link (N2 decision R-3), on a real node in the test process over the REAL LocalRpc endpoint. MOCKED center (FakeCenter), MOCKED
/// browser (ScriptedBrowser), ISOLATED store.
/// </summary>
public sealed class SignInAccountServiceTests
{
    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    [Fact]
    public async Task TheSignInMethodsFollowTheContractsMatrix()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        await using var script = await node.ChannelAsync(Origin.Script);
        await using var agent = await node.ChannelAsync(Origin.Agent);
        await using var human = await node.ChannelAsync(Origin.Human);
        foreach (var refused in new[] { script, agent })
        {
            var begin = await refused.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = CloudNode.Command() }, cancellationToken: Cancel);
            Assert.Equal("permission_denied", begin.Error.Code);
        }

        Assert.Equal(0, center.FlowCount);
        var flow = (await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = CloudNode.Command(), Method = SignInMethod.Browser }, cancellationToken: Cancel)).Value.Flow;

        // GetSignInFlow: HUMAN A, SCRIPT A, AGENT D (account.sign_in.read, fixed).
        Assert.Equal(flow.FlowId, (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flow.FlowId }, cancellationToken: Cancel)).Value.Flow.FlowId);
        Assert.Equal(flow.FlowId, (await script.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flow.FlowId }, cancellationToken: Cancel)).Value.Flow.FlowId);
        Assert.Equal("permission_denied", (await agent.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flow.FlowId }, cancellationToken: Cancel)).Error.Code);
        Assert.Equal("not_found", (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = new Id { Value = ByteString.CopyFrom(new byte[16]) } }, cancellationToken: Cancel)).Error.Code);
        Assert.Equal("invalid_argument", (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest(), cancellationToken: Cancel)).Error.Code);

        // CancelSignIn: HUMAN A, SCRIPT D, AGENT D.
        foreach (var refused in new[] { script, agent })
        {
            var cancel = await refused.Account.CancelSignInAsync(new AccountServiceCancelSignInRequest { Meta = CloudNode.Command(), FlowId = flow.FlowId }, cancellationToken: Cancel);
            Assert.Equal("permission_denied", cancel.Error.Code);
        }

        Assert.Equal(SignInFlowState.Pending, (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flow.FlowId }, cancellationToken: Cancel)).Value.Flow.State);
    }

    [Fact]
    public async Task BeginSignInIsNotRecordedAndCancelSignInReplaysItsOutcome()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        await using var human = await node.ChannelAsync(Origin.Human);
        var meta = CloudNode.Command();
        var first = (await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = meta }, cancellationToken: Cancel)).Value.Flow;

        // The same command ID during the flow returns the live flow.
        Assert.Equal(first.FlowId, (await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = meta }, cancellationToken: Cancel)).Value.Flow.FlowId);
        var cancelMeta = CloudNode.Command();
        var cancelled = await human.Account.CancelSignInAsync(new AccountServiceCancelSignInRequest { Meta = cancelMeta, FlowId = first.FlowId }, cancellationToken: Cancel);
        Assert.Equal(SignInFlowState.Cancelled, cancelled.Value.Flow.State);
        var replay = await human.Account.CancelSignInAsync(new AccountServiceCancelSignInRequest { Meta = cancelMeta, FlowId = first.FlowId }, cancellationToken: Cancel);
        Assert.Equal(SignInFlowState.Cancelled, replay.Value.Flow.State);
        var again = await human.Account.CancelSignInAsync(new AccountServiceCancelSignInRequest { Meta = CloudNode.Command(), FlowId = first.FlowId }, cancellationToken: Cancel);
        Assert.Equal("invalid_state", again.Error.Code);

        // After the flow ended, the same command ID starts a new flow (BeginSignIn is not recorded).
        var second = (await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = meta }, cancellationToken: Cancel)).Value.Flow;
        Assert.NotEqual(first.FlowId, second.FlowId);
        Assert.Equal(2, center.FlowCount);
    }

    [Fact]
    public async Task TheCenterUrlIsRefusedWhileSigningInAndAcceptedAfterTheFlowEnds()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        await using var human = await node.ChannelAsync(Origin.Human);
        var flow = (await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = CloudNode.Command(), Method = SignInMethod.DeviceCode }, cancellationToken: Cancel)).Value.Flow;
        var refused = await human.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = CloudNode.Command(), CenterUrl = "https://other.example.test" }, cancellationToken: Cancel);
        Assert.Equal("invalid_state", refused.Error.Code);
        Assert.Equal("signing_in", refused.Error.Details.State.State);
        Assert.Equal("center_url", refused.Error.Details.State.Reason);
        await human.Account.CancelSignInAsync(new AccountServiceCancelSignInRequest { Meta = CloudNode.Command(), FlowId = flow.FlowId }, cancellationToken: Cancel);
        var accepted = await human.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = CloudNode.Command(), CenterUrl = "https://other.example.test" }, cancellationToken: Cancel);
        Assert.Null(accepted.Error);
    }

    [Fact]
    public async Task ABrowserSignInThroughTheApiAdvertisesItsFeatureAndSignsIn()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        await using var human = await node.ChannelAsync(Origin.Human);
        var info = (await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: Cancel)).Value.Node;
        Assert.Contains("account.sign_in.v1", info.Features);
        var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = CloudNode.Command() }, cancellationToken: Cancel);
        Assert.Empty(begun.Meta.Warnings);
        Assert.Equal([begun.Value.Flow.AuthorizeUrl], node.Browser.Opened);
        await ScriptedBrowser.GetAsync(center.ApproveFlow());
        await Eventually.TrueAsync(() => node.Cloud.SignIn.Get(begun.Value.Flow.FlowId)?.State == SignInFlowState.SignedIn, "signed in");
        var flow = (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = begun.Value.Flow.FlowId }, cancellationToken: Cancel)).Value.Flow;
        Assert.Equal(SignInFlowState.SignedIn, flow.State);
        var status = (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Cancel)).Value.Status;
        Assert.True(status.SignedIn);
        Assert.Equal(flow.NodeKeyFingerprint, status.NodeKeyFingerprint);
        var again = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = CloudNode.Command() }, cancellationToken: Cancel);
        Assert.Equal("signed_in", again.Error.Details.State.State);
    }

    [Fact]
    public async Task ASignOutDuringAFlowCancelsTheFlowFirst()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        await using var human = await node.ChannelAsync(Origin.Human);
        var flow = (await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = CloudNode.Command(), Method = SignInMethod.DeviceCode }, cancellationToken: Cancel)).Value.Flow;
        var signOut = await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command() }, cancellationToken: Cancel);
        Assert.Equal("not_signed_in", signOut.Error.Code);
        Assert.Equal(SignInFlowState.Cancelled, (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flow.FlowId }, cancellationToken: Cancel)).Value.Flow.State);
        Assert.Equal(CloudLinkPhase.SignedOut, node.Cloud.Phase);
    }

    [Theory]
    [InlineData("credential_for_other_node", true)]
    [InlineData("credential_backend_changed", true)]
    [InlineData("credential_store_unavailable", false)]
    public async Task OnlyALinkOfAnotherBackendOrNodeIsAbandonedAndOnlyLocally(string state, bool abandoned)
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await link.StopAsync();
        var file = link.Storage.ReadLink()!;
        var held = link.Secrets;
        switch (state)
        {
            case "credential_for_other_node":
                file.NodeId = Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
                link.Storage.WriteLink(file);
                break;
            case "credential_backend_changed":
                link.Secrets = new IsolatedSecretStore(ArcForges.Node.Store.NodeSecretStores.TestBackend == ArcForges.Security.Secrets.SecretStoreBackend.SecretService
                    ? ArcForges.Security.Secrets.SecretStoreBackend.WindowsCredentialManager : ArcForges.Security.Secrets.SecretStoreBackend.SecretService);
                break;
            default:
                file.Target = "ArcForges.Secrets.v1." + new string('A', 64);
                link.Storage.WriteLink(file);
                break;
        }

        await link.StartAsync();
        Assert.Contains(state, link.Service.Status().Warnings);
        var linkBytes = PrivateFiles.ReadOrNull(link.Storage.LinkPath)!;

        // The remote form never abandons anything.
        Assert.Equal(state == "credential_store_unavailable" ? SignOutResult.StoreUnavailable : SignOutResult.NotSignedIn,
            await link.Service.SignOutHeldAsync(revokeRemote: true));
        Assert.Equal(linkBytes, PrivateFiles.ReadOrNull(link.Storage.LinkPath)!);

        var result = await link.Service.SignOutHeldAsync(revokeRemote: false);
        await link.Service.PublishCurrentAsync();
        if (abandoned)
        {
            Assert.Equal(SignOutResult.Abandoned, result);
            Assert.False(File.Exists(link.Storage.LinkPath));
            Assert.False(File.Exists(link.Storage.KeysPath));
            Assert.Null(link.Keys.Recorded());
            Assert.Single(held.Names());
            Assert.Equal("link_abandoned", link.Service.LastError);
            Assert.Contains(link.Notices(), notice => notice.Kind == "account_link_abandoned");
            Assert.Empty(link.Center.CallsOf("SignOutNode"));

            // A sign-in works again.
            var flow = (await SignInFlowTests.BeginAsync(link, SignInMethod.Browser)).Flow!;
            Assert.Equal(SignInFlowState.Pending, flow.State);
        }
        else
        {
            Assert.Equal(SignOutResult.StoreUnavailable, result);
            Assert.Equal(linkBytes, PrivateFiles.ReadOrNull(link.Storage.LinkPath)!);
            Assert.True(File.Exists(link.Storage.KeysPath));
            Assert.Single(held.Names());
        }
    }
}
