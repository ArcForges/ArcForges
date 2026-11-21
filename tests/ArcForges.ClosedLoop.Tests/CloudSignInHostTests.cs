// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// N2-16 and N2-17: the sign-in of a REAL <c>arcforges node run --test-mode</c> process whose center is FakeCenter (MOCKED center, compiled
/// in from the cloud-link test project) through <c>ARCFORGES_TEST_CENTER_URL</c>, the browser played by the test (MOCKED browser: the node
/// writes the derived URL to <c>ARCFORGES_TEST_BROWSER_FILE</c> and starts nothing; the test approves on FakeCenter and sends the
/// redirect to the Node's loopback receiver). Local SCRIPT callers cannot start or end the account session.
/// </summary>
[Trait("loop", "local")]
public sealed class CloudSignInHostTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task TheNodeProcessSignsInThroughItsReceiverAndKeepsTheCredentialAcrossARestart()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = TestNode.Create();
        var browserFile = Path.Combine(node.Root, "browser.txt");
        var connectLog = Path.Combine(node.Root, "connect.log");
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        node.Environment[CloudLinkTestHooks.BrowserFile] = browserFile;
        node.Environment[CloudLinkTestHooks.ConnectLog] = connectLog;
        await node.StartNodeAsync();
        string fingerprint;
        await using (var human = await node.HumanChannelAsync())
        {
            var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = Command(), Method = SignInMethod.Browser }, cancellationToken: Ct);
            Assert.Null(begun.Error);
            var flow = begun.Value.Flow;
            await TestNode.WaitAsync(() => File.Exists(browserFile), TimeSpan.FromSeconds(10), "the browser file");
            Assert.Equal(flow.AuthorizeUrl + "\n", File.ReadAllText(browserFile));
            Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync(center.ApproveFlow()));
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status.SignedIn,
                TimeSpan.FromSeconds(20), "signed in");
            var status = (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status;
            fingerprint = status.NodeKeyFingerprint;
            Assert.Equal(flow.NodeKeyFingerprint, fingerprint);
            Assert.Equal(SignInFlowState.SignedIn, (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flow.FlowId }, cancellationToken: Ct)).Value.Flow.State);
            Assert.Contains("account.sign_in.v1", (await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: Ct)).Value.Node.Features);
        }

        await node.StopNodeAsync();
        await node.StartNodeAsync();
        await using (var human = await node.HumanChannelAsync())
        {
            var status = (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status;
            Assert.True(status.SignedIn);
            Assert.Equal(fingerprint, status.NodeKeyFingerprint);
        }

        await using (var human = await node.HumanChannelAsync())
        {
            Assert.Null((await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() }, cancellationToken: Ct)).Error);
        }

        await node.StopNodeAsync();
        Assert.All(File.ReadAllLines(connectLog), line => Assert.StartsWith("127.0.0.1:" + center.Endpoint.Port + " sent ", line, StringComparison.Ordinal));
        var log = TestNode.ReadShared(node.NodeLog);
        foreach (var secret in new[] { "afr1.", "afa1.", center.LatestDelivered! })
        {
            Assert.DoesNotContain(secret, log, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("/connect#flow=", log, StringComparison.Ordinal);
        Assert.Contains("cloud.sign_in.ended", log, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADeviceSignInOfTheNodeProcessAndARestartThatCancelsAFlow()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        await node.StartNodeAsync();
        Id flowId;
        int port;
        await using (var human = await node.HumanChannelAsync())
        {
            // A browser flow without the test hook opens nothing (warned), and a restart cancels it: its receiver is gone.
            var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = Command(), Method = SignInMethod.Browser }, cancellationToken: Ct);
            Assert.Contains("browser_not_opened", begun.Meta.Warnings);
            flowId = begun.Value.Flow.FlowId;
            port = new Uri(center.ApproveFlow()).Port;
        }

        await node.StopNodeAsync();
        await node.StartNodeAsync();
        await using (var human = await node.HumanChannelAsync())
        {
            Assert.Equal("not_found", (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flowId }, cancellationToken: Ct)).Error.Code);
            await Assert.ThrowsAnyAsync<Exception>(() => ScriptedBrowser.RawAsync("127.0.0.1", port, "GET / HTTP/1.1\r\n\r\n", TimeSpan.FromSeconds(2)));

            var device = (await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = Command(), Method = SignInMethod.DeviceCode }, cancellationToken: Ct)).Value.Flow;
            Assert.Equal(center.LatestUserCode, device.UserCode);
            Assert.Equal(center.Endpoint.ActivateCompleteUrl(device.UserCode), device.VerificationUriComplete);
            center.ApproveDevice();
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status.SignedIn,
                TimeSpan.FromSeconds(30), "signed in by the device code");
            Assert.Null((await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() }, cancellationToken: Ct)).Error);
        }

        await node.StopNodeAsync();
        var log = TestNode.ReadShared(node.NodeLog);
        Assert.DoesNotContain(center.LatestUserCode!, log, StringComparison.Ordinal);
        Assert.DoesNotContain("afr1.", log, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ALocalScriptCanReadButCannotChangeTheAccountSession()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        await node.StartNodeAsync();
        await using var script = CloudLinkCenterControlTests.OpenChannel(node);
        var hello = ClientProcess.Hello(ClientKind.Cli);
        hello.InteractiveTerminal = false;
        hello.CiMarkers.Clear();
        var origin = await script.Node.HelloAsync(new NodeServiceHelloRequest { Hello = hello }, cancellationToken: Ct);
        Assert.Null(origin.Error);
        Assert.Equal(Origin.Script, origin.Value.AssignedOrigin);
        var login = await script.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest
        {
            Meta = Command(),
            Method = SignInMethod.DeviceCode,
        }, cancellationToken: Ct);
        Assert.Equal("permission_denied", login.Error.Code);
        var logout = await script.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() }, cancellationToken: Ct);
        Assert.Equal("permission_denied", logout.Error.Code);
        var status = await script.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct);
        Assert.Null(status.Error);
        Assert.False(status.Value.Status.SignedIn);
        Assert.Equal(0, center.DeviceCount);
        Assert.Empty(center.CallsOf("SignOutNode"));
    }

    [Fact]
    public async Task ALocalSignOutCanForgetAStrandedLinkWithoutDeletingTheUnownedCredential()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        await node.StartNodeAsync();
        byte[] nodeId;
        await using (var human = await node.HumanChannelAsync())
        {
            var response = await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: Ct);
            Assert.Null(response.Error);
            nodeId = response.Value.Node.Node.NodeId.Value.ToByteArray();
        }

        await node.StopNodeAsync();
        var issued = center.Issue(nodeId);
        CloudLinkHostTests.Seed(node.DataRoot, nodeId, center, issued);
        var linkPath = Path.Combine(node.DataRoot, "run", "cloud-link.json");
        var link = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(linkPath))!.AsObject();
        var otherNode = nodeId.ToArray();
        otherNode[0] ^= 1;
        link["nodeId"] = Convert.ToHexStringLower(otherNode);
        File.WriteAllText(linkPath, link.ToJsonString());
        var target = CloudCredentialStore.Target(nodeId, center.Endpoint.Origin);
        var secrets = ArcForges.Node.Store.NodeSecretStores.ForTestDataRoot(node.DataRoot).Store;
        try
        {
            await node.StartNodeAsync();
            await using var human = await node.HumanChannelAsync();
            var status = await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct);
            Assert.Null(status.Error);
            Assert.False(status.Value.Status.SignedIn);
            Assert.Contains("credential_for_other_node", status.Value.Status.Warnings);
            var signedOut = await human.Account.SignOutAsync(new AccountServiceSignOutRequest
            {
                Meta = Command(),
                RevokeRemote = false,
            }, cancellationToken: Ct);
            Assert.Null(signedOut.Error);
            Assert.Contains("stranded_credential_abandoned", signedOut.Meta.Warnings);
            Assert.False(File.Exists(linkPath));
            Assert.Empty(center.CallsOf("SignOutNode"));
            Assert.True(center.IsLive(issued.RefreshToken));
            Assert.NotNull(secrets.Read(target));
            await node.StopNodeAsync();
        }
        finally
        {
            secrets.Delete(target);
        }
    }

    private static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
}
