// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// N2-7: the sign-in of REAL <c>arcforges --test-mode</c> node processes against a REAL center (the local official-hosted rehearsal by
/// default, or proof with the coordinator's go; never production), approved in a REAL browser by the Cloud tool <c>node-approve</c>
/// (pinned Chromium, MOCKED authenticator) through its handshake directory: the test writes <c>&lt;case&gt;.begin.json</c> and
/// <c>&lt;case&gt;.result.json</c> in node-probe's format (Cloud docs/center-fleet.md, "node-probe and the node-approve run"; data only,
/// nothing of Cloud is built). Cases (<c>ARCFORGES_E2E_CASES</c>, default <c>device-1,pkce-1</c>): <c>device-*</c> and <c>pkce-*</c> through
/// the API as HUMAN, <c>cli-device-*</c> through the literal CLI in a pty (Linux). Each case: signed in, the fingerprint and the derived
/// URL, a first contact, two refreshes at the 15 s cadence (counted from the status's last contact), the delivered center keys when
/// <c>ARCFORGES_E2E_EXPECT_KEYS=command:&lt;kid&gt;,&lt;kid&gt;[;entitlement:&lt;kid&gt;,...]</c> is set (the node's <c>run/cloud-keys.json</c> holds exactly those kids,
/// after the sign-in and after the refreshes; skipped with its reason otherwise), a restart that keeps credential and key, only the center's authority contacted; after every
/// result is written, node-approve's clean-up revokes the devices and each node turns signed out, deletes its key and notifies. Skipped
/// with its reason unless <c>ARCFORGES_E2E_CENTER_URL</c> is set; it runs only when the coordinator starts it beside node-approve.
/// </summary>
[Trait("loop", "cloud")]
public sealed class CloudSignInTests
{
    private const string CenterVariable = "ARCFORGES_E2E_CENTER_URL";
    private const string DirectoryVariable = "ARCFORGES_E2E_DIR";
    private const string CasesVariable = "ARCFORGES_E2E_CASES";
    private const string ExpectedKidsVariable = "ARCFORGES_E2E_EXPECT_KEYS";

    /// <summary>
    /// AF-CTR-05 N1-20: with <c>ARCFORGES_E2E_CHANNEL=1</c> (a center that serves the node channel, Cloud E1a and later), each case also
    /// checks that the node holds a CONNECTED channel after the sign-in, still CONNECTED after its refreshes (TokenRefresh in band), and
    /// DISABLED after node-approve's revocation; otherwise those steps are not run.
    /// </summary>
    private const string ChannelVariable = "ARCFORGES_E2E_CHANNEL";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task RealNodesSignInAtARealCenterApprovedInARealBrowser()
    {
        var url = Environment.GetEnvironmentVariable(CenterVariable);
        Assert.SkipUnless(!string.IsNullOrEmpty(url), CenterVariable + " is not set");
        Assert.True(CenterEndpoint.TryParse(url, out var center, out var reason), reason);
        Assert.NotEqual(CenterEndpoint.OfficialDefault, center.Url);
        var handshake = Environment.GetEnvironmentVariable(DirectoryVariable);
        Assert.True(!string.IsNullOrEmpty(handshake) && Path.IsPathFullyQualified(handshake), DirectoryVariable + " must name the handshake directory");
        Directory.CreateDirectory(handshake);
        var cases = (Environment.GetEnvironmentVariable(CasesVariable) is { Length: > 0 } list ? list : "device-1,pkce-1")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var nodes = new List<(string Case, TestNode Node)>();
        try
        {
            foreach (var name in cases)
            {
                var node = TestNode.Create();
                nodes.Add((name, node));
                await SignInAsync(node, center, handshake, name);
            }

            // node-approve revokes the approved devices after the last result: each node's next refresh signs it out.
            foreach (var (name, node) in nodes)
            {
                await using var human = await node.HumanChannelAsync();
                await TestNode.WaitAsync(async () => !(await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status.SignedIn,
                    TimeSpan.FromMinutes(10), name + ": signed out after node-approve revoked the device");
                var status = (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status;
                Assert.False(status.HasNodeKeyFingerprint, name + ": the key is deleted with the revoked credential");
                var notifications = await human.Node.ListNotificationsAsync(new NodeServiceListNotificationsRequest(), cancellationToken: Ct);
                Assert.Contains(notifications.Value.Notifications, item => item.Kind == "account_signed_out");
            }

            foreach (var (name, node) in nodes)
            {
                await node.StopNodeAsync();
                var log = TestNode.ReadShared(node.NodeLog);
                Assert.False(log.Contains("afr1.", StringComparison.Ordinal) || log.Contains("afa1.", StringComparison.Ordinal), name + ": a token in the node log");
                Assert.DoesNotContain("/connect#flow=", log, StringComparison.Ordinal);
            }
        }
        finally
        {
            foreach (var (_, node) in nodes)
            {
                await node.DisposeAsync();
            }
        }
    }

    private static async Task SignInAsync(TestNode node, CenterEndpoint center, string handshake, string name)
    {
        var browserFile = Path.Combine(node.Root, "browser.txt");
        var connectLog = Path.Combine(node.Root, "connect.log");
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Url;
        node.Environment[CloudLinkTestHooks.BrowserFile] = browserFile;
        node.Environment[CloudLinkTestHooks.ConnectLog] = connectLog;
        node.Environment[CloudLinkTestHooks.RefreshSeconds] = "15";
        var keys = CloudSignInChecks.KeyExpectation.Parse(Environment.GetEnvironmentVariable(ExpectedKidsVariable));
        var steps = new JsonArray();
        void Step(string step, bool ok, string outcome)
        {
            steps.Add(new JsonObject { ["name"] = step, ["ok"] = ok, ["outcome"] = outcome });
            Assert.True(ok, name + ": " + step + " (" + outcome + ")");
        }

        async Task KeysAsync(string when)
        {
            if (keys is null)
            {
                Step("the delivered center keys " + when, true, "skipped: " + ExpectedKidsVariable + " is not set (proof delivers no command keys today)");
                return;
            }

            var file = Path.Combine(node.DataRoot, "run", "cloud-keys.json");
            string? problem;
            var started = TimeProvider.System.GetTimestamp();
            while ((problem = CloudSignInChecks.CompareKeys(File.Exists(file) ? File.ReadAllText(file) : null, keys)) is not null
                && TimeProvider.System.GetElapsedTime(started) < TimeSpan.FromSeconds(10))
            {
                await Task.Delay(200, Ct);
            }

            Step("the delivered center keys " + when, problem is null, problem ?? "exactly " + string.Join("; ", keys.Select(item => item.Purpose + ": " + string.Join(", ", item.Kids))));
        }

        await node.StartNodeAsync();
        var nodeName = "n2-" + DateTime.UtcNow.ToString("HHmmss", System.Globalization.CultureInfo.InvariantCulture) + "-" + name;
        SignInFlow flow;
        await using (var human = await node.HumanChannelAsync())
        {
            var renamed = await human.Node.RenameNodeAsync(new NodeServiceRenameNodeRequest { Meta = Command(), Name = nodeName }, cancellationToken: Ct);
            Assert.Null(renamed.Error);
            var device = !name.StartsWith("pkce", StringComparison.Ordinal);
            if (name.StartsWith("cli-", StringComparison.Ordinal))
            {
                Assert.SkipUnless(OperatingSystem.IsLinux() && File.Exists("/usr/bin/script"), "the literal HUMAN CLI runs in a pty on Linux only (H-C14)");
                using var cli = CloudSignInHostTests.Pty(node, "login --device-code");
                await cli.WaitForAsync("Waiting for the approval");
                flow = await LatestFlowAsync(human, cli.Text);
                WriteBegin(handshake, name, flow, nodeName, center);
                Assert.Equal(0, await cli.WaitExitAsync(TimeSpan.FromMinutes(9)));
                Step("the CLI signed in", cli.Text.Contains("Signed in", StringComparison.Ordinal), "exit 0");
            }
            else
            {
                var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = Command(), Method = device ? SignInMethod.DeviceCode : SignInMethod.Browser }, cancellationToken: Ct);
                Assert.Null(begun.Error);
                flow = begun.Value.Flow;
                if (!device)
                {
                    await TestNode.WaitAsync(() => File.Exists(browserFile), TimeSpan.FromSeconds(10), "the browser file");
                    Step("the derived authorize URL", File.ReadAllText(browserFile).Trim() == flow.AuthorizeUrl && flow.AuthorizeUrl.StartsWith(center.Url + "/connect#flow=", StringComparison.Ordinal), "derived");
                }
                else
                {
                    Step("the derived verification URIs", flow.VerificationUri == center.ActivateUrl && flow.VerificationUriComplete == center.ActivateCompleteUrl(flow.UserCode), "derived");
                }

                WriteBegin(handshake, name, flow, nodeName, center);
                await TestNode.WaitAsync(async () => (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flow.FlowId }, cancellationToken: Ct)).Value.Flow.State is not (SignInFlowState.Pending or SignInFlowState.Completing),
                    TimeSpan.FromMinutes(9), name + ": the decision");
                var ended = (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flow.FlowId }, cancellationToken: Ct)).Value.Flow;
                Step("signed in", ended.State == SignInFlowState.SignedIn, ended.State + (ended.Error is { } error ? " " + error.Category + "/" + error.Code : string.Empty));
            }

            var status = (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status;
            Step("the account status", status.SignedIn && status.CenterUrl == center.Url && !status.CredentialInOsStore && status.NodeKeyFingerprint == flow.NodeKeyFingerprint,
                "signed in, fingerprint " + status.NodeKeyFingerprint);
            await KeysAsync("after the sign-in");
            var channel = Environment.GetEnvironmentVariable(ChannelVariable) == "1";
            async Task<RelayState> RelayAsync() => (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status.Relay;
            if (channel)
            {
                await TestNode.WaitAsync(async () => await RelayAsync() == RelayState.Connected, TimeSpan.FromSeconds(60), name + ": the channel is connected");
                Step("the channel is connected", true, "CONNECTED");
            }

            var refreshes = new CloudSignInChecks.RefreshCounter(15);
            async Task<bool> TwoRefreshesAsync()
            {
                refreshes.Observe((await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status.LastContactAt?.UnixSeconds);
                return refreshes.Refreshes >= 2;
            }

            await TestNode.WaitAsync(TwoRefreshesAsync, TimeSpan.FromSeconds(120), name + ": a first contact, then two refreshes at the 15 s cadence");
            var after = (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status;
            Step("two refreshes seen", after.SignedIn, refreshes.Describe());
            if (channel)
            {
                Step("the channel stays connected across the refreshes", after.Relay == RelayState.Connected, after.Relay + " " + after.RelayReason);
            }

            await KeysAsync("after the refreshes");
        }

        await node.StopNodeAsync();
        await node.StartNodeAsync();
        await using (var human = await node.HumanChannelAsync())
        {
            var status = (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status;
            Step("a restart keeps credential and key", status.SignedIn && status.NodeKeyFingerprint == flow.NodeKeyFingerprint, "same fingerprint");
        }

        var authority = center.Host + ":" + center.EffectivePort;
        var lines = File.ReadAllLines(connectLog);
        Step("only the center's authority", lines.All(line => line.StartsWith(authority + " sent ", StringComparison.Ordinal)), lines.Length + " attempts");
        var result = new JsonObject
        {
            ["case"] = name,
            ["kind"] = name.StartsWith("pkce", StringComparison.Ordinal) ? "pkce" : "device",
            ["passed"] = true,
            ["steps"] = steps,
            ["requests"] = new JsonArray([.. lines.Select(line => (JsonNode?)line[(line.LastIndexOf(' ') + 1)..])]),
        };
        Write(handshake, name + ".result.json", result);
    }

    private static async Task<SignInFlow> LatestFlowAsync(NodeChannel human, string text)
    {
        // The CLI's flow is the node's active one: begin returns it again.
        var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = Command(), Method = SignInMethod.DeviceCode }, cancellationToken: Ct);
        Assert.Null(begun.Error);
        Assert.Contains(SignInUrls.DisplayUserCode(begun.Value.Flow.UserCode), text, StringComparison.Ordinal);
        return begun.Value.Flow;
    }

    private static void WriteBegin(string handshake, string name, SignInFlow flow, string nodeName, CenterEndpoint center)
    {
        var device = flow.Method == SignInMethod.DeviceCode;
        var begin = new JsonObject
        {
            ["case"] = name,
            ["kind"] = device ? "device" : "pkce",
            ["url"] = device ? flow.VerificationUriComplete : flow.AuthorizeUrl,
            ["fingerprint"] = flow.NodeKeyFingerprint,
            ["name"] = nodeName,
            ["os"] = OperatingSystem.IsWindows() ? "Windows" : "Linux",
            ["arch"] = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64 ? "Arm64" : "x64",
            ["version"] = NodeContract.ProductVersion.Split('+')[0],
            ["centerHost"] = center.Port is { } port ? center.Host + ":" + port : center.Host,
            ["decision"] = "approve",
        };
        if (device)
        {
            begin["userCode"] = SignInUrls.DisplayUserCode(flow.UserCode);
        }

        Write(handshake, name + ".begin.json", begin);
    }

    private static void Write(string directory, string name, JsonObject document)
    {
        var temporary = Path.Combine(directory, "." + name + ".tmp");
        File.WriteAllText(temporary, document.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n");
        File.Move(temporary, Path.Combine(directory, name), overwrite: true);
    }

    private static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
}
