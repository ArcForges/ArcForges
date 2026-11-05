// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// N2-15 (N2 interim review tests B-2; SEC-14, protocol-16, R-4): a REAL <c>arcforges node run --test-mode</c> process signs in with PKCE
/// and with a device code, and runs one FAILED and one CANCELLED flow, against FakeCenter (MOCKED center) with the test-mode browser file
/// (MOCKED browser). Every value the flows generate or receive (the one-use code, the center's flow ID as UUID, hex and raw bytes, the
/// device code, the user code raw and displayed, the PKCE verifier and state, every node key proof, every token) is then absent from every
/// file of the node outside its secret store (node.log, the journal with its events, notifications and recorded command outcomes in
/// node.db, the supervisor log, the link and key-set files, the connect log) and from every error the node returned. The user code and
/// the derived URLs appear only where they are shown by design (SignInFlow replies and the test-mode browser file).
/// </summary>
[Trait("loop", "local")]
public sealed class SignInSecretsTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task NoSignInSecretReachesALogTheJournalANotificationAnErrorOrTheConnectLog()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = TestNode.Create();
        var browserFile = Path.Combine(node.Root, "browser.txt");
        var connectLog = Path.Combine(node.Root, "connect.log");
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        node.Environment[CloudLinkTestHooks.BrowserFile] = browserFile;
        node.Environment[CloudLinkTestHooks.ConnectLog] = connectLog;
        await node.StartNodeAsync();
        var secrets = new List<(string What, byte[] Value)>();
        var errors = new List<ArcError>();
        var userCodes = new List<string>();
        var recorded = new List<IMessage>();
        await using (var human = await node.HumanChannelAsync())
        {
            // PKCE: approved, signed in, signed out.
            var browser = await BeginAsync(human, SignInMethod.Browser);
            await TestNode.WaitAsync(() => File.Exists(browserFile), TimeSpan.FromSeconds(10), "the browser file");
            var redirect = center.ApproveFlow();
            Collect(secrets, "code", redirect[(redirect.IndexOf("code=", StringComparison.Ordinal) + 5)..redirect.IndexOf('&', StringComparison.Ordinal)]);
            Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync(redirect));
            await WaitForAsync(human, browser.FlowId, SignInFlowState.SignedIn);
            Collect(secrets, "refresh token", center.LatestDelivered!);
            await SignOutAsync(human, errors);

            // Device code: approved, signed in, signed out.
            var device = await BeginAsync(human, SignInMethod.DeviceCode);
            userCodes.Add(device.UserCode);
            center.ApproveDevice();
            await WaitForAsync(human, device.FlowId, SignInFlowState.SignedIn);
            await SignOutAsync(human, errors);

            // FAILED: the center refuses the Complete.
            center.Script("CompleteNodeSignIn", new FakeFault.Refusal(new ArcError
            {
                Category = ErrorCategory.Conflict,
                Code = "code_reused",
                MessageKey = "error.conflict.code_reused",
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Effect = EffectCertainty.DidNotHappen,
            }));
            var failed = await BeginAsync(human, SignInMethod.Browser);
            var refused = center.ApproveFlow();
            Collect(secrets, "code", refused[(refused.IndexOf("code=", StringComparison.Ordinal) + 5)..refused.IndexOf('&', StringComparison.Ordinal)]);
            Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync(refused));
            errors.Add((await WaitForAsync(human, failed.FlowId, SignInFlowState.Failed)).Error);

            // CANCELLED: a device flow cancelled by CancelSignIn (a recorded command).
            var cancelled = await BeginAsync(human, SignInMethod.DeviceCode);
            userCodes.Add(cancelled.UserCode);
            var meta = Command();
            var reply = await human.Account.CancelSignInAsync(new AccountServiceCancelSignInRequest { Meta = meta, FlowId = cancelled.FlowId }, cancellationToken: Ct);
            Assert.Equal(SignInFlowState.Cancelled, reply.Value.Flow.State);

            // The recorded outcome (a replay answers from node.db) carries no URL and no code.
            var replay = await human.Account.CancelSignInAsync(new AccountServiceCancelSignInRequest { Meta = meta, FlowId = cancelled.FlowId }, cancellationToken: Ct);
            Assert.Equal(SignInFlowState.Cancelled, replay.Value.Flow.State);
            Assert.False(replay.Value.Flow.HasUserCode);
            Assert.False(replay.Value.Flow.HasAuthorizeUrl);
            recorded.Add(replay);
            errors.Add((await human.Account.CancelSignInAsync(new AccountServiceCancelSignInRequest { Meta = Command(), FlowId = cancelled.FlowId }, cancellationToken: Ct)).Error);
            errors.Add((await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = cancelled.FlowId }, cancellationToken: Ct)).Value.Flow.Error ?? new ArcError());
        }

        await node.StopNodeAsync();

        // What the center saw and answered.
        foreach (var call in center.CallsOf("BeginNodeSignIn"))
        {
            var begin = NodeEnrollmentServiceBeginNodeSignInRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body));
            Collect(secrets, "state", begin.State);
        }

        var completes = center.CallsOf("CompleteNodeSignIn").Select(call => NodeEnrollmentServiceCompleteNodeSignInRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(2, completes.Count);
        foreach (var complete in completes)
        {
            Collect(secrets, "verifier", complete.CodeVerifier);
            CollectBytes(secrets, "proof", complete.NodeKeyProof.ToByteArray());
            var flowId = complete.FlowId.Value.ToByteArray();
            CollectBytes(secrets, "center flow ID", flowId);
            Collect(secrets, "center flow ID (UUID)", new Guid(flowId, bigEndian: true).ToString("D"));
            Collect(secrets, "center flow ID (hex)", Convert.ToHexStringLower(flowId));
            Collect(secrets, "center flow ID (HEX)", Convert.ToHexString(flowId));
        }

        var polls = center.CallsOf("PollDeviceAuthorization").Select(call => NodeEnrollmentServicePollDeviceAuthorizationRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.NotEmpty(polls);
        foreach (var poll in polls)
        {
            Collect(secrets, "device code", poll.DeviceCode);
            CollectBytes(secrets, "proof", poll.NodeKeyProof.ToByteArray());
        }

        foreach (var code in userCodes)
        {
            Collect(secrets, "user code", code);
            Collect(secrets, "user code (display)", SignInUrls.DisplayUserCode(code));
        }

        foreach (var call in center.CallsOf("SignOutNode").Concat(center.CallsOf("ReportNodeInfo")))
        {
            if (call.Authorization is { Length: > 7 } bearer)
            {
                Collect(secrets, "access token", bearer["Bearer ".Length..]);
            }
        }

        Collect(secrets, "refresh token", center.LatestDelivered!);
        Collect(secrets, "token prefix", "afr1.");
        Collect(secrets, "token prefix", "afa1.");
        Assert.Contains(secrets, secret => secret.What == "access token");

        // Every error the node returned (the FAILED flow's, the refusals of the ended flow) and the recorded CancelSignIn outcome.
        foreach (var answer in errors.Where(error => error is not null).Cast<IMessage>().Concat(recorded))
        {
            var text = Encoding.UTF8.GetBytes(JsonFormatter.Default.Format(answer)).Concat(answer.ToByteArray()).ToArray();
            foreach (var (what, value) in secrets)
            {
                Assert.False(Contains(text, value), "the " + what + " in an answer of the node: " + JsonFormatter.Default.Format(answer));
            }
        }

        // Every node file outside the secret store (and outside the test-mode browser file, which holds the derived URL by design).
        await TestNode.WaitAsync(() => node.LiveProcesses().Count == 0, TimeSpan.FromSeconds(30), "the node and its supervisor to exit");
        var store = Path.Combine(node.DataRoot, "run", "test-secrets") + Path.DirectorySeparatorChar;
        var read = new List<string>();
        foreach (var file in Directory.EnumerateFiles(node.Root, "*", SearchOption.AllDirectories)
            .Where(file => !file.StartsWith(store, StringComparison.Ordinal) && !file.EndsWith(".lock", StringComparison.Ordinal) && file != browserFile).ToList())
        {
            if (CloudLinkHostTests.ReadAllShared(file) is not { } bytes)
            {
                continue;
            }

            read.Add(file);
            foreach (var (what, value) in secrets)
            {
                Assert.False(Contains(bytes, value), "the " + what + " in " + file);
            }
        }

        Assert.Contains(read, file => file.EndsWith("node.db", StringComparison.Ordinal));
        Assert.Contains(read, file => file == node.NodeLog);
        Assert.Contains(read, file => file == connectLog);
        Assert.Contains("cloud.sign_in.ended", TestNode.ReadShared(node.NodeLog), StringComparison.Ordinal);
    }

    private static async Task<SignInFlow> BeginAsync(NodeChannel human, SignInMethod method)
    {
        var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = Command(), Method = method }, cancellationToken: Ct);
        Assert.Null(begun.Error);
        return begun.Value.Flow;
    }

    private static async Task<SignInFlow> WaitForAsync(NodeChannel human, Id flowId, SignInFlowState state)
    {
        SignInFlow? flow = null;
        await TestNode.WaitAsync(async () =>
        {
            flow = (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flowId }, cancellationToken: Ct)).Value.Flow;
            return flow.State == state;
        }, TimeSpan.FromSeconds(30), "the flow " + state);
        return flow!;
    }

    private static async Task SignOutAsync(NodeChannel human, List<ArcError> errors)
    {
        var response = await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() }, cancellationToken: Ct);
        Assert.Null(response.Error);
        errors.Add((await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() }, cancellationToken: Ct)).Error);
    }

    private static void Collect(List<(string, byte[])> secrets, string what, string value)
    {
        Assert.False(string.IsNullOrEmpty(value), "no " + what + " to look for");
        secrets.Add((what, Encoding.UTF8.GetBytes(value)));
    }

    /// <summary>A binary value: its raw bytes and its base64url, base64 and hexadecimal forms.</summary>
    private static void CollectBytes(List<(string, byte[])> secrets, string what, byte[] value)
    {
        Assert.NotEmpty(value);
        secrets.Add((what, value));
        secrets.Add((what + " (base64url)", Encoding.ASCII.GetBytes(Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_'))));
        secrets.Add((what + " (base64)", Encoding.ASCII.GetBytes(Convert.ToBase64String(value).TrimEnd('='))));
        secrets.Add((what + " (hex)", Encoding.ASCII.GetBytes(Convert.ToHexString(value))));
        secrets.Add((what + " (hex)", Encoding.ASCII.GetBytes(Convert.ToHexStringLower(value))));
    }

    private static bool Contains(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle) >= 0;

    private static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
}
