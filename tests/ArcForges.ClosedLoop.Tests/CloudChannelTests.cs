// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// AF-CTR-05 N1 (G.2 rows N1-15 and N1-22, process level): a REAL <c>arcforges node run --test-mode</c> process holds a proved channel to
/// FakeCenter's channel peer (MOCKED center, compiled in from the cloud-link test project), answers a call with a result signed by its node
/// key, sends TokenRefresh after its refreshes, and leaves no access token, refresh token or call payload in any file outside its secret
/// store (log, journal, connect log, node.db). The credential and the key are seeded test-side as in <see cref="CloudLinkHostTests"/>.
/// </summary>
[Trait("loop", "local")]
public sealed class CloudChannelTests
{
    /// <summary>Hostile calls face the verifier in a separate actual node process; only the center peer is mocked.</summary>
    [Fact(Timeout = 180_000)]
    public async Task TheNodeProcessRefusesForgedAlteredRetargetedAndExpiredCallsBeforeAnyEffect()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        using var host = await node.StartNodeAsync();
        var comparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        Assert.Equal(Path.GetFullPath(TestNode.Host), Path.GetFullPath(host.MainModule!.FileName), comparer);
        await using var human = await node.HumanChannelAsync();
        var info = await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct);
        Assert.Null(info.Error);
        var nodeId = info.Value.Node.Node.NodeId;
        var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Method = SignInMethod.DeviceCode,
        }, cancellationToken: ct);
        Assert.Null(begun.Error);
        center.ApproveDevice();
        await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct))
            .Value.Status.Relay == RelayState.Connected, TimeSpan.FromSeconds(30), "the mocked center channel is connected");
        var connection = await center.Channel.ProvedAsync();
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = nodeId.Clone(),
            LocalOrigin = Origin.Script,
            LocalSessionId = CommandIds.New(),
        };
        var marker = "XFORGED" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        TaskServiceSubmitTaskRequest Submit(string title)
        {
            var argv = new ArgvCommand();
            argv.Argv.Add([TestNode.TestLoad, "hold", "--hold-ms", "100"]);
            return new TaskServiceSubmitTaskRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                Spec = new TaskSpec
                {
                    Title = title,
                    Command = new CommandSpec { Argv = argv },
                    WorkingDirectory = node.Root,
                    Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
                },
            };
        }

        static byte[] Flip(byte[] input)
        {
            var changed = (byte[])input.Clone();
            changed[^1] ^= 1;
            return changed;
        }

        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var otherNode = nodeId.Value.ToByteArray();
        otherNode[0] ^= 1;
        var cases = new (string Step, Func<FakeCallSpec, FakeCallSpec> Alter)[]
        {
            ("signature", spec => spec with { SigningKey = otherKey }),
            ("signature", spec => spec with { AlterHeader = Flip }),
            ("request_digest", spec => spec with { AlterPayload = Flip }),
            ("target_mismatch", spec => spec with { TargetNodeId = otherNode }),
            ("expired", spec => spec with { IssuedOffset = TimeSpan.FromSeconds(-400) }),
        };
        foreach (var (step, alter) in cases)
        {
            var submit = Submit(marker);
            var spec = new FakeCallSpec { Method = RoutedMethod.SubmitNodeTask, Caller = caller, CommandId = submit.Meta.CommandId, Payload = submit.ToByteArray() };
            var (call, _) = center.Channel.BuildCall(connection, alter(spec));
            await connection.SendCallAsync(call);
            var frame = await connection.ResultOfAsync(call.CallId);
            await TestNode.WaitAsync(() => connection.VerifiedResults.Any(result => result.Header.CallId.Equals(call.CallId)), TimeSpan.FromSeconds(15), "the refusal signature verified");
            Assert.Empty(connection.UnverifiedResults);
            var header = connection.VerifiedResults.Single(result => result.Header.CallId.Equals(call.CallId)).Header;
            Assert.Equal(RoutedOutcome.RefusedVerification, header.Outcome);
            Assert.Equal(step, header.Error.Details.State.Reason);
            Assert.Equal(step == "expired" ? "expired" : "signature_invalid", header.Error.Code);
            Assert.Null(header.CommandId);
            Assert.False(header.HasMethod);
            Assert.False(header.HasRequestSha256);
            Assert.Empty(frame.Payload);
            Assert.False(header.ToString().Contains(marker, StringComparison.Ordinal));
        }

        var beforeControl = await human.Tasks.ListTasksAsync(new TaskServiceListTasksRequest { Meta = new RequestMeta { CommandId = CommandIds.New() } }, cancellationToken: ct);
        Assert.Null(beforeControl.Error);
        Assert.Empty(beforeControl.Value.Tasks);

        // A valid call with the same process command and caller really reaches the independent node and runs.
        var valid = Submit("valid-control");
        var (acceptedCall, _) = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.SubmitNodeTask,
            Caller = caller,
            CommandId = valid.Meta.CommandId,
            Payload = valid.ToByteArray(),
        });
        await connection.SendCallAsync(acceptedCall);
        var acceptedFrame = await connection.ResultOfAsync(acceptedCall.CallId);
        await TestNode.WaitAsync(() => connection.VerifiedResults.Any(result => result.Header.CallId.Equals(acceptedCall.CallId)), TimeSpan.FromSeconds(15), "the accepted result signature verified");
        Assert.Equal(RoutedOutcome.Executed, connection.VerifiedResults.Single(result => result.Header.CallId.Equals(acceptedCall.CallId)).Header.Outcome);
        var accepted = TaskServiceSubmitTaskResponse.Parser.ParseFrom(acceptedFrame.Payload);
        Assert.Null(accepted.Error);
        var waited = await human.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New() },
            TaskId = accepted.Value.TaskId,
            Target = WaitTarget.Terminal,
            WaitMs = 50_000,
        }, deadline: DateTime.UtcNow.AddSeconds(58), cancellationToken: ct);
        Assert.Null(waited.Error);
        Assert.True(waited.Value.Reached);
        Assert.Equal(TaskState.Succeeded, waited.Value.Task.State);
        Assert.Null((await human.Account.SignOutAsync(new AccountServiceSignOutRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
        }, cancellationToken: ct)).Error);
        await node.StopNodeAsync();
        // The stop command has returned; wait for this node and its supervisor to release the database before scanning every file.
        await TestNode.WaitAsync(() => node.LiveProcesses().Count == 0, TimeSpan.FromSeconds(30), "the node and its supervisor to exit");

        var secrets = Path.Combine(node.DataRoot, "run", "test-secrets") + Path.DirectorySeparatorChar;
        var markerBytes = System.Text.Encoding.UTF8.GetBytes(marker);
        var files = Directory.EnumerateFiles(node.Root, "*", SearchOption.AllDirectories)
            .Where(file => !file.StartsWith(secrets, StringComparison.Ordinal) && !file.EndsWith(".lock", StringComparison.Ordinal)).ToArray();
        Assert.Contains(files, file => file.EndsWith("node.db", StringComparison.Ordinal));
        foreach (var file in files)
        {
            if (CloudLinkHostTests.ReadAllShared(file) is { } bytes)
            {
                Assert.False(bytes.AsSpan().IndexOf(markerBytes) >= 0, "untrusted payload leaked into node files");
            }
        }
    }

    [Fact]
    public async Task TheNodeProcessHoldsAProvedChannelAndLeavesNoSecretOrPayloadInItsFiles()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        await using var node = TestNode.Create();
        var connectLog = Path.Combine(node.Root, "connect.log");
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        node.Environment[CloudLinkTestHooks.ConnectLog] = connectLog;
        node.Environment[CloudLinkTestHooks.RefreshSeconds] = "15";

        await node.StartNodeAsync();
        byte[] nodeId;
        await using (var human = await node.HumanChannelAsync())
        {
            nodeId = (await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct)).Value.Node.Node.NodeId.Value.ToByteArray();
        }

        await node.StopNodeAsync();
        var issued = center.Issue(nodeId, "Closed Loop");
        CloudLinkHostTests.Seed(node.DataRoot, nodeId, center, issued);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.Channel.RegisterNodeKey(issued.AccessToken, key.PublicKey);
        }

        await node.StartNodeAsync();
        var connection = await center.Channel.ProvedAsync();
        await using (var human = await node.HumanChannelAsync())
        {
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.Relay == RelayState.Connected,
                TimeSpan.FromSeconds(30), "the channel is connected");
            Assert.Contains(CloudLinkService.ChannelFeature, (await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct)).Value.Node.Features);
        }

        // A call whose payload carries a marker: verified, rejected by the N2 dispatcher as an invalid task, and signed; the payload is not stored.
        var marker = "N1MARKER" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        var submit = new TaskServiceSubmitTaskRequest { Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() } };
        submit.Spec = new TaskSpec { WorkingDirectory = "/srv/" + marker };
        var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec { Method = RoutedMethod.SubmitNodeTask, CommandId = submit.Meta.CommandId, Payload = submit.ToByteArray() });
        await connection.SendCallAsync(call);
        await TestNode.WaitAsync(() => !connection.VerifiedResults.IsEmpty, TimeSpan.FromSeconds(15), "the signed result");
        Assert.Empty(connection.UnverifiedResults);
        var result = Assert.Single(connection.VerifiedResults);
        Assert.Equal(RoutedOutcome.Executed, result.Header.Outcome);
        var error = TaskServiceSubmitTaskResponse.Parser.ParseFrom(result.Frame.Payload).Error;
        Assert.Equal((ErrorCategory.Validation, "invalid_argument", EffectCertainty.DidNotHappen), (error.Category, error.Code, error.Effect));

        // The node's refreshes on the hook's cadence each send TokenRefresh on the open channel.
        await TestNode.WaitAsync(() => connection.TokenRefreshes.Count >= 1, TimeSpan.FromSeconds(60), "TokenRefresh after a refresh");
        Assert.Equal(CloudLinkHostTests.Stored(node.DataRoot, nodeId, center)!.AccessToken, connection.TokenRefreshes[^1]);

        // A HUMAN sign-out ends the credential (nothing is left in the isolated store) and closes the channel.
        await using (var human = await node.HumanChannelAsync())
        {
            var signedOut = await human.Account.SignOutAsync(new AccountServiceSignOutRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            }, cancellationToken: ct);
            Assert.Null(signedOut.Error);
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.Relay == RelayState.Disabled,
                TimeSpan.FromSeconds(15), "the channel is disabled after the sign-out");
        }

        await connection.Done.WaitAsync(TimeSpan.FromSeconds(15), ct);
        await node.StopNodeAsync();

        var lines = File.ReadAllLines(connectLog);
        Assert.All(lines, line => Assert.StartsWith("127.0.0.1:" + center.Endpoint.Port + " sent ", line, StringComparison.Ordinal));
        var log = TestNode.ReadShared(node.NodeLog);
        Assert.Contains("cloud.channel.connected", log, StringComparison.Ordinal);
        Assert.Contains("cloud.channel.call_answered", log, StringComparison.Ordinal);

        // N1-22: no token of the center and no payload byte string reaches a file outside the secret store.
        await TestNode.WaitAsync(() => node.LiveProcesses().Count == 0, TimeSpan.FromSeconds(30), "the node and its supervisor to exit");
        var secrets = Path.Combine(node.DataRoot, "run", "test-secrets") + Path.DirectorySeparatorChar;
        var read = new List<string>();
        foreach (var file in Directory.EnumerateFiles(node.Root, "*", SearchOption.AllDirectories)
            .Where(file => !file.StartsWith(secrets, StringComparison.Ordinal) && !file.EndsWith(".lock", StringComparison.Ordinal)).ToList())
        {
            if (CloudLinkHostTests.ReadAllShared(file) is not { } bytes)
            {
                continue;
            }

            read.Add(file);
            var text = System.Text.Encoding.Latin1.GetString(bytes);
            Assert.False(text.Contains("afr1.", StringComparison.Ordinal) || text.Contains("afa1.", StringComparison.Ordinal), "a token in " + file);
            Assert.False(text.Contains(marker, StringComparison.Ordinal), "the call payload in " + file);
        }

        Assert.Contains(read, file => file.EndsWith("node.db", StringComparison.Ordinal));
    }
}
