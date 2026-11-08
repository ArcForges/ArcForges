// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// AF-CTR-05 part N2b end to end against FakeCenter's channel peer: a REAL node (NodeHost, store, execution platform: the Windows job, Linux
/// cgroups where delegated) signed in with its channel, a routed run through the real verifier, dispatcher and signer, its output by offset,
/// and a routed cancel; every result verified at the peer with its own verifier (N2-16's FakeCenter half; N2-22 on Windows). MOCKED: the
/// center (FakeCenter; the real-center closed loops N2-16..N2-20 run at the E2b merge).
/// </summary>
public sealed class RoutedNodeTests
{
    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    [Fact(Timeout = 180_000)]
    public async Task ARoutedRunExecutesOnTheNodeAndARoutedCancelEndsIt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var center = await FakeCenter.StartAsync();
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            if (!center.CommandKeys.Any(existing => existing.Kid == FakeChannelPeer.Kid))
            {
                center.CommandKeys.Add(center.Channel.CommandPublicKey);
            }

            center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        var connection = await center.Channel.ProvedAsync();
        await using var human = await node.ChannelAsync(Origin.Human);
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(nodeId) },
            LocalOrigin = Origin.Script,
            LocalSessionId = CommandIds.New(),
        };

        async Task<(ResultHeader Header, ByteString Payload)> RouteAsync(RoutedMethod method, IMessage request, Id? commandId = null)
        {
            var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec { Method = method, Payload = request.ToByteArray(), Caller = caller, CommandId = commandId });
            await connection.SendCallAsync(call);
            var result = await connection.ResultOfAsync(call.CallId);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(verified => verified.Header.CallId.Equals(call.CallId)), "the result verified at the peer");
            Assert.Empty(connection.UnverifiedResults);
            return (connection.VerifiedResults.Single(verified => verified.Header.CallId.Equals(call.CallId)).Header, result.Payload);
        }

        // A routed run of a process that prints, through the platform; its output by offset.
        var printing = Spec(node.Root, CloudNode.TestLoad, "output", "--bytes", "2048");
        var submit = new TaskServiceSubmitTaskRequest { Meta = CloudNode.Command(), Spec = printing };
        var (header, payload) = await RouteAsync(RoutedMethod.SubmitNodeTask, submit, submit.Meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, header.Outcome);
        var submitted = TaskServiceSubmitTaskResponse.Parser.ParseFrom(payload);
        Assert.True(submitted.Error is null, $"{submitted.Error?.Category}/{submitted.Error?.Code}");
        var wait = new TaskServiceWaitTaskRequest { Meta = CloudNode.Command(), TaskId = submitted.Value.TaskId, WaitMs = 8_000 };
        ManagedTask task;
        do
        {
            task = TaskServiceWaitTaskResponse.Parser.ParseFrom((await RouteAsync(RoutedMethod.WaitNodeTask, wait)).Payload).Value.Task;
        }
        while (task.State is not (TaskState.Succeeded or TaskState.Failed or TaskState.Cancelled or TaskState.Lost));

        Assert.Equal(TaskState.Succeeded, task.State);
        Assert.Equal(new ActorRef { Origin = Origin.Remote, ClientKind = ClientKind.Unspecified, CenterCaller = caller, RemoteCommandId = submit.Meta.CommandId }, task.Owner);
        var read = new TaskServiceReadTaskOutputRequest { Meta = CloudNode.Command(), AttemptId = task.CurrentAttempt.AttemptId, FromOffset = 1024, MaxBytes = 512 };
        var output = TaskServiceReadTaskOutputResponse.Parser.ParseFrom((await RouteAsync(RoutedMethod.ReadNodeTaskOutput, read)).Payload).Value;
        Assert.Equal((512, 1536UL), (output.Data.Length, output.NextOffset));

        // N2-22: a routed run of a holding process under the platform (the job on Windows), and a routed cancel that ends it.
        var holding = new TaskServiceSubmitTaskRequest { Meta = CloudNode.Command(), Spec = Spec(node.Root, CloudNode.TestLoad, "hold", "--hold-ms", "120000") };
        var held = TaskServiceSubmitTaskResponse.Parser.ParseFrom((await RouteAsync(RoutedMethod.SubmitNodeTask, holding, holding.Meta.CommandId)).Payload).Value.TaskId;
        var started = await WaitAsync(human, held, WaitTarget.Started);
        Assert.Equal(TaskState.Running, started.State);
        if (OperatingSystem.IsWindows())
        {
            Assert.False(started.CurrentAttempt.Unenforced, "a routed run on Windows runs under the node's job");
        }

        var cancel = new TaskServiceCancelTaskRequest { Meta = CloudNode.Command(), TaskId = held };
        var (cancelled, cancelPayload) = await RouteAsync(RoutedMethod.CancelNodeTask, cancel, cancel.Meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, cancelled.Outcome);
        Assert.Null(TaskServiceCancelTaskResponse.Parser.ParseFrom(cancelPayload).Error);
        Assert.Equal(TaskState.Cancelled, (await WaitAsync(human, held, WaitTarget.Terminal)).State);

        // N2-25: a successful routed task actually receives both an argv marker and a secret-shaped environment marker. Its legitimate
        // task output contains them; the node's structured logs must contain neither marker nor either synthetic center credential.
        var argvMarker = "N2BARGV" + Guid.NewGuid().ToString("N");
        var envMarker = "N2BENV" + Guid.NewGuid().ToString("N");
        var marked = OperatingSystem.IsWindows()
            ? Spec(node.Root, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"), "/d", "/c", "echo %N2B_SENSITIVE_TOKEN% & echo " + argvMarker)
            : Spec(node.Root, "/bin/sh", "-c", "printf '%s\\n' \"$N2B_SENSITIVE_TOKEN\" \"$1\"", "n2b", argvMarker);
        marked.Environment.Set["N2B_SENSITIVE_TOKEN"] = envMarker;
        var markedRequest = new TaskServiceSubmitTaskRequest { Meta = CloudNode.Command(), Spec = marked };
        var (markedHeader, markedPayload) = await RouteAsync(RoutedMethod.SubmitNodeTask, markedRequest, markedRequest.Meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, markedHeader.Outcome);
        var markedSubmit = TaskServiceSubmitTaskResponse.Parser.ParseFrom(markedPayload);
        Assert.Null(markedSubmit.Error);
        var markedTask = await WaitAsync(human, markedSubmit.Value.TaskId, WaitTarget.Terminal);
        Assert.Equal(TaskState.Succeeded, markedTask.State);
        var markedRead = new TaskServiceReadTaskOutputRequest { Meta = CloudNode.Command(), AttemptId = markedTask.CurrentAttempt.AttemptId, FromOffset = 0, MaxBytes = 4096 };
        var markedOutput = TaskServiceReadTaskOutputResponse.Parser.ParseFrom((await RouteAsync(RoutedMethod.ReadNodeTaskOutput, markedRead)).Payload);
        Assert.Null(markedOutput.Error);
        var outputText = markedOutput.Value.Data.ToStringUtf8();
        Assert.True(outputText.Contains(argvMarker, StringComparison.Ordinal), "the child received its argv marker");
        Assert.True(outputText.Contains(envMarker, StringComparison.Ordinal), "the child received its environment marker");
        var logs = Directory.EnumerateFiles(Path.Combine(node.DataRoot, "logs", "node"), "*", SearchOption.AllDirectories).ToArray();
        Assert.NotEmpty(logs);
        foreach (var file in logs)
        {
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            var content = reader.ReadToEnd();
            Assert.False(content.Contains(argvMarker, StringComparison.Ordinal), "the routed argv appeared in a node log");
            Assert.False(content.Contains(envMarker, StringComparison.Ordinal), "the routed environment value appeared in a node log");
            Assert.False(content.Contains(credentials.AccessToken, StringComparison.Ordinal), "a synthetic access credential appeared in a node log");
            Assert.False(content.Contains(credentials.RefreshToken, StringComparison.Ordinal), "a synthetic refresh credential appeared in a node log");
        }

        // Every routed call has its completed routed_call_log row (N2-10): executed, with the response's digest.
        Assert.All(node.Runtime.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("SELECT decision, response_sha256 IS NOT NULL FROM routed_call_log;");
            using var rows = command.ExecuteReader();
            var found = new List<(long, bool)>();
            while (rows.Read())
            {
                found.Add((rows.GetInt64(0), rows.GetBoolean(1)));
            }

            return found;
        }), row => Assert.Equal((1L, true), row));
    }

    private static async Task<ManagedTask> WaitAsync(NodeChannel channel, Id task, WaitTarget target)
    {
        var response = await channel.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest { Meta = CloudNode.Command(), TaskId = task, Target = target, WaitMs = 50_000 },
            deadline: DateTime.UtcNow.AddSeconds(58), cancellationToken: Cancel);
        Assert.True(response.Error is null && response.Value.Reached, $"WaitTask {target}: {response.Error?.Code}");
        return response.Value.Task;
    }

    private static TaskSpec Spec(string directory, params string[] argv)
    {
        var command = new ArgvCommand();
        command.Argv.Add(argv);
        return new TaskSpec { Command = new CommandSpec { Argv = command }, WorkingDirectory = directory, Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node } };
    }
}
