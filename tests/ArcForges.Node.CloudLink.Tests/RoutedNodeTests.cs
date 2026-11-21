// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>AF-CTR-05 retained Task ownership and cancellation through the real verifier, dispatcher, signer and audit store.</summary>
/// <remarks>
/// FakeCenter sends signed synthetic calls. The source at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a preserves the original V1 native payload,
/// output offset and running-process cancellation checks. Installed V2 Run and privacy checks live in CliMxcRunServiceTests,
/// TerminalCliMxcRunServiceTests and SecurityMxcRunServiceTests.
/// </remarks>
public sealed class RoutedNodeTests
{
    [Fact(Timeout = 180_000)]
    public async Task AVerifiedRoutedCallerCanCancelItsRetainedTaskWithoutAdmittingNewWork()
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
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(nodeId) },
            LocalOrigin = Origin.Script,
            LocalSessionId = CommandIds.New(),
        };

        var confirmed = new List<(byte[] Call, byte[] Sha256)>();
        async Task<ByteString> RouteAsync(RoutedMethod method, IMessage request, Id? commandId = null)
        {
            var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec { Method = method, Payload = request.ToByteArray(), Caller = caller, CommandId = commandId });
            await connection.SendCallAsync(call);
            var result = await connection.ResultOfAsync(call.CallId);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(verified => verified.Header.CallId.Equals(call.CallId)), "the result verified at the peer");
            Assert.Empty(connection.UnverifiedResults);
            var header = connection.VerifiedResults.Single(verified => verified.Header.CallId.Equals(call.CallId)).Header;
            Assert.Equal(RoutedOutcome.Executed, header.Outcome);
            confirmed.Add((call.CallId.Value.ToByteArray(), SHA256.HashData(result.Payload.Span)));
            return result.Payload;
        }

        var store = node.Runtime.Store;
        var taskId = CommandIds.New();
        var owner = new ActorRef
        {
            Origin = Origin.Remote,
            ClientKind = ClientKind.Unspecified,
            CenterCaller = caller,
            RemoteCommandId = CommandIds.New(),
        };
        var spec = HistoricalSpec(node.Root, "retained-task-fixture");
        store.Write(transaction => SeedQueuedTask(transaction, taskId, owner, spec), CommitDurability.Full);
        var get = new TaskServiceGetTaskRequest { Meta = CloudNode.Command(), TaskId = taskId, Detail = TaskDetail.Full };
        var queued = TaskServiceGetTaskResponse.Parser.ParseFrom(await RouteAsync(RoutedMethod.GetNodeTask, get));
        Assert.Null(queued.Error);
        Assert.Equal(TaskState.Queued, queued.Value.Task.State);
        Assert.Equal(owner, queued.Value.Task.Owner);
        Assert.Equal(spec, queued.Value.Task.Spec);

        var cancel = new TaskServiceCancelTaskRequest { Meta = CloudNode.Command(), TaskId = taskId };
        var cancelledBytes = await RouteAsync(RoutedMethod.CancelNodeTask, cancel, cancel.Meta.CommandId);
        var cancelled = TaskServiceCancelTaskResponse.Parser.ParseFrom(cancelledBytes);
        Assert.Null(cancelled.Error);
        Assert.Equal(TaskState.Cancelled, cancelled.Value.State);
        Assert.Equal(cancel.Meta.CommandId, cancelled.Value.Receipt.CommandId);
        Assert.Equal(EffectCertainty.Happened, cancelled.Value.Receipt.Effect);
        Assert.Equal(cancelledBytes, await RouteAsync(RoutedMethod.CancelNodeTask, cancel, cancel.Meta.CommandId));

        var terminal = TaskServiceGetTaskResponse.Parser.ParseFrom(await RouteAsync(RoutedMethod.GetNodeTask, get));
        Assert.Null(terminal.Error);
        Assert.Equal(TaskState.Cancelled, terminal.Value.Task.State);
        Assert.Equal(owner, terminal.Value.Task.Owner);
        Assert.Equal(queued.Value.Task.Revision.Value + 1, terminal.Value.Task.Revision.Value);

        // A verified fresh Submit is declined before admission. The request is kept out of the structured log.
        var argvMarker = "N2BARGV" + Guid.NewGuid().ToString("N");
        var envMarker = "N2BENV" + Guid.NewGuid().ToString("N");
        var marked = HistoricalSpec(node.Root, "retained-task-fixture", argvMarker);
        marked.Environment.Set["N2B_SENSITIVE_TOKEN"] = envMarker;
        var submit = new TaskServiceSubmitTaskRequest { Meta = CloudNode.Command(), Spec = marked };
        var refused = TaskServiceSubmitTaskResponse.Parser.ParseFrom(await RouteAsync(RoutedMethod.SubmitNodeTask, submit, submit.Meta.CommandId));
        Assert.Equal("operation_failed", refused.Error.Code);
        Assert.Equal("legacy_task_outcome_unavailable", refused.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, refused.Error.Effect);
        Assert.Equal(RetryMode.Never, refused.Error.Retry.Mode);
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;",
            ("$id", submit.Meta.CommandId.Value.ToByteArray()))));

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

        Assert.Equal((long)confirmed.Count, store.Read(reader => reader.Scalar("SELECT count(*) FROM routed_call_log;")));
        foreach (var (call, digest) in confirmed)
        {
            var audit = store.Read(reader =>
            {
                using var query = reader.CreateCommand("SELECT decision, response_sha256 FROM routed_call_log WHERE call_id = $call;");
                query.Parameters.AddWithValue("$call", call);
                using var rows = query.ExecuteReader();
                Assert.True(rows.Read());
                return (Decision: rows.GetInt32(0), Digest: (byte[])rows.GetValue(1));
            });
            Assert.Equal((int)RoutedCallDecision.Executed, audit.Decision);
            Assert.Equal(digest, audit.Digest);
        }
    }

    private static void SeedQueuedTask(StoreTransaction transaction, Id taskId, ActorRef owner, TaskSpec spec)
    {
        var bytes = spec.ToByteArray();
        transaction.Execute("""
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                              pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                              command_digest, created_at, queued_at, rev)
            VALUES ($id, $state, $kind, 'retained task fixture', 'retained task fixture', $spec, $digest, $owner, $origin,
                    'default', 3, 3, 4, 1, 'retained-task-fixture', $digest, $now, $now, 0);
            """, ("$id", taskId.Value.ToByteArray()), ("$state", (int)TaskState.Queued), ("$kind", (int)TaskKind.Command),
            ("$spec", bytes), ("$digest", SHA256.HashData(bytes)), ("$owner", owner.ToByteArray()), ("$origin", (int)Origin.Remote),
            ("$now", transaction.NowMicroseconds));
    }

    private static TaskSpec HistoricalSpec(string directory, params string[] argv) => new()
    {
        Kind = TaskKind.Command,
        Command = new CommandSpec { Argv = new ArgvCommand { Argv = { argv } } },
        WorkingDirectory = directory,
        Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
    };
}
