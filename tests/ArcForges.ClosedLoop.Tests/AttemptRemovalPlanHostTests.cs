// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// A real Windows Host and task producer with native files, SQLite and signed channel. The Center peer and
/// account custody are isolated fixtures; this is not actual Center routing or strict cleanup acceptance.
/// </summary>
[Trait("loop", "local")]
public sealed class AttemptRemovalPlanHostTests
{
    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    public async Task SignedActualAttemptPlanAndReceiptSurviveRestartWithoutFileEffects()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Attempt create provenance is Windows native.");
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        using var host = await node.StartNodeAsync();
        Assert.False(host.HasExited);
        try
        {
            await using var human = await node.HumanChannelAsync();
            var info = await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct);
            Assert.Null(info.Error);
            Assert.DoesNotContain("files.v1", info.Value.Node.Features);
            var nodeId = info.Value.Node.Node.NodeId;
            var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest
            {
                Meta = Command(),
                Method = SignInMethod.DeviceCode,
            }, cancellationToken: ct);
            Assert.Null(begun.Error);
            center.ApproveDevice();
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(
                new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.Relay == RelayState.Connected,
                TimeSpan.FromSeconds(30), "the isolated center peer is connected");
            var channel = await center.Channel.ProvedAsync();
            var caller = new CenterCaller
            {
                Kind = CenterCallerKind.NodeRelay,
                AccountId = new Id { Value = ByteString.CopyFrom(channel.AccountId) },
                RelayingNodeId = nodeId.Clone(),
                LocalOrigin = Origin.Agent,
                LocalSessionId = CommandIds.New(),
            };

            async Task<byte[]> Invoke(RoutedMethod method, IMessage request, Id command, CenterCaller source)
            {
                var built = center.Channel.BuildCall(channel, new FakeCallSpec
                {
                    Method = method,
                    Payload = request.ToByteArray(),
                    Caller = source,
                    CommandId = command,
                    Lifetime = TimeSpan.FromSeconds(30),
                });
                await channel.SendCallAsync(built.Call);
                var frame = await channel.ResultOfAsync(built.Call.CallId);
                await TestNode.WaitAsync(() => channel.VerifiedResults.Any(value => value.Header.CallId.Equals(built.Call.CallId)),
                    TimeSpan.FromSeconds(15), "the real Host result signature verifies");
                Assert.Equal(RoutedOutcome.Executed, channel.VerifiedResults.Single(value => value.Header.CallId.Equals(built.Call.CallId)).Header.Outcome);
                return frame.Payload.ToByteArray();
            }

            var submit = new TaskServiceSubmitTaskRequest
            {
                Meta = Command(),
                Spec = new TaskSpec
                {
                    Command = new CommandSpec
                    {
                        Shell = new ShellCommand { Kind = ShellKind.Cmd, Script = "echo retained>\"%TEMP%\\keep.txt\"" },
                    },
                    WorkingDirectory = node.Root,
                    Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
                },
            };
            var submitted = TaskServiceSubmitTaskResponse.Parser.ParseFrom(
                await Invoke(RoutedMethod.SubmitNodeTask, submit, submit.Meta.CommandId, caller));
            Assert.Null(submitted.Error);
            var waited = await human.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest
            {
                Meta = Command(),
                TaskId = submitted.Value.TaskId,
                Target = WaitTarget.Terminal,
                WaitMs = 50_000,
            }, cancellationToken: ct);
            Assert.Null(waited.Error);
            Assert.Equal(TaskState.Succeeded, waited.Value.Task.State);
            var attempt = waited.Value.Task.CurrentAttempt.AttemptId;
            await TestNode.WaitAsync(() => AttemptIsIdle(node.DataRoot, attempt),
                TimeSpan.FromSeconds(20), "the actual native attempt identity and idle transition");

            var root = Path.Combine(node.DataRoot, "tmp", IdText.Format(attempt));
            var file = Path.Combine(root, "keep.txt");
            Assert.Equal("retained", File.ReadAllText(file).Trim());
            const string body = "signed-host-attempt-content-not-persisted-5189";
            File.WriteAllText(file, body);
            var directory = Directory.CreateDirectory(Path.Combine(root, "later")).FullName;
            File.WriteAllText(Path.Combine(directory, "child.txt"), "child-fixture");

            var request = new FileServicePlanRemovalRequest { Meta = Command(), AttemptId = attempt.Clone() };
            var raw = request.ToByteArray();
            var first = await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId, caller);
            Assert.Equal(-1, first.AsSpan().IndexOf(Encoding.UTF8.GetBytes(body)));
            var response = FileServicePlanRemovalResponse.Parser.ParseFrom(first);
            Assert.True(NodeShapes.IsValid(response));
            Assert.Null(response.Error);
            var plan = response.Value.Plan;
            Assert.Equal(attempt, plan.AttemptId);
            Assert.Null(plan.WorkspacePath);
            Assert.Equal(RiskClass.High, plan.Risk);
            Assert.True(plan.RequiresApproval);
            Assert.False(plan.QuarantineAvailable);
            Assert.Equal(4, plan.Items.Count);
            Assert.Equal((ulong)(new FileInfo(file).Length + new FileInfo(Path.Combine(directory, "child.txt")).Length), plan.TotalBytes);
            Assert.Equal("", plan.Items[0].Path);
            Assert.Equal(FileEntryKind.Directory, plan.Items[0].Kind);
            Assert.True(plan.Items[0].OwnerVerified);
            Assert.Contains(plan.Items, item => item.Path == "later/child.txt");
            Assert.All(plan.Items.Skip(1), item => Assert.False(item.OwnerVerified));
            Assert.True(response.Audit is null || response.Audit.Observations.Count == 0);
            AssertPersisted(node.DataRoot, request.Meta.CommandId, raw, first, caller, attempt);

            // Only these association rows are fixtures: the Host producer, FULL refusal/audit and signature are real.
            var unknownSession = CommandIds.New().Value.ToByteArray();
            FixtureWrite(node.DataRoot, """
                INSERT INTO session (session_id, client, source, state, started_at, last_activity_at, rev)
                VALUES ($id, 1, 1, 1, $now, $now, 0);
                """, ("$id", unknownSession), ("$now", StoreTime.ToMicroseconds(DateTimeOffset.UtcNow)));
            var unknownRequest = new FileServicePlanRemovalRequest { Meta = Command(), AttemptId = attempt.Clone() };
            var unknownFirst = await Invoke(RoutedMethod.PlanNodeRemoval, unknownRequest, unknownRequest.Meta.CommandId, caller);
            AssertQualification(unknownFirst, "attempt_references_unverified");
            FixtureWrite(node.DataRoot, "UPDATE session SET state = 3 WHERE session_id = $id;", ("$id", unknownSession));
            Assert.Equal(unknownFirst, await Invoke(RoutedMethod.PlanNodeRemoval, unknownRequest, unknownRequest.Meta.CommandId, caller));

            // A missing root association cannot be invented by tracking classification.
            var unknownDirectory = CommandIds.New().Value.ToByteArray();
            var recordsRoot = FixtureScalar(node.DataRoot, "SELECT path FROM root_location WHERE root_class = 'records';") as string;
            FixtureWrite(node.DataRoot, """
                DELETE FROM root_location WHERE root_class = 'records';
                INSERT INTO managed_directory
                  (directory_id, owner_kind, owner_id, root_class, relative_path, created_at, last_used_at, pinned, state, rev)
                VALUES ($id, 5, $owner, 'records', 'unresolved-reference', $now, $now, 0, 2, 0);
                """, ("$id", unknownDirectory), ("$owner", nodeId.Value.ToByteArray()),
                ("$now", StoreTime.ToMicroseconds(DateTimeOffset.UtcNow)));
            var trackingRequest = new FileServicePlanRemovalRequest { Meta = Command(), AttemptId = attempt.Clone() };
            var trackingFirst = await Invoke(RoutedMethod.PlanNodeRemoval, trackingRequest, trackingRequest.Meta.CommandId, caller);
            AssertQualification(trackingFirst, "attempt_tracking_unverified");
            FixtureWrite(node.DataRoot, "UPDATE managed_directory SET state = 5 WHERE directory_id = $id;", ("$id", unknownDirectory));
            if (recordsRoot is not null) FixtureWrite(node.DataRoot,
                "INSERT INTO root_location (root_class, path) VALUES ('records', $path);", ("$path", recordsRoot));
            Assert.Equal(trackingFirst, await Invoke(RoutedMethod.PlanNodeRemoval, trackingRequest, trackingRequest.Meta.CommandId, caller));
            Assert.Equal(1L, FixtureScalar(node.DataRoot, "SELECT count(*) FROM file_removal_plan;"));
            Assert.Equal(0L, FixtureScalar(node.DataRoot, "SELECT count(*) FROM file_operation_journal;"));

            var foreign = caller.Clone();
            foreign.LocalSessionId = CommandIds.New();
            var foreignRequest = new FileServicePlanRemovalRequest { Meta = Command(), AttemptId = attempt.Clone() };
            var foreignReply = FileServicePlanRemovalResponse.Parser.ParseFrom(
                await Invoke(RoutedMethod.PlanNodeRemoval, foreignRequest, foreignRequest.Meta.CommandId, foreign));
            Assert.Equal("not_found", foreignReply.Error.Code);
            File.WriteAllText(file, body + "-after-plan");
            Assert.Equal(first, await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId, caller));
            await node.StopNodeAsync();
            await node.StartNodeAsync();
            channel = await center.Channel.ProvedAsync(2);
            Assert.Equal(first, await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId, caller));
            Assert.Equal(unknownFirst, await Invoke(RoutedMethod.PlanNodeRemoval, unknownRequest, unknownRequest.Meta.CommandId, caller));
            Assert.Equal(trackingFirst, await Invoke(RoutedMethod.PlanNodeRemoval, trackingRequest, trackingRequest.Meta.CommandId, caller));
            AssertPersisted(node.DataRoot, request.Meta.CommandId, raw, first, caller, attempt);
            Assert.Equal(body + "-after-plan", File.ReadAllText(file));
            Assert.True(Directory.Exists(directory));
            Assert.Empty(channel.UnverifiedResults);
            foreach (var path in new[] { StorePaths.Database(node.DataRoot), StorePaths.Database(node.DataRoot) + "-wal", node.NodeLog })
            {
                if (CloudLinkHostTests.ReadAllShared(path) is not { } bytes) continue;
                Assert.Equal(-1, bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(body)));
            }
        }
        finally
        {
            if (node.Descriptor() is { } descriptor && descriptor.ProcessIsAlive())
            {
                await using var cleanup = await node.HumanChannelAsync();
                var signedOut = await cleanup.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() },
                    deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: CancellationToken.None);
                Assert.Null(signedOut.Error);
                await node.StopNodeAsync();
            }
        }
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "linux-real")]
    public async Task SignedRealLinuxAttemptWithoutProvenanceRefusesAndReplays()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux producer does not record native-create provenance.");
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        using var host = await node.StartNodeAsync();
        Assert.False(host.HasExited);
        try
        {
            await using var human = await node.HumanChannelAsync();
            var info = await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct);
            Assert.Null(info.Error);
            Assert.DoesNotContain("files.v1", info.Value.Node.Features);
            var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest
            {
                Meta = Command(),
                Method = SignInMethod.DeviceCode,
            }, cancellationToken: ct);
            Assert.Null(begun.Error);
            center.ApproveDevice();
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(
                new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.Relay == RelayState.Connected,
                TimeSpan.FromSeconds(30), "the isolated center peer is connected");
            var channel = await center.Channel.ProvedAsync();
            var caller = new CenterCaller
            {
                Kind = CenterCallerKind.NodeRelay,
                AccountId = new Id { Value = ByteString.CopyFrom(channel.AccountId) },
                RelayingNodeId = info.Value.Node.Node.NodeId.Clone(),
                LocalOrigin = Origin.Agent,
                LocalSessionId = CommandIds.New(),
            };

            async Task<byte[]> Invoke(RoutedMethod method, IMessage request, Id command)
            {
                var built = center.Channel.BuildCall(channel, new FakeCallSpec
                {
                    Method = method,
                    Payload = request.ToByteArray(),
                    Caller = caller,
                    CommandId = command,
                    Lifetime = TimeSpan.FromSeconds(30),
                });
                await channel.SendCallAsync(built.Call);
                var frame = await channel.ResultOfAsync(built.Call.CallId);
                await TestNode.WaitAsync(() => channel.VerifiedResults.Any(value => value.Header.CallId.Equals(built.Call.CallId)),
                    TimeSpan.FromSeconds(15), "the real Host result signature verifies");
                Assert.Equal(RoutedOutcome.Executed, channel.VerifiedResults.Single(value => value.Header.CallId.Equals(built.Call.CallId)).Header.Outcome);
                return frame.Payload.ToByteArray();
            }

            var argv = new ArgvCommand();
            argv.Argv.Add("/bin/sh");
            argv.Argv.Add("-c");
            argv.Argv.Add("printf retained > \"$TMPDIR/keep.txt\"");
            var submit = new TaskServiceSubmitTaskRequest
            {
                Meta = Command(),
                Spec = new TaskSpec
                {
                    Command = new CommandSpec { Argv = argv },
                    WorkingDirectory = node.Root,
                    Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
                },
            };
            var submitted = TaskServiceSubmitTaskResponse.Parser.ParseFrom(
                await Invoke(RoutedMethod.SubmitNodeTask, submit, submit.Meta.CommandId));
            Assert.Null(submitted.Error);
            var waited = await human.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest
            {
                Meta = Command(),
                TaskId = submitted.Value.TaskId,
                Target = WaitTarget.Terminal,
                WaitMs = 50_000,
            }, cancellationToken: ct);
            Assert.Null(waited.Error);
            Assert.Equal(TaskState.Succeeded, waited.Value.Task.State);
            var attempt = waited.Value.Task.CurrentAttempt.AttemptId;
            var file = Path.Combine(node.DataRoot, "tmp", IdText.Format(attempt), "keep.txt");
            Assert.Equal("retained", File.ReadAllText(file));
            var request = new FileServicePlanRemovalRequest { Meta = Command(), AttemptId = attempt.Clone() };
            var raw = request.ToByteArray();
            var first = await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId);
            var refusal = FileServicePlanRemovalResponse.Parser.ParseFrom(first);
            Assert.True(NodeShapes.IsValid(refusal));
            Assert.Equal(ErrorCategory.State, refusal.Error.Category);
            Assert.Equal("file_access_denied", refusal.Error.Code);
            Assert.Equal("identity_unavailable", refusal.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, refusal.Error.Effect);
            Assert.Equal(RetryMode.Never, refusal.Error.Retry.Mode);
            Assert.True(refusal.Audit is null || refusal.Audit.Observations.Count == 0);
            AssertNoAttemptPlan(node.DataRoot, request.Meta.CommandId, raw, first, attempt);
            Assert.Equal(first, await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId));
            await node.StopNodeAsync();
            await node.StartNodeAsync();
            channel = await center.Channel.ProvedAsync(2);
            Assert.Equal(first, await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId));
            AssertNoAttemptPlan(node.DataRoot, request.Meta.CommandId, raw, first, attempt);
            Assert.Equal("retained", File.ReadAllText(file));
            Assert.Empty(channel.UnverifiedResults);
        }
        finally
        {
            if (node.Descriptor() is { } descriptor && descriptor.ProcessIsAlive())
            {
                await using var cleanup = await node.HumanChannelAsync();
                var signedOut = await cleanup.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() },
                    deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: CancellationToken.None);
                Assert.Null(signedOut.Error);
                await node.StopNodeAsync();
            }
        }
    }

    private static void AssertQualification(byte[] encoded, string reason)
    {
        var response = FileServicePlanRemovalResponse.Parser.ParseFrom(encoded);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Null(response.Value);
        Assert.Equal(ErrorCategory.State, response.Error.Category);
        Assert.Equal("invalid_state", response.Error.Code);
        Assert.Equal("file", response.Error.Details.State.State);
        Assert.Equal(reason, response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(RetryMode.Never, response.Error.Retry.Mode);
        Assert.Null(response.Error.Retry.RetryAt);
        Assert.False(response.Error.Retry.HasReconciliationOperation);
        Assert.Null(response.Error.Details.State.Resource);
        Assert.Null(response.Error.Details.State.Native);
    }

    // Isolated metadata fixtures only. Never used with a production database or to manufacture an effect result.
    private static void FixtureWrite(string dataRoot, string sql, params (string Name, object? Value)[] parameters)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(dataRoot),
            Mode = SqliteOpenMode.ReadWrite,
        }.ToString());
        connection.Open();
        using var setting = connection.CreateCommand();
        setting.CommandText = "PRAGMA synchronous=FULL;";
        setting.ExecuteNonQuery();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private static object? FixtureScalar(string dataRoot, string sql)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(dataRoot),
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private static void AssertNoAttemptPlan(string dataRoot, Id command, byte[] raw, byte[] response, Id attempt)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = StorePaths.Database(dataRoot), Mode = SqliteOpenMode.ReadOnly };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT d.payload_digest, d.outcome,
                   (SELECT count(*) FROM file_removal_plan WHERE command_id = d.command_id),
                   (SELECT count(*) FROM file_attempt_temp_identity WHERE attempt_id = $attempt),
                   (SELECT count(*) FROM file_workspace_audit f JOIN audit_log a ON a.seq = f.audit_seq
                    WHERE f.attempt_id = $attempt AND a.operation = 'cleanup.plan FileService.PlanRemoval'
                      AND a.outcome_summary = 'refused: file_access_denied')
            FROM command_dedup d WHERE d.command_id = $id;
            """;
        query.Parameters.AddWithValue("$id", command.Value.ToByteArray());
        query.Parameters.AddWithValue("$attempt", attempt.Value.ToByteArray());
        using var row = query.ExecuteReader();
        Assert.True(row.Read());
        Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(0));
        Assert.Equal(response, (byte[])row.GetValue(1));
        Assert.Equal(0L, row.GetInt64(2));
        Assert.Equal(0L, row.GetInt64(3));
        Assert.Equal(1L, row.GetInt64(4));
        Assert.False(row.Read());
    }

    private static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };

    private static bool AttemptIsIdle(string dataRoot, Id attempt)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = StorePaths.Database(dataRoot), Mode = SqliteOpenMode.ReadOnly };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT count(*) FROM file_attempt_temp_identity p
            JOIN managed_directory m ON m.directory_id = p.directory_id
            JOIN attempt a ON a.attempt_id = p.attempt_id
            WHERE p.attempt_id = $id AND m.state = 2 AND a.state = 9;
            """;
        query.Parameters.AddWithValue("$id", attempt.Value.ToByteArray());
        return (long)query.ExecuteScalar()! == 1;
    }

    private static void AssertPersisted(string dataRoot, Id command, byte[] raw, byte[] response, CenterCaller caller, Id attempt)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = StorePaths.Database(dataRoot), Mode = SqliteOpenMode.ReadOnly };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT p.target_kind, p.attempt_id, p.request_sha256, p.caller, d.outcome,
                   (SELECT count(*) FROM file_removal_plan_item i WHERE i.plan_id = p.plan_id),
                   (SELECT count(*) FROM file_removal_plan_item i WHERE i.plan_id = p.plan_id AND i.owner_verified = 1),
                   (SELECT count(*) FROM audit_log WHERE operation = 'cleanup.plan FileService.PlanRemoval' AND outcome_summary = 'planned'),
                   (SELECT c.item_class FROM cleanup_item c JOIN file_removal_plan_item i
                    ON i.plan_id = c.plan_id AND i.item_id = c.item_id WHERE i.plan_id = p.plan_id AND i.ordinal = 0),
                   (SELECT count(*) FROM cleanup_item c JOIN file_removal_plan_item i
                    ON i.plan_id = c.plan_id AND i.item_id = c.item_id
                    WHERE i.plan_id = p.plan_id AND i.ordinal > 0 AND c.item_class = 10)
            FROM file_removal_plan p JOIN command_dedup d ON d.command_id = p.command_id WHERE p.command_id = $id;
            """;
        query.Parameters.AddWithValue("$id", command.Value.ToByteArray());
        using var row = query.ExecuteReader();
        Assert.True(row.Read());
        Assert.Equal(2, row.GetInt32(0));
        Assert.Equal(attempt.Value.ToByteArray(), (byte[])row.GetValue(1));
        Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(2));
        Assert.Equal(caller, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(3)));
        Assert.Equal(response, (byte[])row.GetValue(4));
        Assert.Equal(4L, row.GetInt64(5));
        Assert.Equal(1L, row.GetInt64(6));
        Assert.Equal(1L, row.GetInt64(7));
        Assert.Equal(1, row.GetInt32(8));
        Assert.Equal(1L, row.GetInt64(9)); // only the unrecorded directory, not either ordinary file

        Assert.False(row.Read());
    }
}
