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
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Actual Host, native private producer and FULL SQLite. The signed center/caller peer is synthetic.</summary>
[Trait("loop", "local")]
public sealed class FileStageProducerHostTests
{
    [Fact(Timeout = 180_000)]
    public async Task DefaultScriptUsesARealIdentityBoundProducerAndPendingApprovalSurvivesActualRestart()
    {
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
            var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest
            {
                Meta = Command(),
                Method = SignInMethod.DeviceCode,
            }, cancellationToken: ct);
            Assert.Null(begun.Error);
            center.ApproveDevice();
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(
                new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.Relay == RelayState.Connected,
                TimeSpan.FromSeconds(30), "the synthetic peer has a real signed channel");
            var connection = await center.Channel.ProvedAsync();
            var owner = new CenterCaller
            {
                Kind = CenterCallerKind.NodeRelay,
                AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
                RelayingNodeId = info.Value.Node.Node.NodeId.Clone(),
                LocalOrigin = Origin.Human,
                LocalSessionId = CommandIds.New(),
            };
            var script = owner.Clone();
            script.LocalOrigin = Origin.Script;
            script.LocalSessionId = CommandIds.New();
            var root = Directory.CreateDirectory(Path.Combine(node.Root, "default-script-stage-workspace")).FullName;
            async Task<(ResultHeader Header, byte[] Payload)> Invoke(RoutedMethod method, IMessage request, Id? id, CenterCaller actor)
            {
                var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec
                {
                    Method = method,
                    Payload = request.ToByteArray(),
                    CommandId = id,
                    Caller = actor,
                    Lifetime = TimeSpan.FromSeconds(30),
                });
                await connection.SendCallAsync(call);
                var result = await connection.ResultOfAsync(call.CallId);
                await TestNode.WaitAsync(() => connection.VerifiedResults.Any(item => item.Header.CallId.Equals(call.CallId)),
                    TimeSpan.FromSeconds(15), "the real Host result signature verifies");
                return (connection.VerifiedResults.Single(item => item.Header.CallId.Equals(call.CallId)).Header,
                    result.Payload.ToByteArray());
            }
            var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = Command(), Path = root, Name = "script-stage" };
            var registered = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(
                (await Invoke(RoutedMethod.RegisterNodeWorkspace, register, register.Meta.CommandId, owner)).Payload);
            Assert.Null(registered.Error);
            var workspace = registered.Value.Workspace.WorkspaceId;
            var body = Encoding.UTF8.GetBytes("REAL_STAGE_WORKER_PRIVATE_BODY_a7b1");
            var write = new FileServiceWriteFileRequest
            {
                Meta = Command(),
                ExpectedAbsent = true,
                Data = ByteString.CopyFrom(body),
                Path = new NodeFilePath { WorkspaceId = workspace.Clone(), Path = "approved-later.txt" },
            };
            var raw = write.ToByteArray();
            var (pending, pendingBytes) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, script);
            Assert.Equal(RoutedOutcome.RefusedByPolicy, pending.Outcome);
            Assert.Equal("approval_required", pending.Error?.Code);
            Assert.Empty(pendingBytes);
            var approvalId = pending.Error!.Details.State.Resource.Id;
            Assert.False(File.Exists(Path.Combine(root, write.Path.Path)));
            var stageName = ".arcforges-stage-" + Convert.ToHexStringLower(write.Meta.CommandId.Value.Span) + "-2";
            Assert.Equal(body, File.ReadAllBytes(Path.Combine(root, stageName)));
            AssertProducer(node.DataRoot, write, script, body);

            var read = new FileServiceReadFileRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                Offset = 0,
                Length = 128,
                Path = new NodeFilePath { WorkspaceId = workspace.Clone(), Path = stageName },
            };
            var protectedRead = FileServiceReadFileResponse.Parser.ParseFrom((await Invoke(RoutedMethod.ReadNodeFile, read, null, owner)).Payload);
            Assert.NotNull(protectedRead.Error);
            Assert.Null(protectedRead.Value);
            var list = new FileServiceListDirectoryRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = workspace.Clone(), Path = "" },
            };
            var listed = FileServiceListDirectoryResponse.Parser.ParseFrom((await Invoke(RoutedMethod.ListNodeDirectory, list, null, owner)).Payload);
            Assert.Null(listed.Error);
            Assert.DoesNotContain(listed.Value.Entries, entry => entry.Name == stageName);

            await node.StopNodeAsync();
            await TestNode.WaitAsync(() => node.LiveProcesses().Count == 0, TimeSpan.FromSeconds(30), "the exact owned Host and workers exit");
            foreach (var file in new[] { StorePaths.Database(node.DataRoot), StorePaths.Database(node.DataRoot) + "-wal",
                         StorePaths.Database(node.DataRoot) + "-shm", node.NodeLog })
                if (CloudLinkHostTests.ReadAllShared(file) is { } bytes) Assert.Equal(-1, bytes.AsSpan().IndexOf(body));
            await node.StartNodeAsync();
            connection = await center.Channel.ProvedAsync(2);
            var (replayed, replayBytes) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, script);
            Assert.Equal(RoutedOutcome.RefusedByPolicy, replayed.Outcome);
            Assert.Equal(pending.Error.ToByteArray(), replayed.Error.ToByteArray());
            Assert.Equal(pendingBytes, replayBytes);
            AssertProducer(node.DataRoot, write, script, body);
            await using var restartedHuman = await node.HumanChannelAsync();
            var denied = await restartedHuman.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
            {
                Meta = Command(),
                ApprovalId = approvalId.Clone(),
                Decision = ApprovalDecisionKind.Deny,
            }, cancellationToken: ct);
            Assert.Null(denied.Error);
            Assert.Equal(ApprovalState.Denied, denied.Value.Approval.State);
            Assert.False(File.Exists(Path.Combine(root, write.Path.Path)));
            Assert.Equal(body, File.ReadAllBytes(Path.Combine(root, stageName)));
            if (OperatingSystem.IsLinux())
            {
                // Linux approval effects use the same reopened private source FDs, rather than staging new copies.
                // Windows final target worker qualification is separate from its initial private-stage producer.
                async Task<byte[]> Approve(IMessage request, RequestMeta meta, RoutedMethod method)
                {
                    var (header, payload) = await Invoke(method, request, meta.CommandId, script);
                    Assert.Equal(RoutedOutcome.RefusedByPolicy, header.Outcome);
                    Assert.Equal("approval_required", header.Error?.Code);
                    Assert.Empty(payload);
                    var actualApproval = await restartedHuman.Approvals.GetApprovalAsync(new ApprovalServiceGetApprovalRequest
                    {
                        ApprovalId = header.Error!.Details.State.Resource.Id.Clone(),
                    }, cancellationToken: ct);
                    Assert.Null(actualApproval.Error);
                    var expires = ProtoTime.ToDateTimeOffset(actualApproval.Value.Approval.ExpiresAt)!.Value;
                    var remainingSeconds = (expires - DateTimeOffset.UtcNow).TotalSeconds;
                    TestContext.Current.TestOutputHelper?.WriteLine($"actual approval remaining seconds={remainingSeconds:F3}; execution native budget remains 10 seconds");
                    Assert.True(remainingSeconds > 300); // The real default approval TTL is not a routed signature lifetime.
                    var decision = await restartedHuman.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
                    {
                        Meta = Command(),
                        ApprovalId = header.Error!.Details.State.Resource.Id.Clone(),
                        Decision = ApprovalDecisionKind.Approve,
                    }, cancellationToken: ct);
                    Assert.Null(decision.Error);
                    var (replayHeader, replay) = await Invoke(method, request, meta.CommandId, script);
                    var error = request is FileServiceWriteFileRequest ? FileServiceWriteFileResponse.Parser.ParseFrom(replay).Error :
                        FileServiceEditFileResponse.Parser.ParseFrom(replay).Error;
                    TestContext.Current.TestOutputHelper?.WriteLine($"approved state={decision.Value.Approval.State}; outer={replayHeader.Error?.Code}; inner={error?.Code}/{error?.Details?.State?.Reason}");
                    Assert.Equal(ApprovalState.Executed, decision.Value.Approval.State);
                    Assert.Equal(RoutedOutcome.Executed, replayHeader.Outcome);
                    return replay;
                }
                var create = write.Clone();
                create.Meta = Command();
                create.Path.Path = "script-approved-created.txt";
                create.Data = ByteString.CopyFromUtf8("REAL_APPROVED_SOURCE_fd28 hello");
                var created = FileServiceWriteFileResponse.Parser.ParseFrom(await Approve(create, create.Meta, RoutedMethod.WriteNodeFile));
                Assert.Null(created.Error);
                Assert.Equal(create.Data.ToByteArray(), File.ReadAllBytes(Path.Combine(root, create.Path.Path)));
                var ownerBefore = AssertCreatedOwner(node.DataRoot, create, script, create.Data.ToByteArray());
                var update = new FileServiceWriteFileRequest
                {
                    Meta = Command(),
                    Path = create.Path.Clone(),
                    ExpectedSha256 = created.Value.Result.Sha256,
                    Data = ByteString.CopyFromUtf8("REAL_APPROVED_SOURCE_fd28 updated hello"),
                };
                var updated = FileServiceWriteFileResponse.Parser.ParseFrom(await Approve(update, update.Meta, RoutedMethod.WriteNodeFile));
                Assert.Null(updated.Error);
                Assert.Equal(update.Data.ToByteArray(), File.ReadAllBytes(Path.Combine(root, create.Path.Path)));
                Assert.Equal(ownerBefore, AssertCreatedOwner(node.DataRoot, create, script, update.Data.ToByteArray()));
                var edit = new FileServiceEditFileRequest
                {
                    Meta = Command(),
                    Path = create.Path.Clone(),
                    ExpectedSha256 = updated.Value.Result.Sha256,
                    OldText = "hello",
                    NewText = "world",
                    ExpectedOccurrences = 1,
                };
                var edited = FileServiceEditFileResponse.Parser.ParseFrom(await Approve(edit, edit.Meta, RoutedMethod.EditNodeFile));
                Assert.Null(edited.Error);
                Assert.Equal(1U, edited.Value.Result.Replacements);
                var final = Encoding.UTF8.GetBytes("REAL_APPROVED_SOURCE_fd28 updated world");
                Assert.Equal(final, File.ReadAllBytes(Path.Combine(root, create.Path.Path)));
                Assert.Equal(ownerBefore, AssertCreatedOwner(node.DataRoot, create, script, final));
                var readFinal = new FileServiceReadFileRequest
                {
                    Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                    Path = create.Path.Clone(),
                    Offset = 0,
                    Length = checked((uint)final.Length),
                };
                var readBack = FileServiceReadFileResponse.Parser.ParseFrom((await Invoke(RoutedMethod.ReadNodeFile, readFinal, null, script)).Payload);
                Assert.Null(readBack.Error);
                Assert.Equal(final, readBack.Value.Data.ToByteArray());
                var plan = new FileServicePlanRemovalRequest { Meta = Command(), WorkspacePath = create.Path.Clone() };
                var planned = FileServicePlanRemovalResponse.Parser.ParseFrom((await Invoke(
                    RoutedMethod.PlanNodeRemoval, plan, plan.Meta.CommandId, script)).Payload);
                Assert.Null(planned.Error);
                // SCRIPT provenance is durable but does not grant AGENT-only unattended owner verification or cleanup.
                Assert.False(Assert.Single(planned.Value.Plan.Items).OwnerVerified);
                Assert.True(planned.Value.Plan.RequiresApproval);
                Assert.False(planned.Value.Plan.QuarantineAvailable);
            }
            Assert.Empty(connection.UnverifiedResults);
        }
        finally
        {
            if (node.Descriptor() is { } descriptor && descriptor.ProcessIsAlive())
            {
                await using var cleanup = await node.HumanChannelAsync();
                Assert.Null((await cleanup.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() },
                    deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: CancellationToken.None)).Error);
                await node.StopNodeAsync();
            }
        }
    }

    private static void AssertProducer(string dataRoot, FileServiceWriteFileRequest write, CenterCaller caller, byte[] body)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(dataRoot),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT p.request_sha256, p.caller, p.active, p.object_count, p.reserved_bytes,
                   o.phase, o.native_identity, o.expected_size, o.expected_sha256, w.ended, w.process_id,
                   w.start_ticks, w.worker_nonce, w.producer_nonce, p.producer_nonce, s.phase, s.native_identity,
                   (SELECT count(*) FROM file_operation_journal WHERE command_id = p.command_id)
            FROM file_stage_production p JOIN file_stage_produced_object o ON o.command_id = p.command_id
            JOIN file_stage_worker w ON w.command_id = o.command_id AND w.slot = o.slot
            JOIN file_private_stage_object s ON s.command_id = o.command_id AND s.slot = o.slot
            WHERE p.command_id = $id;
            """;
        query.Parameters.AddWithValue("$id", write.Meta.CommandId.Value.ToByteArray());
        using var row = query.ExecuteReader();
        Assert.True(row.Read(), "The real public SCRIPT request must create the producer records.");
        Assert.Equal(SHA256.HashData(write.ToByteArray()), (byte[])row.GetValue(0));
        Assert.Equal(caller, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(1)));
        Assert.Equal(0, row.GetInt32(2));
        Assert.Equal(1, row.GetInt32(3));
        Assert.Equal(body.Length, row.GetInt64(4));
        Assert.Equal(2, row.GetInt32(5));
        Assert.Equal(OperatingSystem.IsLinux() ? 53 : 33, ((byte[])row.GetValue(6)).Length);
        Assert.Equal(body.Length, row.GetInt64(7));
        Assert.Equal(SHA256.HashData(body), (byte[])row.GetValue(8));
        Assert.Equal(1, row.GetInt32(9));
        Assert.True(row.GetInt32(10) > 1);
        Assert.True(row.GetInt64(11) > 0);
        Assert.Equal(16, ((byte[])row.GetValue(12)).Length);
        Assert.Equal((byte[])row.GetValue(14), (byte[])row.GetValue(13));
        Assert.Equal(3, row.GetInt32(15));
        Assert.Equal((byte[])row.GetValue(6), (byte[])row.GetValue(16));
        Assert.Equal(0, row.GetInt64(17)); // Stage reservation is not a fabricated target PREPARED.
        Assert.False(row.Read());
    }

    private static byte[] AssertCreatedOwner(string dataRoot, FileServiceWriteFileRequest create, CenterCaller caller, byte[] body)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(dataRoot),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT c.caller, c.object_identity, c.creation_marker, c.last_written_size, c.last_written_sha256,
                   j.phase, j.held, w.ended FROM file_creation_ownership c
            JOIN file_operation_journal j ON j.command_id = c.creation_command_id
            JOIN file_effect_worker w ON w.command_id = j.command_id
            WHERE c.creation_command_id = $id AND c.workspace_id = $workspace AND c.relative_path = $path;
            """;
        query.Parameters.AddWithValue("$id", create.Meta.CommandId.Value.ToByteArray());
        query.Parameters.AddWithValue("$workspace", create.Path.WorkspaceId.Value.ToByteArray());
        query.Parameters.AddWithValue("$path", create.Path.Path);
        using var row = query.ExecuteReader();
        Assert.True(row.Read(), "Only a real approved creation can generate its durable provenance.");
        Assert.Equal(caller, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(0)));
        var identity = (byte[])row.GetValue(1);
        Assert.Equal(53, identity.Length);
        Assert.Equal(32, ((byte[])row.GetValue(2)).Length);
        Assert.Equal(body.Length, row.GetInt64(3));
        Assert.Equal(SHA256.HashData(body), (byte[])row.GetValue(4));
        Assert.Equal(2, row.GetInt32(5));
        Assert.Equal(0, row.GetInt32(6));
        Assert.Equal(1, row.GetInt32(7));
        Assert.False(row.Read());
        return identity;
    }

    private static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
}
