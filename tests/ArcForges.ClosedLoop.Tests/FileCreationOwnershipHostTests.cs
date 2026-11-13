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

/// <summary>
/// Actual Host, signed dispatcher, native exclusive create/worker, SQLite and restart. Only the center peer is
/// synthetic. No ownership/journal rows are seeded; evidence must originate in the successful public operation.
/// </summary>
[Trait("loop", "local")]
public sealed class FileCreationOwnershipHostTests
{
    [Fact(Timeout = 180_000)]
    public async Task ExplicitlyAllowedCallersCreateRealEvidenceAndTheExactAgentRetainsItAcrossUpdatesAndRestart()
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
            var agent = owner.Clone();
            agent.LocalOrigin = Origin.Agent;
            agent.LocalSessionId = CommandIds.New();
            var script = owner.Clone();
            script.LocalOrigin = Origin.Script;
            script.LocalSessionId = CommandIds.New();
            var root = Directory.CreateDirectory(Path.Combine(node.Root, "actual-created-workspace")).FullName;
            Directory.CreateDirectory(Path.Combine(root, "nested"));
            async Task<(RoutedOutcome Outcome, byte[] Payload)> Invoke(RoutedMethod method, IMessage request, Id id, CenterCaller actor)
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
                    TimeSpan.FromSeconds(15), "the actual creation/result signature verifies");
                return (connection.VerifiedResults.Single(item => item.Header.CallId.Equals(call.CallId)).Header.Outcome,
                    result.Payload.ToByteArray());
            }
            var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = Command(), Path = root, Name = "created-owner" };
            var (_, registration) = await Invoke(RoutedMethod.RegisterNodeWorkspace, register, register.Meta.CommandId, owner);
            var registered = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(registration);
            Assert.Null(registered.Error);
            var workspace = registered.Value.Workspace.WorkspaceId;
            FileServiceWriteFileRequest Create(string path, string body) => new()
            {
                Meta = Command(),
                Path = new NodeFilePath { WorkspaceId = workspace.Clone(), Path = path },
                ExpectedAbsent = true,
                Data = ByteString.CopyFromUtf8(body),
            };
            async Task<(byte[] Bytes, FileServiceWriteFileResponse Response)> Write(CenterCaller actor, FileServiceWriteFileRequest request)
            {
                var (outcome, bytes) = await Invoke(RoutedMethod.WriteNodeFile, request, request.Meta.CommandId, actor);
                var response = FileServiceWriteFileResponse.Parser.ParseFrom(bytes);
                if (response.Error is null) Assert.Equal(RoutedOutcome.Executed, outcome);
                return (bytes, response);
            }
            var denied = Create("agent-denied.txt", "no-policy-no-object");
            var (deniedOutcome, _) = await Invoke(RoutedMethod.WriteNodeFile, denied, denied.Meta.CommandId, agent);
            Assert.Equal(RoutedOutcome.RefusedByPolicy, deniedOutcome);
            Assert.False(File.Exists(Path.Combine(root, denied.Path.Path)));

            // The actual local HUMAN grants only these origins file.write. SCRIPT's default approval path is
            // tested separately; this case deliberately exercises its explicit ALLOW, not an implied approval.
            var current = await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Command() }, cancellationToken: ct);
            Assert.Null(current.Error);
            var policy = current.Value.Document.Clone();
            foreach (var origin in new[] { Origin.Agent, Origin.Script })
                policy.Permissions.Add(new PermissionOverride { Operation = "file.write", Origin = origin, Decision = PermissionDecision.Allow });
            var policyMeta = Command();
            policyMeta.ExpectedRev = current.Value.Revision.Revision;
            var changed = await human.Policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest
            {
                Meta = policyMeta,
                Document = policy,
                Comment = "owned native creation fixture",
            }, cancellationToken: ct);
            Assert.Null(changed.Error);

            const string first = "REAL_CREATED_PRIVATE_BODY_c087 hello";
            const string second = "REAL_CREATED_PRIVATE_BODY_c087 updated hello";
            const string third = "REAL_CREATED_PRIVATE_BODY_c087 updated world";
            var request = Create("nested/agent.txt", first);
            var (createdBytes, created) = await Write(agent, request);
            Assert.Null(created.Error);
            Assert.Equal(first, File.ReadAllText(Path.Combine(root, request.Path.Path)));
            Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(first)), created.Value.Result.Sha256.ToByteArray());
            var original = Record(node.DataRoot, workspace, request.Path.Path, request, agent, first);
            Assert.Equal(32, original.Marker.Length);
            if (OperatingSystem.IsLinux()) Assert.True(original.EndedWorker);
            foreach (var (actor, path) in new[] { (owner, "human.txt"), (script, "script.txt") })
            {
                var create = Create(path, "caller-created-" + path);
                Assert.Null((await Write(actor, create)).Response.Error);
                _ = Record(node.DataRoot, workspace, path, create, actor, "caller-created-" + path);
            }
            async Task<FileRemovalPlan> Plan(CenterCaller actor, bool expectedOwner)
            {
                var plan = new FileServicePlanRemovalRequest
                {
                    Meta = Command(),
                    WorkspacePath = request.Path.Clone(),
                };
                var (_, bytes) = await Invoke(RoutedMethod.PlanNodeRemoval, plan, plan.Meta.CommandId, actor);
                var response = FileServicePlanRemovalResponse.Parser.ParseFrom(bytes);
                Assert.Null(response.Error);
                Assert.Equal(expectedOwner, Assert.Single(response.Value.Plan.Items).OwnerVerified);
                // Verified provenance is not proof of the separate strict namespace/cleanup capability.
                Assert.True(response.Value.Plan.RequiresApproval);
                Assert.False(response.Value.Plan.QuarantineAvailable);
                return response.Value.Plan;
            }
            _ = await Plan(agent, expectedOwner: true);
            var foreign = agent.Clone();
            foreign.LocalSessionId = CommandIds.New();
            _ = await Plan(foreign, expectedOwner: false);
            _ = await Plan(owner, expectedOwner: false);

            var update = new FileServiceWriteFileRequest
            {
                Meta = Command(),
                Path = request.Path.Clone(),
                ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(Encoding.UTF8.GetBytes(first))),
                Data = ByteString.CopyFromUtf8(second),
            };
            Assert.Null((await Write(agent, update)).Response.Error);
            var advanced = Record(node.DataRoot, workspace, request.Path.Path, request, agent, second, compareCreationReceipt: false);
            Assert.Equal(original.Marker, advanced.Marker);
            Assert.Equal(original.Identity, advanced.Identity);
            var edit = new FileServiceEditFileRequest
            {
                Meta = Command(),
                Path = request.Path.Clone(),
                ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(Encoding.UTF8.GetBytes(second))),
                OldText = "hello",
                NewText = "world",
                ExpectedOccurrences = 1,
            };
            var (_, editBytes) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId, agent);
            var edited = FileServiceEditFileResponse.Parser.ParseFrom(editBytes);
            Assert.Null(edited.Error);
            Assert.Equal(1U, edited.Value.Result.Replacements);
            var afterEdit = Record(node.DataRoot, workspace, request.Path.Path, request, agent, third, compareCreationReceipt: false);
            Assert.Equal(original.Marker, afterEdit.Marker);
            Assert.Equal(original.Identity, afterEdit.Identity);
            _ = await Plan(agent, expectedOwner: true);
            var collision = Create(request.Path.Path, "rival-must-not-overwrite");
            var (_, collisionResult) = await Write(agent, collision);
            Assert.Equal("expected_absent_conflict", collisionResult.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, collisionResult.Error.Effect);
            Assert.Equal(third, File.ReadAllText(Path.Combine(root, request.Path.Path)));
            Assert.Equal(original.Marker, Record(node.DataRoot, workspace, request.Path.Path, request, agent, third,
                compareCreationReceipt: false).Marker);

            await node.StopNodeAsync();
            await TestNode.WaitAsync(() => node.LiveProcesses().Count == 0, TimeSpan.FromSeconds(30), "the exact owned node exits");
            await node.StartNodeAsync();
            connection = await center.Channel.ProvedAsync(2);
            var (replayBytes, _) = await Write(agent, request);
            Assert.Equal(createdBytes, replayBytes);
            Assert.Equal(third, File.ReadAllText(Path.Combine(root, request.Path.Path)));
            _ = await Plan(agent, expectedOwner: true);
            Assert.Equal(original.Marker, Record(node.DataRoot, workspace, request.Path.Path, request, agent, third,
                compareCreationReceipt: false).Marker);
            // Exercise the new execution route through the real Host. This HUMAN uses its actual local policy
            // ALLOW and its own plan, but neither that authority nor real creation provenance supplies a strict
            // namespace backend. The committed refusal is a real no-effect result, never a cleanup success.
            var humanPlan = await Plan(owner, expectedOwner: false);
            var execution = new FileServiceExecuteRemovalRequest
            {
                Meta = Command(),
                PlanId = humanPlan.PlanId.Clone(),
                PlanDigest = humanPlan.Digest,
            };
            var namesBefore = Directory.GetFileSystemEntries(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToArray();
            var (executionOutcome, executionBytes) = await Invoke(RoutedMethod.ExecuteNodeRemoval, execution, execution.Meta.CommandId, owner);
            Assert.Equal(RoutedOutcome.Executed, executionOutcome);
            var refusedExecution = FileServiceExecuteRemovalResponse.Parser.ParseFrom(executionBytes);
            Assert.Equal("enforcement_unavailable", refusedExecution.Error.Code);
            Assert.Equal("strict_cleanup_guard_unavailable", refusedExecution.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, refusedExecution.Error.Effect);
            var (_, executionReplay) = await Invoke(RoutedMethod.ExecuteNodeRemoval, execution, execution.Meta.CommandId, owner);
            Assert.Equal(executionBytes, executionReplay);
            Assert.Equal(namesBefore, Directory.GetFileSystemEntries(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToArray());
            Assert.Equal(third, File.ReadAllText(Path.Combine(root, request.Path.Path)));
            Assert.Equal(original.Marker, Record(node.DataRoot, workspace, request.Path.Path, request, agent, third,
                compareCreationReceipt: false).Marker);
            Assert.Empty(connection.UnverifiedResults);
            foreach (var file in new[] { StorePaths.Database(node.DataRoot), StorePaths.Database(node.DataRoot) + "-wal", node.NodeLog })
            {
                if (CloudLinkHostTests.ReadAllShared(file) is not { } bytes) continue;
                foreach (var text in new[] { first, second, third }) Assert.Equal(-1, bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(text)));
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

    private static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };

    private static (byte[] Marker, byte[] Identity, bool EndedWorker) Record(string dataRoot, Id workspace, string path,
        FileServiceWriteFileRequest create, CenterCaller actor, string content, bool compareCreationReceipt = true)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = StorePaths.Database(dataRoot), Mode = SqliteOpenMode.ReadOnly, Pooling = false };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var sql = connection.CreateCommand();
        sql.CommandText = """
            SELECT c.creation_marker, c.object_identity, c.caller, c.creation_command_id, c.last_written_size,
                   c.last_written_sha256, j.phase, j.held, j.expected_absent, j.request_sha256, d.outcome,
                   w.ended, c.root_identity
            FROM file_creation_ownership c
            JOIN file_ownership_generation g ON g.singleton = 1 AND g.generation = c.global_generation
            JOIN file_ownership_object_generation o ON o.object_platform = c.object_platform AND o.object_key = c.object_key
                                                        AND o.generation = c.object_generation
            JOIN file_operation_journal j ON j.command_id = c.creation_command_id
            JOIN command_dedup d ON d.command_id = j.command_id
            LEFT JOIN file_effect_worker w ON w.command_id = j.command_id
            WHERE c.workspace_id = $workspace AND c.relative_path = $path;
            """;
        sql.Parameters.AddWithValue("$workspace", workspace.Value.ToByteArray());
        sql.Parameters.AddWithValue("$path", path);
        using var row = sql.ExecuteReader();
        Assert.True(row.Read(), "Only a real completed creation may generate durable ownership.");
        var marker = (byte[])row.GetValue(0);
        var identity = (byte[])row.GetValue(1);
        Assert.Equal(actor, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2)));
        Assert.Equal(create.Meta.CommandId.Value.ToByteArray(), (byte[])row.GetValue(3));
        Assert.Equal(Encoding.UTF8.GetByteCount(content), row.GetInt64(4));
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(content)), (byte[])row.GetValue(5));
        Assert.Equal(2L, row.GetInt64(6));
        Assert.Equal(0L, row.GetInt64(7));
        Assert.Equal(1L, row.GetInt64(8));
        Assert.Equal(SHA256.HashData(create.ToByteArray()), (byte[])row.GetValue(9));
        var receipt = FileServiceWriteFileResponse.Parser.ParseFrom((byte[])row.GetValue(10));
        Assert.Null(receipt.Error);
        if (compareCreationReceipt)
            Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(content)), receipt.Value.Result.Sha256.ToByteArray());
        Assert.Equal(OperatingSystem.IsLinux() ? 53 : 33, identity.Length);
        Assert.Equal(OperatingSystem.IsLinux() ? 53 : 33, ((byte[])row.GetValue(12)).Length);
        var ended = !row.IsDBNull(11) && row.GetInt64(11) == 1;
        Assert.False(row.Read());
        return (marker, identity, ended);
    }
}
