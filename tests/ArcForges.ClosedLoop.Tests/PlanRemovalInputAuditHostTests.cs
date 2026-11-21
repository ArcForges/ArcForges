// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Actual ownership input observation and retained audit through SQLite and an offline routed caller.</summary>
[Trait("loop", "local")]
public sealed class PlanRemovalInputAuditHostTests
{
    // The signed installed-host observation and old fresh planner remain executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    [Fact(Timeout = 180_000)]
    public async Task RetainedPlanReplaysTheOriginalOwnershipInputObservation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var history = new LegacyFileHostHistory();
        var workspace = RetainedHostWorkspace.Seed(history, "host-plan-input-root", ct);
        var owner = history.Caller(Origin.Agent);
        const string name = "input.txt";
        var path = Path.Combine(workspace.RootPath, name);
        var body = "aot-host-plan-input-private-body-719c"u8.ToArray();
        var request = new FileServicePlanRemovalRequest
        {
            Meta = LegacyFileHostHistory.Command(),
            WorkspacePath = LegacyFileHostHistory.FilePath(workspace, name),
        };
        var raw = request.ToByteArray();
        var requestDigest = SHA256.HashData(raw);
        var command = request.Meta.CommandId.Value.ToByteArray();

        byte[] marker;
        byte[] receipt;
        using (var root = WorkspacePath.OpenRoot(workspace.RootPath))
        {
            RegisteredWorkspaces.RootIdentity objectIdentity;
            using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                file.Write(body);
                file.Flush(flushToDisk: true);
                marker = Assert.IsType<byte[]>(WorkspaceCreationMarker.TryWriteNew(file.SafeFileHandle));
                objectIdentity = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file.SafeFileHandle), directory: false);
            }

            var rootIdentity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            receipt = history.Store.Write(tx =>
            {
                SeedSyntheticProvenance(tx, workspace, owner, rootIdentity, objectIdentity, marker, body);
                var manager = new RegisteredWorkspaces(history.Store);
                using var use = manager.OpenForQuery(tx, workspace.Id, beforeUse: null, ct);
                using var audit = new WorkspaceOwnershipInputAudit();
                var snapshot = WorkspaceRemovalPlan.Capture(use.Root, name, ct);
                Assert.True(FileCreationOwnership.IsVerifiedAgent(tx, owner, workspace.Id, use.Root, Assert.Single(snapshot.Entries), ct, audit));
                var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = owner, RemoteCommandId = request.Meta.CommandId };
                var plan = FileRemovalPlans.PrepareWorkspace(tx, command, requestDigest, owner, actor, request.WorkspacePath,
                    workspace.RootPath, snapshot, tx.NowMicroseconds, new HashSet<string>(StringComparer.Ordinal) { name },
                    quarantineAvailable: true);
                Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, command,
                    "arcforges.node.v1.FileService/PlanRemoval", requestDigest, Origin.Remote).Status);
                tx.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($id, $caller);",
                    ("$id", command), ("$caller", owner.ToByteArray()));
                FileRemovalPlans.RecordWorkspace(tx, plan);
                var observed = audit.Snapshot();
                var response = new FileServicePlanRemovalResponse
                {
                    Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
                    Value = new FileServicePlanRemovalValue { Plan = plan.Plan },
                    Audit = observed,
                };
                CommandDeduplication.Complete(tx, command, response.ToByteArray());
                AuditLog.AppendFileWorkspace(tx, actor, "cleanup.plan FileService.PlanRemoval", workspace.Id,
                    null, name, PermissionDecision.Allow, "planned", observed);
                return response.ToByteArray();
            }, CommitDurability.Full);
        }

        async Task<byte[]> RouteAsync(FileServicePlanRemovalRequest current, CenterCaller caller)
        {
            var answer = await history.RouteAsync(RoutedMethod.PlanNodeRemoval, caller, current, current.Meta.CommandId, ct);
            Assert.Equal(RoutedOutcome.Executed, answer?.Outcome);
            return Assert.IsType<ByteString>(answer!.Response).ToByteArray();
        }

        var first = await RouteAsync(request, owner);
        Assert.Equal(receipt, first);
        Assert.Equal(-1, first.AsSpan().IndexOf(body));
        Assert.Equal(-1, first.AsSpan().IndexOf(marker));
        var response = FileServicePlanRemovalResponse.Parser.ParseFrom(first);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Null(response.Error);
        Assert.Equal(request.Meta.CorrelationId, response.Meta.CorrelationId);
        Assert.True(Assert.Single(response.Value.Plan.Items).OwnerVerified);
        var observation = Assert.Single(response.Audit.Observations);
        Assert.Equal(FileAuditKind.InputBytes, observation.Kind);
        Assert.Equal((ulong)body.Length, observation.SizeBytes);
        Assert.Equal((ulong)body.Length, observation.DigestInputBytes);
        Assert.False(observation.HasItemCount);
        Assert.Equal(SHA256.HashData(body), observation.Sha256.ToByteArray());
        AssertStored(history.Store, command, requestDigest, first, body);

        var changedCaller = owner.Clone();
        changedCaller.LocalSessionId = CommandIds.New();
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(await RouteAsync(request, changedCaller)).Error.Code);
        var changedRequest = request.Clone();
        changedRequest.Meta.CorrelationId = CommandIds.New();
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(await RouteAsync(changedRequest, owner)).Error.Code);

        var updated = "changed-after-signed-plan"u8.ToArray();
        File.WriteAllBytes(path, updated);
        Assert.Equal(first, await RouteAsync(request, owner));
        await history.ReopenAsync();
        Assert.Equal(first, await RouteAsync(request, owner));
        AssertStored(history.Store, command, requestDigest, first, body);
        var read = await RetainedHostWorkspace.ReadAsync(history, workspace, owner, name, ct);
        Assert.Null(read.Error);
        Assert.Equal(updated, read.Value.Data.ToByteArray());

        var fresh = request.Clone();
        fresh.Meta = LegacyFileHostHistory.Command();
        var refused = FileServicePlanRemovalResponse.Parser.ParseFrom(await RouteAsync(fresh, owner));
        Assert.Null(refused.Value);
        Assert.Equal(("internal", "legacy_removal_plan_outcome_unavailable", EffectCertainty.Unknown, RetryMode.Never),
            (refused.Error.Code, refused.Error.Details.State.Reason, refused.Error.Effect, refused.Error.Retry.Mode));
        Assert.Equal(1L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(updated, File.ReadAllBytes(path));
        RetainedHostWorkspace.AssertPrivateBytesAbsent(history, body);
        foreach (var log in Directory.EnumerateFiles(Path.Combine(history.Root, "data", "logs", "node")))
        {
            if (CloudLinkHostTests.ReadAllShared(log) is { } bytes)
                Assert.Equal(-1, bytes.AsSpan().IndexOf(marker));
        }
    }

    private static void SeedSyntheticProvenance(StoreTransaction tx, RegisteredWorkspace workspace, CenterCaller caller,
        RegisteredWorkspaces.RootIdentity root, RegisteredWorkspaces.RootIdentity file, byte[] marker, byte[] body)
    {
        var key = Assert.IsType<byte[]>(FileCreationOwnership.StableKey(file.Platform, file.Bytes));
        tx.Execute("INSERT INTO file_ownership_object_generation (object_platform, object_key, generation) VALUES ($p, $key, 0);",
            ("$p", file.Platform), ("$key", key));
        tx.Execute("""
            INSERT INTO file_creation_ownership
              (workspace_id, relative_path, caller, creation_command_id, creation_request_sha256, root_platform, root_identity,
               object_platform, object_identity, object_key, creation_marker, last_written_size, last_written_sha256,
               global_generation, object_generation, recorded_at)
            VALUES ($ws, 'input.txt', $caller, $command, $request, $platform, $root, $platform, $object, $key,
                    $marker, $size, $hash, 0, 0, $now);
            """, ("$ws", workspace.Id), ("$caller", caller.ToByteArray()), ("$command", CommandIds.New().Value.ToByteArray()),
            ("$request", SHA256.HashData("synthetic-owner-provenance"u8)), ("$platform", file.Platform), ("$root", root.Bytes),
            ("$object", file.Bytes), ("$key", key), ("$marker", marker), ("$size", body.LongLength), ("$hash", SHA256.HashData(body)),
            ("$now", tx.NowMicroseconds));
    }

    private static void AssertStored(NodeStore store, byte[] command, byte[] rawDigest, byte[] response, byte[] body) => store.Read(reader =>
    {
        using var query = reader.CreateCommand("""
            SELECT d.payload_digest, d.outcome, o.kind, o.size_bytes, o.digest_input_bytes, o.item_count, o.sha256
            FROM command_dedup d JOIN audit_log a ON a.remote_command_id = d.command_id
            JOIN file_workspace_audit_observation o ON o.audit_seq = a.seq
            WHERE d.command_id = $id AND a.operation = 'cleanup.plan FileService.PlanRemoval' AND a.outcome_summary = 'planned';
            """);
        query.Parameters.AddWithValue("$id", command);
        using var row = query.ExecuteReader();
        Assert.True(row.Read());
        Assert.Equal(rawDigest, (byte[])row.GetValue(0));
        Assert.Equal(response, (byte[])row.GetValue(1));
        Assert.Equal((int)FileAuditKind.InputBytes, row.GetInt32(2));
        Assert.Equal((long)body.Length, row.GetInt64(3));
        Assert.Equal((long)body.Length, row.GetInt64(4));
        Assert.True(row.IsDBNull(5));
        Assert.Equal(SHA256.HashData(body), (byte[])row.GetValue(6));
        Assert.False(row.Read());
        return 0;
    });
}
