// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real SQLite capacity and command binding, with metadata-only synthetic reservations and no staged files.</summary>
public sealed class PrivateStageRegistryCapacityTests
{
    [Fact(Timeout = 120_000)]
    public async Task DurableAndInProcessMutationsShareTheSixtyFourSlotBound()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "stage-capacity")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var budget = new FileStageBudget();
        (FileServiceWriteFileRequest Request, PrivateStageSpec Spec) Make(int index)
        {
            var request = new FileServiceWriteFileRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target-" + index },
                ExpectedAbsent = true,
                Data = ByteString.Empty,
            };
            return (request, new PrivateStageSpec(2, Path.Combine(root, "stage-" + index), 0, SHA256.HashData(ReadOnlySpan<byte>.Empty)));
        }
        PrivateStageReservationResult Reserve((FileServiceWriteFileRequest Request, PrivateStageSpec Spec) item) =>
            node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t, budget, FileOperationKind.Write,
                item.Request.Meta.CommandId.Value.Span, workspace.Id, item.Request.Meta.CorrelationId.Value.Span,
                caller, item.Request.ToByteArray(), [item.Spec]), CommitDurability.Full);

        for (var i = 0; i < 63; i++) Assert.Equal(PrivateStageReservationResult.Reserved, Reserve(Make(i)));
        using (var transient = budget.TryReserve(0, 0))
        {
            Assert.NotNull(transient);
            Assert.Equal(PrivateStageReservationResult.Capacity, Reserve(Make(63)));
        }
        var final = Make(63);
        Assert.Equal(PrivateStageReservationResult.Reserved, Reserve(final));
        Assert.Equal(PrivateStageReservationResult.Capacity, Reserve(Make(64)));
        Assert.Equal((64, 0L), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        // Compatible earlier direct writers cannot bypass the active limit, including by reactivating retained metadata.
        var direct = Make(100);
        var directId = direct.Request.Meta.CommandId.Value.ToByteArray();
        var directFailure = Assert.Throws<SqliteException>(() => node.Runtime.Store.Write(t =>
        {
            t.Execute("""
                INSERT INTO command_dedup (command_id, method, payload_digest, origin, created_at, expires_at)
                VALUES ($id, 'arcforges.node.v1.FileService/WriteFile', zeroblob(32), 4, 0, 1);
                """, ("$id", directId));
            t.Execute("""
                INSERT INTO file_private_stage_reservation
                  (command_id, workspace_id, kind, correlation_id, relative_path, expected_absent, request_sha256,
                   caller, reserved_bytes, created_at)
                VALUES ($id, $workspace, 1, $correlation, 'direct-target', 1, zeroblob(32), x'01', 0, 0);
                """, ("$id", directId), ("$workspace", workspace.Id),
                ("$correlation", direct.Request.Meta.CorrelationId.Value.ToByteArray()));
        }, CommitDurability.Full));
        Assert.Equal(19, directFailure.SqliteErrorCode);
        Assert.Null(node.Runtime.Store.Read(r => r.Scalar("SELECT 1 FROM command_dedup WHERE command_id = $id;", ("$id", directId))));
        var retainedId = final.Request.Meta.CommandId.Value.ToByteArray();
        node.Runtime.Store.Write(t => t.Execute("UPDATE file_private_stage_reservation SET active = 0 WHERE command_id = $id;",
            ("$id", retainedId)), CommitDurability.Full); // Test-owned metadata only; actual HUMAN acknowledgment is covered separately.
        Assert.Equal(PrivateStageReservationResult.Reserved, Reserve(Make(65)));
        var reactivation = Assert.Throws<SqliteException>(() => node.Runtime.Store.Write(t => t.Execute(
            "UPDATE file_private_stage_reservation SET active = 1 WHERE command_id = $id;", ("$id", retainedId)), CommitDurability.Full));
        Assert.Equal(19, reactivation.SqliteErrorCode);
        Assert.Equal((64, 0L), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Null(budget.TryReserve(0, 0, durableMutations: 64));
        Assert.Null(budget.TryReserve(1, 0, durableBytes: FileStageBudget.MaximumBytes));
        Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(() =>
            new RegisteredWorkspaces(node.Runtime.Store).UnregisterFromVerifiedHuman(workspace.Id, ct)).Reason);
        var failure = Assert.Throws<SqliteException>(() => node.Runtime.Store.Write(t => t.Execute(
            "UPDATE workspace SET removed_at = $now WHERE workspace_id = $id;", ("$now", t.NowMicroseconds), ("$id", workspace.Id))));
        Assert.Equal(19, failure.SqliteErrorCode); // Compatible direct writer cannot bypass the hold.
        Assert.Equal(65L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_reservation;")));
    }

    [Fact(Timeout = 120_000)]
    public async Task MissingMutationCorrelationIsInvalidAndTheVerifiedCallIdBindsItsRefusal()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "stage-correlation")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFromUtf8("body"),
        };
        var raw = request.ToByteArray();
        Assert.False(NodeShapes.IsValid(request)); // Actual published 450.1 requires correlation inside a present RequestMeta.
        var withCorrelation = request.Clone();
        withCorrelation.Meta.CorrelationId = CommandIds.New();
        Assert.True(NodeShapes.IsValid(withCorrelation));
        var call = await calls.CallAsync(caller, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, call.Answer!.Outcome);
        var response = FileServiceWriteFileResponse.Parser.ParseFrom(call.Answer.Response);
        Assert.Equal("invalid_argument", response.Error.Code);
        Assert.Equal(calls.LastCallId, response.Meta.CorrelationId);
        Assert.Equal(calls.LastCallId, response.Error.CorrelationId);
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_reservation;")));
        Assert.False(File.Exists(Path.Combine(root, "target")));
    }

    [Fact(Timeout = 120_000)]
    public async Task DurableBytesAreBoundedAndTheRequestBytesAndKindCannotBeSwapped()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "stage-byte-capacity")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var budget = new FileStageBudget();
        var expectedOriginal = SHA256.HashData("original"u8);
        (FileServiceEditFileRequest Request, PrivateStageSpec[] Stages) Make(int index, long bytes)
        {
            var request = new FileServiceEditFileRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target-" + index },
                ExpectedSha256 = ByteString.CopyFrom(expectedOriginal),
                OldText = "old",
                NewText = "new",
                ExpectedOccurrences = 1,
            };
            return (request,
            [
                new PrivateStageSpec(1, Path.Combine(root, "before-" + index), bytes, expectedOriginal),
                new PrivateStageSpec(2, Path.Combine(root, "after-" + index), bytes, SHA256.HashData("intended"u8)),
            ]);
        }
        PrivateStageReservationResult Reserve((FileServiceEditFileRequest Request, PrivateStageSpec[] Stages) item) =>
            node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t, budget, FileOperationKind.Edit,
                item.Request.Meta.CommandId.Value.Span, workspace.Id, item.Request.Meta.CorrelationId.Value.Span,
                caller, item.Request.ToByteArray(), item.Stages), CommitDurability.Full);

        for (var i = 0; i < 32; i++) Assert.Equal(PrivateStageReservationResult.Reserved, Reserve(Make(i, FileStageBudget.MaximumFileBytes)));
        Assert.Equal((32, FileStageBudget.MaximumBytes), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        var overflow = Make(32, 1);
        Assert.Equal(PrivateStageReservationResult.Capacity, Reserve(overflow));
        // Metadata-only capacity fixture: a compatible writer releases active flags, not retained byte accounting.
        node.Runtime.Store.Write(t => t.Execute("UPDATE file_private_stage_reservation SET active = 0;"), CommitDurability.Full);
        Assert.Equal((0, FileStageBudget.MaximumBytes), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Equal(PrivateStageReservationResult.Capacity, Reserve(overflow));
        Assert.Null(node.Runtime.Store.Read(r => r.Scalar("SELECT 1 FROM command_dedup WHERE command_id = $id;",
            ("$id", overflow.Request.Meta.CommandId.Value.ToByteArray()))));
        var bad = Make(33, 1);
        bad.Stages[0] = bad.Stages[0] with { ExpectedSha256 = new byte[32] };
        Assert.Throws<ArgumentException>(() => Reserve(bad)); // Declared preimage must match the transmitted precondition.
    }
}
