// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>A previously pending create approval remains recoverable without reactivating the retired producer.</summary>
public sealed class RoutedApprovedFileCreateTests
{
    [Fact(Timeout = 120_000)]
    public async Task PendingCreateApprovalRetainsItsOriginalOwnerAndCannotStageOrCreate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "approved-create")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "new.txt" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFromUtf8("approved-created-file-49ca"),
        };
        var raw = request.ToByteArray();
        var commandId = request.Meta.CommandId.Value.ToByteArray();
        var stage = new PrivateStageSpec(2, Path.Combine(root, "previous-stage"), request.Data.Length, SHA256.HashData(request.Data.Span));

        var approvalId = await node.Runtime.Processor.ExecuteAsync(command =>
        {
            var transaction = command.Transaction;
            // Seed historical metadata only. Neither the native stage nor the target is opened or produced.
            Assert.Equal(PrivateStageReservationResult.Reserved, PrivateStageRegistry.Reserve(transaction,
                new FileStageBudget(), FileOperationKind.Write, commandId, workspace.Id,
                request.Meta.CorrelationId.Value.Span, actor, raw, [stage]));
            var approval = Approvals.Raise(command, new ApprovalCapture
            {
                Operation = "FileService.WriteFile",
                MatrixOperation = PermissionMatrix.FileWrite,
                Summary = "Retained create approval fixture",
                Risk = RiskClass.High,
                Requester = new ActorRef { Origin = Origin.Remote, CenterCaller = actor, RemoteCommandId = request.Meta.CommandId.Clone() },
                CommandId = commandId,
                Request = [1, .. commandId],
                RequestDigest = SHA256.HashData(raw),
                TargetKind = "workspace",
                TargetId = workspace.Id,
            }, TimeSpan.FromHours(1));
            Assert.True(approval.Created);
            Assert.Null(approval.Error);
            var id = approval.Approval!.Id;
            var platform = OperatingSystem.IsWindows() ? 1 : 2;
            var identity = new byte[platform == 1 ? 33 : 53];
            identity[0] = 1;
            Assert.Equal(1, transaction.Execute("""
                UPDATE file_private_stage_object
                SET phase = 2, identity_platform = $platform, native_identity = $identity, parent_identity = $identity
                WHERE command_id = $command AND slot = 2 AND phase = 1;
                """, ("$command", commandId), ("$platform", platform), ("$identity", identity)));
            Assert.Equal(1, transaction.Execute("""
                UPDATE file_private_stage_object SET phase = 3 WHERE command_id = $command AND slot = 2 AND phase = 2;
                """, ("$command", commandId)));
            Assert.Equal(1, transaction.Execute("""
                INSERT INTO file_private_approval_binding
                    (command_id, approval_id, identity_platform, root_identity, parent_identity)
                VALUES ($command, $approval, $platform, $identity, $identity);
                """, ("$command", commandId), ("$approval", id), ("$platform", platform), ("$identity", identity)));
            return id;
        }, CommitDurability.Full).WaitAsync(ct);

        var handler = calls.Dispatcher.FileHandlerForTests!;
        bool reachedCreate = false;
        void RefuseUnexpectedCreate()
        {
            reachedCreate = true;
            throw new InvalidOperationException("The draining route must not enter the native create path.");
        }

        handler.BeforeCreateForTests = RefuseUnexpectedCreate;
        handler.AfterCreateForTests = RefuseUnexpectedCreate;
        try
        {
            await RequirePendingAsync(calls, actor, request, raw, approvalId, ct);
            var foreign = actor.Clone();
            foreign.AccountId = CommandIds.New();
            var denied = await calls.CallAsync(foreign, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId,
                cancellationToken: ct);
            Assert.Equal(RoutedOutcome.Executed, denied.Answer!.Outcome);
            var deniedResponse = FileServiceWriteFileResponse.Parser.ParseFrom(denied.Answer.Response);
            Assert.Equal("command_id_reused", deniedResponse.Error.Code);
            Assert.Null(deniedResponse.Error.Details?.State?.Resource?.Id);
            Assert.False(reachedCreate);
        }
        finally
        {
            handler.BeforeCreateForTests = null;
            handler.AfterCreateForTests = null;
        }

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        await RequirePendingAsync(new RoutedCalls(node), actor, request, raw, approvalId, ct);

        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(ApprovalState.Pending, Approvals.Get(reader, approvalId)!.State);
            Assert.Equal((1, (long)request.Data.Length), PrivateStageRegistry.Usage(reader));
            Assert.True(PrivateStageRegistry.HasWorkspaceHold(reader, workspace.Id));
            Assert.Null(FileMutationJournal.GetForCaller(reader, commandId, actor));
            Assert.Null(reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", commandId)));
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM approval;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_stage_worker;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_effect_worker;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_creation_ownership;"));
            return 0;
        });
        Assert.Empty(Directory.EnumerateFileSystemEntries(root));
    }

    private static async Task RequirePendingAsync(RoutedCalls calls, CenterCaller caller, FileServiceWriteFileRequest request,
        byte[] raw, byte[] approvalId, CancellationToken cancellationToken)
    {
        var result = await calls.CallAsync(caller, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId,
            cancellationToken: cancellationToken);
        var answer = Assert.IsType<RoutedAnswer>(result.Answer);
        Assert.Equal((RoutedOutcome.RefusedByPolicy, "approval_required", EffectCertainty.DidNotHappen, RetryMode.Reconcile),
            (answer.Outcome, answer.Error!.Code, answer.Error.Effect, answer.Error.Retry.Mode));
        Assert.Equal(request.Meta.CorrelationId, answer.Error.CorrelationId);
        Assert.Equal(approvalId, answer.Error.Details.State.Resource.Id.Value.ToByteArray());
    }
}
