// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Retained file approvals reconcile from real SQLite without producing or applying a legacy file effect.</summary>
public sealed class FileApprovedExecutionTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(false, "completed")]
    [InlineData(true, "completed")]
    [InlineData(false, "target_changed")]
    [InlineData(false, "policy_denied")]
    [InlineData(false, "interrupted")]
    [InlineData(false, "pending")]
    public async Task RestartReconcilesOnlyTheOriginalSettledFileApproval(bool edit, string history)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = InProcessNode.Create();
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "approved-local-rpc")).FullName;
        var target = Path.Combine(directory, "target");
        // The live file is a sentinel, independent of the old result recorded in the fixture.
        byte[] preimage = "alpha-private-cb89 alpha-private-cb89"u8.ToArray();
        byte[] intended = "beta-private-cb89 beta-private-cb89"u8.ToArray();
        File.WriteAllBytes(target, preimage);
        var seeded = await SeedRetainedApprovalAsync(node, directory, edit, history, preimage, intended, ct);
        var expected = history switch
        {
            "completed" => ApprovalState.Executed,
            "target_changed" or "policy_denied" => ApprovalState.Failed,
            _ => ApprovalState.Approved,
        };

        await node.StartAsync();
        if (history == "pending")
        {
            await using var script = await node.ChannelAsync();
            await using var human = await node.ChannelAsync(helloAsHuman: true);
            var decision = new ApprovalServiceDecideApprovalRequest
            {
                Meta = InProcessNode.Command(),
                ApprovalId = new Id { Value = ByteString.CopyFrom(seeded.ApprovalId) },
                Decision = ApprovalDecisionKind.Approve,
            };
            var denied = await script.Approvals.DecideApprovalAsync(decision, cancellationToken: ct);
            Assert.Equal("permission_denied", denied.Error.Code);
            Assert.Equal(ApprovalState.Pending, ReadApproval(node, seeded).State);
            var approved = await human.Approvals.DecideApprovalAsync(decision, cancellationToken: ct);
            Assert.Null(approved.Error);
            Assert.Equal(ApprovalState.Approved, approved.Value.Approval.State);
        }

        if (expected is ApprovalState.Executed or ApprovalState.Failed)
        {
            // Positive cases rely on the host's actual startup resumer.
            var started = System.Diagnostics.Stopwatch.StartNew();
            while (ReadApproval(node, seeded).State == ApprovalState.Approved && started.Elapsed < TimeSpan.FromSeconds(15))
                await Task.Delay(20, ct);
        }
        else
        {
            await node.Runtime.ResumeApprovals!().WaitAsync(ct);
        }

        var receipt = ObserveRetainedState(node, seeded, expected, history, preimage, intended);
        var approval = ReadApproval(node, seeded);
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        await node.Runtime.ResumeApprovals!().WaitAsync(ct);
        Assert.Equal(approval.View, ReadApproval(node, seeded).View);
        Assert.Equal(receipt, ObserveRetainedState(node, seeded, expected, history, preimage, intended));
        Assert.Equal(preimage, File.ReadAllBytes(target));
        Assert.Equal(["target"], Directory.EnumerateFileSystemEntries(directory).Select(Path.GetFileName).ToArray());

        foreach (var database in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(database)) continue;
            using var stream = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(preimage));
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(intended));
        }
    }

    private static async Task<RetainedApproval> SeedRetainedApprovalAsync(InProcessNode node, string directory, bool edit,
        string history, byte[] preimage, byte[] intended, CancellationToken cancellationToken)
    {
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "file-approval-history", Clock = node.Clock });
        await using var processor = new CommandProcessor(store, EventJournal.Open(store), new StreamHub());
        var workspace = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(directory, cancellationToken: cancellationToken);
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = RoutedCalls.Account.Clone(),
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(store.Metadata.NodeId.Span) },
            LocalOrigin = Origin.Script,
            LocalSessionId = CommandIds.New(),
        };
        var meta = Tasks.Meta();
        var commandId = meta.CommandId.Value.ToByteArray();
        var path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" };
        var preimageHash = SHA256.HashData(preimage);
        var intendedHash = SHA256.HashData(intended);
        var raw = edit
            ? new FileServiceEditFileRequest
            {
                Meta = meta, Path = path, ExpectedSha256 = ByteString.CopyFrom(preimageHash),
                OldText = "alpha", NewText = "beta", ExpectedOccurrences = 2,
            }.ToByteArray()
            : new FileServiceWriteFileRequest
            {
                Meta = meta, Path = path, ExpectedSha256 = ByteString.CopyFrom(preimageHash),
                Data = ByteString.CopyFrom(intended),
            }.ToByteArray();
        var kind = edit ? FileOperationKind.Edit : FileOperationKind.Write;
        var digest = SHA256.HashData(raw);
        var approvalId = await processor.ExecuteAsync(command =>
        {
            var transaction = command.Transaction;
            Assert.Equal(PrivateStageReservationResult.Reserved, PrivateStageRegistry.Reserve(transaction, new FileStageBudget(),
                kind, commandId, workspace.Id, meta.CorrelationId.Value.Span, caller, raw,
                [new(1, Path.Combine(directory, "before"), preimage.Length, preimageHash),
                 new(2, Path.Combine(directory, "after"), intended.Length, intendedHash)]));
            // The identity tokens belong to database fixtures. No stage file or target guard is opened.
            var platform = OperatingSystem.IsWindows() ? 1 : 2;
            byte[] Identity(byte marker)
            {
                var identity = new byte[platform == 1 ? 33 : 53];
                identity[0] = 1;
                identity[1] = marker;
                return identity;
            }

            var root = Identity(1);
            var target = Identity(2);
            var before = Identity(3);
            var after = Identity(4);
            SeedRetainedStage(transaction, commandId, 1, platform, root, before);
            SeedRetainedStage(transaction, commandId, 2, platform, root, after);
            var raised = Approvals.Raise(command, new ApprovalCapture
            {
                Operation = edit ? "FileService.EditFile" : "FileService.WriteFile",
                MatrixOperation = PermissionMatrix.FileWrite,
                Summary = "Retained file approval fixture",
                Risk = RiskClass.High,
                Requester = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = meta.CommandId.Clone() },
                CommandId = commandId,
                Request = [1, .. commandId],
                RequestDigest = digest,
                TargetKind = "workspace",
                TargetId = workspace.Id,
            }, TimeSpan.FromHours(1));
            Assert.True(raised.Created);
            Assert.Null(raised.Error);
            var id = raised.Approval!.Id;
            Assert.Equal(1, transaction.Execute("""
                INSERT INTO file_private_approval_binding
                  (command_id, approval_id, identity_platform, root_identity, parent_identity, target_identity)
                VALUES ($command, $approval, $platform, $root, $root, $target);
                """, ("$command", commandId), ("$approval", id), ("$platform", platform), ("$root", root), ("$target", target)));
            if (history == "pending") return id;

            Assert.Equal(ApprovalState.Approved, Approvals.Decide(command, id, approve: true,
                new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli }, comment: null).State);
            if (history is "target_changed" or "policy_denied")
            {
                _ = FileMutationJournal.RecordApprovedPreEffectRefusal(transaction, id, history == "target_changed"
                    ? ApprovedFileRefusal.TargetChanged : ApprovedFileRefusal.PolicyDenied);
                return id;
            }

            Assert.Equal(1, transaction.Execute("""
                INSERT INTO file_operation_journal
                  (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
                   identity_platform, root_identity, parent_identity, target_identity, expected_absent, original_size,
                   original_sha256, original_stage_identity, intended_size, intended_sha256, intended_stage_identity,
                   created_at, updated_at, held, acknowledged)
                VALUES ($id, $kind, 1, $digest, $caller, $correlation, $workspace, 'target',
                        $platform, $root, $root, $target, 0, $oldSize, $oldHash, $before, $newSize, $newHash, $after,
                        $now, $now, 1, 0);
                """, ("$id", commandId), ("$kind", (int)kind), ("$digest", digest), ("$caller", caller.ToByteArray()),
                ("$correlation", meta.CorrelationId.Value.ToByteArray()), ("$workspace", workspace.Id), ("$platform", platform),
                ("$root", root), ("$target", target), ("$oldSize", preimage.Length), ("$oldHash", preimageHash),
                ("$before", before), ("$newSize", intended.Length), ("$newHash", intendedHash), ("$after", after),
                ("$now", transaction.NowMicroseconds)));
            if (history == "completed")
                _ = FileMutationJournal.CompleteVerifiedEffect(transaction, commandId, raw, intended.Length, intendedHash, edit ? 2U : null);
            return id;
        }, CommitDurability.Full).WaitAsync(cancellationToken);
        return new RetainedApproval(approvalId, commandId, kind, caller, raw, meta.CorrelationId, digest);
    }

    private static void SeedRetainedStage(StoreTransaction transaction, byte[] commandId, int slot, int platform, byte[] parent, byte[] identity)
    {
        Assert.Equal(1, transaction.Execute("""
            UPDATE file_private_stage_object
            SET phase = 2, identity_platform = $platform, native_identity = $identity, parent_identity = $parent
            WHERE command_id = $id AND slot = $slot AND phase = 1;
            """, ("$id", commandId), ("$slot", slot), ("$platform", platform), ("$identity", identity), ("$parent", parent)));
        Assert.Equal(1, transaction.Execute("""
            UPDATE file_private_stage_object SET phase = 3 WHERE command_id = $id AND slot = $slot AND phase = 2;
            """, ("$id", commandId), ("$slot", slot)));
    }

    private static StoredApproval ReadApproval(InProcessNode node, RetainedApproval seeded) =>
        node.Runtime.Store.Read(reader => Assert.IsType<StoredApproval>(Approvals.Get(reader, seeded.ApprovalId)));

    private static byte[]? ObserveRetainedState(InProcessNode node, RetainedApproval seeded, ApprovalState expected,
        string history, byte[] preimage, byte[] intended)
    {
        return node.Runtime.Store.Read(reader =>
        {
            var approval = Assert.IsType<StoredApproval>(Approvals.Get(reader, seeded.ApprovalId));
            Assert.Equal(expected, approval.State);
            Assert.Equal(seeded.Caller, approval.View.Requester.CenterCaller);
            Assert.Equal(seeded.CommandId, approval.View.CommandId.Value.ToByteArray());
            Assert.Equal(seeded.Digest, approval.RequestDigest);
            var receipt = FileMutationJournal.Replay(reader, seeded.Kind, seeded.CommandId, seeded.Caller, seeded.Raw);
            var foreign = seeded.Caller.Clone();
            foreign.AccountId = CommandIds.New();
            Assert.Null(FileMutationJournal.Replay(reader, seeded.Kind, seeded.CommandId, foreign, seeded.Raw));
            var operation = FileMutationJournal.GetForCaller(reader, seeded.CommandId, seeded.Caller);
            var audit = AuditLog.Recent(reader).Where(entry => entry.ApprovalId is { } approvalId && approvalId.AsSpan().SequenceEqual(seeded.ApprovalId) &&
                (entry.Outcome == "executed after approval" || entry.Outcome.StartsWith("failed after approval:", StringComparison.Ordinal)));
            Assert.Equal((expected == ApprovalState.Approved ? 1 : 0, (long)preimage.Length + intended.Length), PrivateStageRegistry.Usage(reader));
            Assert.Equal(2, PrivateStageRegistry.LoadIdentities(reader).Count);
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_stage_worker;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_effect_worker;"));

            if (expected == ApprovalState.Approved)
            {
                Assert.Null(approval.Outcome);
                Assert.Empty(audit);
                if (history == "pending")
                {
                    Assert.Null(operation);
                    Assert.Null(receipt);
                }
                else
                {
                    Assert.NotNull(receipt);
                    Assert.Equal(FileOperationState.Unknown, operation!.State);
                    Assert.True(operation.Held);
                    Assert.Equal("file_outcome_unknown", operation.Error.Details.State.Reason);
                }

                return receipt;
            }

            Assert.NotNull(receipt);
            Assert.Equal(receipt, approval.Outcome);
            Assert.Equal(FileOperationState.Completed, operation!.State);
            Assert.False(operation.Held);
            Assert.Equal(seeded.Digest, operation.RequestSha256.ToByteArray());
            var entry = Assert.Single(audit);
            Assert.Equal(Origin.Remote, entry.Actor.Origin);
            Assert.Equal(seeded.Caller, entry.Actor.CenterCaller);
            Assert.Equal(seeded.CommandId, entry.Actor.RemoteCommandId.Value.ToByteArray());
            if (history == "completed")
            {
                Assert.Equal("executed after approval", entry.Outcome);
                FileMutationResult result;
                if (seeded.Kind == FileOperationKind.Edit)
                {
                    var response = FileServiceEditFileResponse.Parser.ParseFrom(receipt);
                    Assert.True(NodeShapes.IsValid(response));
                    Assert.Null(response.Error);
                    Assert.Equal(seeded.Correlation, response.Meta.CorrelationId);
                    result = response.Value.Result;
                    Assert.Equal(2U, result.Replacements);
                }
                else
                {
                    var response = FileServiceWriteFileResponse.Parser.ParseFrom(receipt);
                    Assert.True(NodeShapes.IsValid(response));
                    Assert.Null(response.Error);
                    Assert.Equal(seeded.Correlation, response.Meta.CorrelationId);
                    result = response.Value.Result;
                    Assert.False(result.HasReplacements);
                }

                Assert.Equal(SHA256.HashData(intended), result.Sha256.ToByteArray());
            }
            else
            {
                var error = FileServiceWriteFileResponse.Parser.ParseFrom(receipt).Error;
                Assert.Equal(history == "target_changed" ? "file_changed" : "permission_denied", error.Code);
                Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
                Assert.Equal(seeded.Correlation, error.CorrelationId);
                Assert.Equal($"failed after approval: {error.Category}/{error.Code}", entry.Outcome);
            }

            return receipt;
        });
    }

    private sealed record RetainedApproval(byte[] ApprovalId, byte[] CommandId, FileOperationKind Kind, CenterCaller Caller,
        byte[] Raw, Id Correlation, byte[] Digest);
}
