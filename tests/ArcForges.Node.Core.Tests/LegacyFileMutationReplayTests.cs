// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

public sealed class LegacyFileMutationReplayTests
{
    [Theory(Timeout = 30_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WriteAndEditCannotStageNewWorkAndReplayOnlyTheExactRetainedReceipt(bool edit)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var kind = edit ? FileOperationKind.Edit : FileOperationKind.Write;
        var method = edit ? RoutedMethod.EditNodeFile : RoutedMethod.WriteNodeFile;
        var workspace = CommandIds.New();
        var meta = Tasks.Meta();
        var raw = Request(edit, meta, workspace);
        var id = meta.CommandId.Value.ToByteArray();
        var handler = calls.Dispatcher.FileHandlerForTests!;
        handler.AfterStageBeforeJournalForTests = () => throw new InvalidOperationException("The draining path cannot stage a file.");
        handler.AfterApprovalReservationForTests = () => throw new InvalidOperationException("The draining path cannot reserve a producer.");

        async Task<byte[]?> Invoke(byte[] payload, CenterCaller source) =>
            (await calls.CallAsync(source, method, payload, meta.CommandId)).Answer?.Response?.ToByteArray();

        ArcError GetError(byte[]? outcome)
        {
            Assert.NotNull(outcome);
            return edit ? FileServiceEditFileResponse.Parser.ParseFrom(outcome).Error :
                FileServiceWriteFileResponse.Parser.ParseFrom(outcome).Error;
        }

        var refused = GetError(await Invoke(raw, caller));
        Assert.Equal(("operation_failed", "file_outcome_unknown", EffectCertainty.Unknown, RetryMode.Never),
            (refused.Code, refused.Details.State.Reason, refused.Effect, refused.Retry.Mode));
        Assert.Equal(meta.CorrelationId, refused.CorrelationId);
        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", id)));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_operation_journal;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_private_stage_reservation;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_stage_worker;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_effect_worker;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM approval;"));
            return 0;
        });

        node.Runtime.Store.Write(transaction =>
            SeedStage(transaction, workspace, node.Root, meta, kind, caller, raw), CommitDurability.Full);
        Assert.Null(await Invoke(raw, caller));
        var changed = meta.Clone();
        changed.CorrelationId = CommandIds.New();
        Assert.Equal("command_id_reused", GetError(await Invoke(Request(edit, changed, workspace), caller)).Code);
        var foreign = caller.Clone();
        foreign.AccountId = CommandIds.New();
        Assert.Equal("command_id_reused", GetError(await Invoke(raw, foreign)).Code);
        Assert.Equal(1L, node.Runtime.Store.Read(reader =>
            reader.Scalar("SELECT active FROM file_private_stage_reservation WHERE command_id = $id;", ("$id", id))));
        Assert.Null(node.Runtime.Store.Read(reader => reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", id))));

        Assert.True(node.Runtime.Store.Write(transaction => PrivateStageTerminal.RecoverFailedProducer(transaction, id), CommitDurability.Full));
        var original = node.Runtime.Store.Read(reader => FileMutationJournal.Replay(reader, kind, id, caller, raw));
        Assert.NotNull(original);
        var replay = await Invoke(raw, caller);
        Assert.Equal(original, replay);
        Assert.Equal("file_preparation_abandoned", GetError(replay).Details.State.Reason);
        Assert.Equal("command_id_reused", GetError(await Invoke(raw, foreign)).Code);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
    }

    [Theory(Timeout = 30_000)]
    [InlineData(false, FileOperationState.Completed, false, false)]
    [InlineData(false, FileOperationState.Unknown, false, false)]
    [InlineData(true, null, true, false)]
    [InlineData(true, null, true, true)]
    [InlineData(true, null, false, false)]
    public async Task CorruptRetainedMutationReturnsOnlyAuditedUncertainty(bool edit, FileOperationState? journal, bool terminalStage,
        bool missingOutcome)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var foreign = caller.Clone();
        foreign.AccountId = CommandIds.New();
        var kind = edit ? FileOperationKind.Edit : FileOperationKind.Write;
        var method = edit ? RoutedMethod.EditNodeFile : RoutedMethod.WriteNodeFile;
        var workspace = CommandIds.New();
        var meta = Tasks.Meta();
        var raw = Request(edit, meta, workspace);
        var id = meta.CommandId.Value.ToByteArray();
        node.Runtime.Store.Write(transaction =>
        {
            SeedStage(transaction, workspace, node.Root, meta, kind, caller, raw);
            if (journal is { } phase)
            {
                SeedPreparedWrite(transaction, workspace, meta, caller, raw);
                if (phase == FileOperationState.Completed)
                    FileMutationJournal.CompleteVerifiedEffect(transaction, id, raw, 1, SHA256.HashData("x"u8), replacements: null);
                else
                    FileMutationJournal.MarkUnknown(transaction, id);
            }
            if (terminalStage) Assert.True(PrivateStageTerminal.RecoverFailedProducer(transaction, id));
        }, CommitDurability.Full);

        async Task<ArcError> Invoke(CenterCaller source)
        {
            var result = (await calls.CallAsync(source, method, raw, meta.CommandId, cancellationToken: ct)).Answer?.Response;
            Assert.NotNull(result);
            return edit ? FileServiceEditFileResponse.Parser.ParseFrom(result).Error : FileServiceWriteFileResponse.Parser.ParseFrom(result).Error;
        }

        var before = await Invoke(foreign);
        Assert.Equal("command_id_reused", before.Code);
        // A missing terminal outcome or a truncated protobuf cannot establish the original effect.
        byte[]? malformed = missingOutcome ? null : [0x80];
        node.Runtime.Store.Write(transaction => Assert.Equal(1, transaction.Execute(
            "UPDATE command_dedup SET outcome = $malformed WHERE command_id = $id;", ("$malformed", malformed), ("$id", id))),
            CommitDurability.Full);

        var refused = await Invoke(caller);
        Assert.Equal((ErrorCategory.Execution, "operation_failed", "file", "file_outcome_unknown", EffectCertainty.Unknown, RetryMode.Never),
            (refused.Category, refused.Code, refused.Details.State.State, refused.Details.State.Reason, refused.Effect, refused.Retry.Mode));
        Assert.Equal(meta.CorrelationId, refused.CorrelationId);
        Assert.Equal(before, await Invoke(foreign));
        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(malformed, reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", id)) as byte[]);
            Assert.Equal(journal is { } phase ? (long)phase : null,
                reader.Scalar("SELECT phase FROM file_operation_journal WHERE command_id = $id;", ("$id", id)) as long?);
            Assert.Equal(journal is null ? null : journal == FileOperationState.Unknown ? 1L : 0L,
                reader.Scalar("SELECT held FROM file_operation_journal WHERE command_id = $id;", ("$id", id)) as long?);
            Assert.Equal(terminalStage || journal == FileOperationState.Completed ? 0L : 1L,
                reader.Scalar("SELECT active FROM file_private_stage_reservation WHERE command_id = $id;", ("$id", id)));
            Assert.Equal(terminalStage ? 1L : 0L, reader.Scalar("SELECT count(*) FROM file_private_stage_terminal;"));
            Assert.Equal(1L, reader.Scalar("""
                SELECT count(*) FROM audit_log WHERE remote_command_id = $id AND outcome_summary = 'refused: operation_failed';
                """, ("$id", id)));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_effect_worker;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_stage_worker;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM approval;"));
            return 0;
        });
    }

    [Theory(Timeout = 30_000)]
    [InlineData(null)]
    [InlineData(FileOperationState.Prepared)]
    [InlineData(FileOperationState.Unknown)]
    [InlineData(FileOperationState.Completed)]
    public async Task AnApprovedWriteCanOnlyReplayASettledJournalWithoutStartingOrChangingIt(FileOperationState? history)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "legacy-write-replay-fixture", Clock = fixture.Clock });
        using var log = new NodeLog(Path.Combine(fixture.DataRoot, "logs", "node"), LogLevel.Info, fixture.Clock);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        // The production handler shares the real writer without the host's asynchronous approval resumption.
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(fixture.ConfigPath, fixture.DataRoot, log), fixture.DataRoot, "offline-fixture", fixture.Clock,
            new RecoveryReport(false, false, null, store.Opening), new CapabilityReport());
        using var files = new FileServiceHandler(runtime);
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = RoutedCalls.Account.Clone(),
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(runtime.NodeId.Span) },
            LocalOrigin = Origin.Script,
            LocalSessionId = CommandIds.New(),
        };
        var workspace = CommandIds.New();
        var meta = Tasks.Meta();
        var raw = Request(edit: false, meta, workspace);
        var id = meta.CommandId.Value.ToByteArray();
        byte[] reference = [1, .. id];
        var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = meta.CommandId.Clone() };
        var (approvalId, recorded) = await processor.ExecuteAsync(command =>
        {
            var transaction = command.Transaction;
            SeedStage(transaction, workspace, fixture.Root, meta, FileOperationKind.Write, caller, raw);
            var raised = Approvals.Raise(command, new ApprovalCapture
            {
                Operation = "FileService.WriteFile",
                MatrixOperation = PermissionMatrix.FileWrite,
                Summary = "historical named stage fixture",
                Risk = PermissionMatrix.Find(PermissionMatrix.FileWrite)!.Risk,
                Requester = actor,
                CommandId = id,
                RequestDigest = SHA256.HashData(raw),
                Request = reference,
            }, TimeSpan.FromHours(1));
            Assert.True(raised.Created);
            Assert.Null(raised.Error);
            var approval = raised.Approval!;
            var platform = OperatingSystem.IsWindows() ? 1 : 2;
            var identity = new byte[platform == 1 ? 33 : 53];
            identity[0] = 1;
            transaction.Execute("""
                INSERT INTO file_private_stage_object
                  (command_id, slot, stage_path, expected_size, expected_sha256, phase, identity_platform, native_identity, parent_identity)
                VALUES ($id, 2, $path, 1, $hash, 3, $platform, $identity, $identity);
                """, ("$id", id), ("$path", Path.Combine(fixture.Root, "retained-stage")), ("$hash", SHA256.HashData("x"u8)),
                ("$platform", platform), ("$identity", identity));
            transaction.Execute("""
                INSERT INTO file_private_approval_binding
                  (command_id, approval_id, identity_platform, root_identity, parent_identity)
                VALUES ($id, $approval, $platform, $identity, $identity);
                """, ("$id", id), ("$approval", approval.Id), ("$platform", platform), ("$identity", identity));
            var approved = Approvals.Decide(command, approval.Id, approve: true,
                new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli }, comment: null);
            byte[]? completedBytes = null;
            if (history is not null)
            {
                SeedPreparedWrite(transaction, workspace, meta, caller, raw);
                if (history == FileOperationState.Completed)
                    completedBytes = FileMutationJournal.CompleteVerifiedEffect(transaction, id, raw, 1, SHA256.HashData("x"u8), replacements: null);
                if (history == FileOperationState.Unknown)
                    FileMutationJournal.MarkUnknown(transaction, id);
            }
            return (approved.Id, completedBytes);
        }, CommitDurability.Full).WaitAsync(ct);

        Assert.NotNull(store.Read(reader => PrivateStageApprovedPlans.Read(reader, approvalId)));
        var original = store.Read(reader => FileMutationJournal.GetForCaller(reader, id, caller));
        Assert.Equal(history, original?.State);
        var retained = store.Read(reader => FileMutationJournal.ReplayApproved(reader, approvalId));
        var approved = Caller.OfApproval(actor, approvalId, runtime.NodeId.Span, reference);
        var result = await files.ExecuteApprovedReferenceAsync(reference, approved).WaitAsync(ct);
        if (history == FileOperationState.Completed)
        {
            Assert.NotNull(retained);
            Assert.Equal(recorded, retained);
            Assert.Equal(retained, result);
        }
        else
        {
            Assert.Null(result);
        }
        store.Read(reader =>
        {
            Assert.Equal(ApprovalState.Approved, Approvals.Get(reader, approvalId)!.State);
            Assert.Null(Approvals.Get(reader, approvalId)!.Outcome);
            Assert.Equal(history == FileOperationState.Completed ? 0L : 1L,
                reader.Scalar("SELECT active FROM file_private_stage_reservation WHERE command_id = $id;", ("$id", id)));
            Assert.Equal(history is null ? 0L : 1L, reader.Scalar("SELECT count(*) FROM file_operation_journal;"));
            Assert.Equal(original, FileMutationJournal.GetForCaller(reader, id, caller));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_effect_worker;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_stage_worker;"));
            return 0;
        });
        Assert.False(File.Exists(Path.Combine(fixture.Root, "retained-stage")));
        Assert.False(Directory.Exists(Path.Combine(fixture.Root, "unopened-workspace")));
    }

    private static void SeedPreparedWrite(StoreTransaction transaction, Id workspace, RequestMeta meta, CenterCaller caller, byte[] raw)
    {
        // SQLite fixture identities only. No target or stage is opened.
        var platform = OperatingSystem.IsWindows() ? 1 : 2;
        var identity = new byte[platform == 1 ? 33 : 53];
        identity[0] = 1;
        transaction.Execute("""
            INSERT INTO file_operation_journal
              (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
               identity_platform, root_identity, parent_identity, expected_absent, intended_size, intended_sha256,
               intended_stage_identity, created_at, updated_at, held, acknowledged)
            VALUES ($id, 1, 1, $digest, $caller, $correlation, $workspace, 'target', $platform, $identity, $identity,
                    1, 1, $hash, $identity, $now, $now, 1, 0);
            """, ("$id", meta.CommandId.Value.ToByteArray()), ("$digest", SHA256.HashData(raw)), ("$caller", caller.ToByteArray()),
            ("$correlation", meta.CorrelationId.Value.ToByteArray()), ("$workspace", workspace.Value.ToByteArray()),
            ("$platform", platform), ("$identity", identity), ("$hash", SHA256.HashData("x"u8)), ("$now", transaction.NowMicroseconds));
    }

    private static byte[] Request(bool edit, RequestMeta meta, Id workspace)
    {
        var path = new NodeFilePath { WorkspaceId = workspace.Clone(), Path = "target" };
        return edit
            ? new FileServiceEditFileRequest
            {
                Meta = meta.Clone(),
                Path = path,
                ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData("original"u8)),
                OldText = "a",
                NewText = "b",
                ExpectedOccurrences = 1,
            }.ToByteArray()
            : new FileServiceWriteFileRequest
            {
                Meta = meta.Clone(),
                Path = path,
                ExpectedAbsent = true,
                Data = ByteString.CopyFromUtf8("x"),
            }.ToByteArray();
    }

    private static void SeedStage(StoreTransaction transaction, Id workspace, string root, RequestMeta meta,
        FileOperationKind kind, CenterCaller caller, byte[] raw)
    {
        var id = meta.CommandId.Value.ToByteArray();
        var digest = SHA256.HashData(raw);
        var method = kind == FileOperationKind.Write ? "WriteFile" : "EditFile";
        transaction.Execute("""
            INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
            VALUES ($workspace, 1, 2, 'history fixture', $root, $now, $now, 0);
            """, ("$workspace", workspace.Value.ToByteArray()), ("$root", Path.Combine(root, "unopened-workspace")),
            ("$now", transaction.NowMicroseconds));
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id,
            "arcforges.node.v1.FileService/" + method, digest, Origin.Remote).Status);
        transaction.Execute("""
            INSERT INTO file_private_stage_reservation
              (command_id, workspace_id, kind, correlation_id, relative_path, expected_absent, expected_sha256,
               expected_occurrences, request_sha256, caller, reserved_bytes, created_at)
            VALUES ($id, $workspace, $kind, $correlation, 'target', $absent, $expected, $occurrences, $digest, $caller, 1, $now);
            """, ("$id", id), ("$workspace", workspace.Value.ToByteArray()), ("$kind", (int)kind),
            ("$correlation", meta.CorrelationId.Value.ToByteArray()), ("$absent", kind == FileOperationKind.Write ? 1 : 0),
            ("$expected", kind == FileOperationKind.Edit ? SHA256.HashData("original"u8) : null),
            ("$occurrences", kind == FileOperationKind.Edit ? 1 : null), ("$digest", digest), ("$caller", caller.ToByteArray()),
            ("$now", transaction.NowMicroseconds));
    }
}
