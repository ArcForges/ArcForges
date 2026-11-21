// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Active custody of a retained named stage through the real store and routed handlers with an offline call fixture.</summary>
[Trait("loop", "local")]
public sealed class FileStageProducerHostTests
{
    // The native producer and installed-host scenario remain executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    [Fact(Timeout = 180_000)]
    public async Task RetainedPrivateStageStaysHiddenAndItsPendingApprovalSurvivesReopen()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var history = new LegacyFileHostHistory();
        var workspace = history.Workspace(ct);
        var caller = history.Caller(Origin.Script);
        var request = new FileServiceWriteFileRequest
        {
            Meta = LegacyFileHostHistory.Command(),
            Path = LegacyFileHostHistory.FilePath(workspace, "destination"),
            Data = ByteString.CopyFromUtf8("retained-private-stage-fixture"),
            ExpectedAbsent = true,
        };
        var raw = request.ToByteArray();
        var id = request.Meta.CommandId.Value.ToByteArray();
        var digest = SHA256.HashData(raw);
        const string stageName = "retained-stage";
        var stagePath = Path.Combine(workspace.RootPath, stageName);
        File.WriteAllBytes(stagePath, request.Data.ToByteArray());
        File.WriteAllText(Path.Combine(workspace.RootPath, "ordinary-file"), "ordinary fixture body");
        var root = LegacyFileHostHistory.RootIdentity(workspace.RootPath);
        var stage = LegacyFileHostHistory.FileIdentity(stagePath);
        var approvalId = await history.Processor.ExecuteAsync(command =>
        {
            var tx = command.Transaction;
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, id,
                "arcforges.node.v1.FileService/WriteFile", digest, Origin.Remote).Status);
            tx.Execute("""
                INSERT INTO file_private_stage_reservation
                    (command_id, workspace_id, kind, correlation_id, relative_path, expected_absent, request_sha256, caller, reserved_bytes, created_at)
                VALUES ($id, $workspace, 1, $correlation, 'destination', 1, $digest, $caller, $size, $now);
                """, ("$id", id), ("$workspace", workspace.Id), ("$correlation", request.Meta.CorrelationId.Value.ToByteArray()),
                ("$digest", digest), ("$caller", caller.ToByteArray()), ("$size", request.Data.Length), ("$now", tx.NowMicroseconds));
            tx.Execute("""
                INSERT INTO file_private_stage_object
                    (command_id, slot, stage_path, expected_size, expected_sha256, phase, identity_platform, native_identity, parent_identity)
                VALUES ($id, 2, $path, $size, $hash, 3, $platform, $native, $parent);
                """, ("$id", id), ("$path", stagePath), ("$size", request.Data.Length), ("$hash", SHA256.HashData(request.Data.Span)),
                ("$platform", stage.Platform), ("$native", stage.Bytes), ("$parent", root.Bytes));
            var (approval, created, error) = Approvals.Raise(command, new ApprovalCapture
            {
                Operation = "FileService.WriteFile", MatrixOperation = PermissionMatrix.FileWrite, Summary = "retained private fixture",
                Risk = RiskClass.High, Requester = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId },
                CommandId = id, RequestDigest = digest, Request = [1, .. id],
            }, Approvals.DefaultTtl);
            Assert.True(created);
            Assert.Null(error);
            Assert.NotNull(approval);
            tx.Execute("""
                INSERT INTO file_private_approval_binding (command_id, approval_id, identity_platform, root_identity, parent_identity)
                VALUES ($command, $approval, $platform, $root, $root);
                """, ("$command", id), ("$approval", approval.Id), ("$platform", root.Platform), ("$root", root.Bytes));
            return approval.Id;
        }, CommitDurability.Full).WaitAsync(ct);

        async Task AssertPendingAsync()
        {
            var answer = await history.RouteAsync(RoutedMethod.WriteNodeFile, caller, request, request.Meta.CommandId, ct);
            Assert.NotNull(answer);
            Assert.Equal(RoutedOutcome.RefusedByPolicy, answer.Outcome);
            Assert.Null(answer.Response);
            var denied = Assert.IsType<ArcError>(answer.Error);
            Assert.Equal("approval_required", denied.Code);
            Assert.Equal(approvalId, denied.Details.State.Resource.Id.Value.ToByteArray());
            Assert.True(history.Store.Read(reader => PrivateStageRegistry.HasWorkspaceHold(reader, workspace.Id)));
            using var handle = File.OpenHandle(stagePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var native = WorkspacePath.Identity(handle);
            Assert.True(history.Store.Read(reader => PrivateStageRegistry.ContainsIdentity(reader, native)));
            var human = caller.Clone();
            human.LocalOrigin = Origin.Human;
            human.LocalSessionId = CommandIds.New();
            var read = await history.RouteAsync(RoutedMethod.ReadNodeFile, human, new FileServiceReadFileRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() }, Offset = 0, Length = 128,
                Path = LegacyFileHostHistory.FilePath(workspace, stageName),
            }, null, ct);
            var protectedRead = FileServiceReadFileResponse.Parser.ParseFrom(read!.Response);
            Assert.Equal("file_access_denied", protectedRead.Error?.Code);
            Assert.Null(protectedRead.Value);
            var list = await history.RouteAsync(RoutedMethod.ListNodeDirectory, human, new FileServiceListDirectoryRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                Path = LegacyFileHostHistory.FilePath(workspace, ""),
            }, null, ct);
            var listed = FileServiceListDirectoryResponse.Parser.ParseFrom(list!.Response);
            Assert.Null(listed.Error);
            Assert.Contains(listed.Value.Entries, entry => entry.Name == "ordinary-file");
            Assert.DoesNotContain(listed.Value.Entries, entry => entry.Name == stageName);
            Assert.Equal(0L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
            Assert.Equal(0L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_stage_worker;")));
            Assert.Equal(request.Data.ToByteArray(), File.ReadAllBytes(stagePath));
            Assert.False(File.Exists(Path.Combine(workspace.RootPath, "destination")));
        }

        await AssertPendingAsync();
        await history.ReopenAsync();
        await AssertPendingAsync();
        foreach (var file in new[] { history.Store.DatabasePath, history.Store.DatabasePath + "-wal" })
        {
            if (CloudLinkHostTests.ReadAllShared(file) is { } bytes)
                Assert.Equal(-1, bytes.AsSpan().IndexOf(request.Data.Span));
        }
    }
}

internal sealed class LegacyFileHostHistory : IAsyncDisposable
{
    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-file-history-");
    private NodeLog _log = null!;
    private NodeRuntime _runtime = null!;
    private RoutedDispatcher _dispatcher = null!;

    internal LegacyFileHostHistory() => Open();

    internal string Root => _directory.FullName;
    internal NodeStore Store { get; private set; } = null!;
    internal CommandProcessor Processor { get; private set; } = null!;
    internal static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };

    internal RegisteredWorkspace Workspace(CancellationToken token) => new RegisteredWorkspaces(Store).RegisterFromVerifiedHuman(
        Directory.CreateDirectory(Path.Combine(Root, "workspace")).FullName, cancellationToken: token);

    internal static NodeFilePath FilePath(RegisteredWorkspace workspace, string path) =>
        new() { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = path };

    internal CenterCaller Caller(Origin origin) => new()
    {
        Kind = CenterCallerKind.NodeRelay,
        AccountId = CommandIds.New(),
        RelayingNodeId = new Id { Value = ByteString.CopyFrom(_runtime.NodeId.Span) },
        LocalOrigin = origin,
        LocalSessionId = CommandIds.New(),
    };

    internal static RegisteredWorkspaces.RootIdentity RootIdentity(string path)
    {
        using var root = WorkspacePath.OpenRoot(path);
        return RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
    }

    internal static RegisteredWorkspaces.RootIdentity FileIdentity(string path)
    {
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(handle), directory: false);
    }

    internal static FileJournalIntent PrepareMutation(StoreTransaction tx, RegisteredWorkspace workspace, CenterCaller caller,
        FileOperationKind kind, RequestMeta meta, string path, byte[] raw, byte[]? original, byte[] intended)
    {
        var root = RootIdentity(workspace.RootPath);
        var target = original is null ? null : FileIdentity(Path.Combine(workspace.RootPath, path));
        // Identity encodings model already released anonymous stages. No stage bytes or live handles are needed for replay.
        byte[] Stage(byte tag)
        {
            var identity = new byte[root.Bytes.Length];
            identity[0] = 1;
            identity[1] = tag;
            return identity;
        }

        var intent = new FileJournalIntent(kind, meta.CommandId.Value.ToByteArray(), meta.CorrelationId.Value.ToByteArray(), caller,
            workspace.Id, path, root.Platform, root.Bytes, root.Bytes, target?.Bytes, original?.Length,
            original is null ? null : SHA256.HashData(original), original is null ? null : Stage(2),
            intended.Length, SHA256.HashData(intended), Stage(3));
        Assert.Equal(FileJournalPreparation.Prepared, FileMutationJournal.Prepare(tx, intent, raw));
        return intent;
    }

    internal Task<RoutedAnswer?> RouteAsync(RoutedMethod method, CenterCaller caller, IMessage request, Id? command, CancellationToken token)
    {
        var raw = request.ToByteString();
        var now = Store.Clock.GetUtcNow();
        var header = new CallHeader
        {
            CallId = CommandIds.New(), Kid = "offline-file-history", Caller = caller.Clone(), AccountId = caller.AccountId.Clone(),
            TargetNodeId = new Id { Value = ByteString.CopyFrom(_runtime.NodeId.Span) },
            CenterUrlSha256 = ByteString.CopyFrom(new byte[32]), Method = method, CommandId = command?.Clone(),
            RequestSha256 = ByteString.CopyFrom(SHA256.HashData(raw.Span)), RequestSize = (uint)raw.Length,
            IssuedAt = ProtoTime.ToInstant(now), ExpiresAt = ProtoTime.ToInstant(now.AddMinutes(1)), Deadline = ProtoTime.ToInstant(now.AddSeconds(10)),
        };
        return _dispatcher.DispatchAsync(new VerifiedCall(header, raw, 0), new OfflineLink(), token);
    }

    internal async Task ReopenAsync()
    {
        await CloseAsync();
        Open();
    }

    private void Open()
    {
        var data = Path.Combine(Root, "data");
        Store = NodeStore.Open(new NodeStoreOptions { DataRoot = data, BootIdentity = BootIdentity.Read() });
        _log = new NodeLog(Path.Combine(data, "logs", "node"), LogLevel.Info, Store.Clock);
        var journal = EventJournal.Open(Store);
        var hub = new StreamHub();
        Processor = new CommandProcessor(Store, journal, hub);
        _runtime = new NodeRuntime(Store, journal, hub, Processor, _log,
            new NodeSettingsManager(Path.Combine(Root, "node.json"), data, _log), data, "offline-file-history", Store.Clock,
            new RecoveryReport(false, false, null, Store.Opening), new CapabilityReport());
        _dispatcher = new RoutedDispatcher(_runtime);
        _dispatcher.Bind(new TaskServiceHandler(_runtime, new ClientSessions()), new WorkspaceServiceHandler(_runtime), new FileServiceHandler(_runtime));
    }

    private async Task CloseAsync()
    {
        _dispatcher.Dispose();
        _runtime.Dispose();
        await Processor.DisposeAsync();
        _log.Dispose();
        Store.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await CloseAsync();
        _directory.Delete(recursive: true);
    }

    private sealed class OfflineLink : IRoutedLink
    {
        public bool Usable => true;
        public bool Stopping => false;
    }
}
