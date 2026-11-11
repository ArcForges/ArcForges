// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual internal candidate over real policy, SQLite and native files; the center caller is isolated synthetic.</summary>
public sealed class FileWriteExistingCandidateTests
{
    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task WindowsCandidateWritesAndEditsSameGuardedObjectReplaysAndRecoversUnsettledEffect()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows no-sharing existing-file candidate."); return; }
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "existing-write-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: token);
        var path = Path.Combine(rootPath, "target.txt");
        var streamPath = path + ":af-test";
        var original = Encoding.UTF8.GetBytes("REAL_CANDIDATE_ORIGINAL_54cc");
        var intended = Encoding.UTF8.GetBytes("REAL_CANDIDATE_RESULT_709a");
        var alternate = Encoding.UTF8.GetBytes("REAL_CANDIDATE_ALTERNATE_26a2");
        File.WriteAllBytes(path, original);
        File.WriteAllBytes(streamPath, alternate);
        File.SetAttributes(path, FileAttributes.Archive);
        var attributes = File.GetAttributes(path);
        var created = File.GetCreationTimeUtc(path);
        var sections = AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;
        var security = new FileInfo(path).GetAccessControl(sections).GetSecurityDescriptorBinaryForm();
        WorkspaceObjectIdentity identity;
        using (var root = WorkspacePath.OpenRoot(rootPath)) identity = root.InspectEntry("target.txt").Identity;

        FileServiceWriteFileRequest Request(byte[] expected, byte[] data) => new()
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target.txt" },
            ExpectedSha256 = ByteString.CopyFrom(expected),
            Data = ByteString.CopyFrom(data),
        };
        async Task<byte[]?> Invoke(IMessage message, CenterCaller source)
        {
            var meta = message switch
            {
                FileServiceWriteFileRequest write => write.Meta,
                FileServiceEditFileRequest edit => edit.Meta,
                _ => throw new InvalidOperationException("Unexpected test method."),
            };
            var raw = message.ToByteArray();
            var now = node.Runtime.Clock.GetUtcNow();
            var context = new RoutedContext(calls.Link, node.Runtime.Lifecycle, now.AddSeconds(30), TimeSpan.FromSeconds(15),
                node.Runtime.Clock, node.Runtime.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
            var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: source.Clone())
            {
                CellsOrigin = CenterRouting.CellsOrigin(source, node.Runtime.NodeId.Span),
                RemoteCommandId = meta.CommandId.Clone(),
                RawRequest = raw,
                Routed = context,
            };
            var handler = calls.Dispatcher.FileHandlerForTests!;
            return message is FileServiceWriteFileRequest
                ? await handler.WriteExistingCandidateAsync(caller, token)
                : await handler.EditExistingCandidateAsync(caller, token);
        }

        var stale = Request(new byte[32], intended);
        var staleBytes = await Invoke(stale, actor);
        var staleReply = FileServiceWriteFileResponse.Parser.ParseFrom(staleBytes);
        Assert.True(NodeShapes.IsValid(staleReply));
        Assert.Equal("file_changed", staleReply.Error.Code);
        Assert.Equal("hash_mismatch", staleReply.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, staleReply.Error.Effect);
        Assert.Equal(original, File.ReadAllBytes(path));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal WHERE command_id = $id;",
            ("$id", stale.Meta.CommandId.Value.ToByteArray()))));

        var request = Request(SHA256.HashData(original), intended);
        var raw = request.ToByteArray();
        var first = await Invoke(request, actor);
        Assert.NotNull(first);
        var reply = FileServiceWriteFileResponse.Parser.ParseFrom(first);
        Assert.True(NodeShapes.IsValid(reply));
        Assert.Null(reply.Error);
        Assert.Equal(request.Meta.CommandId, reply.Value.Result.CommandId);
        Assert.Equal(request.Meta.CorrelationId, reply.Meta.CorrelationId);
        Assert.Equal(SHA256.HashData(intended), reply.Value.Result.Sha256.ToByteArray());
        Assert.Equal((ulong)intended.Length, reply.Value.Result.SizeBytes);
        Assert.Equal(intended, File.ReadAllBytes(path));
        using (var root = WorkspacePath.OpenRoot(rootPath)) Assert.True(identity.SameObject(root.InspectEntry("target.txt").Identity));
        Assert.Equal(attributes, File.GetAttributes(path));
        Assert.Equal(created, File.GetCreationTimeUtc(path));
        Assert.Equal(security, new FileInfo(path).GetAccessControl(sections).GetSecurityDescriptorBinaryForm());
        Assert.Equal(alternate, File.ReadAllBytes(streamPath));
        var stored = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, request.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Completed, stored!.State);
        Assert.Equal(SHA256.HashData(raw), stored.RequestSha256.ToByteArray());

        var external = Encoding.UTF8.GetBytes("unrelated later change");
        using (var externalWriter = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            externalWriter.Write(external);
            externalWriter.SetLength(external.Length);
            externalWriter.Flush(flushToDisk: true);
        }
        // The test's independent later mutation must not remove the stream before the Edit path is exercised.
        Assert.Equal(alternate, File.ReadAllBytes(streamPath));
        var replay = await Invoke(request, actor);
        Assert.Equal(first, replay);
        Assert.Equal(external, File.ReadAllBytes(path));
        var changedRequest = request.Clone();
        changedRequest.Meta.CorrelationId = CommandIds.New();
        var conflict = FileServiceWriteFileResponse.Parser.ParseFrom(await Invoke(changedRequest, actor));
        Assert.Equal("command_id_reused", conflict.Error.Code);
        Assert.Equal(external, File.ReadAllBytes(path));

        FileServiceEditFileRequest Edit(uint occurrences) => new()
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target.txt" },
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(external)),
            OldText = "later",
            NewText = "recent",
            ExpectedOccurrences = occurrences,
        };
        var mismatch = Edit(2);
        var mismatchReply = FileServiceEditFileResponse.Parser.ParseFrom(await Invoke(mismatch, actor));
        Assert.True(NodeShapes.IsValid(mismatchReply));
        Assert.Equal("occurrence_mismatch", mismatchReply.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, mismatchReply.Error.Effect);
        Assert.Equal(external, File.ReadAllBytes(path));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal WHERE command_id = $id;",
            ("$id", mismatch.Meta.CommandId.Value.ToByteArray()))));

        var edit = Edit(1);
        var editRaw = edit.ToByteArray();
        var editedBytes = await Invoke(edit, actor);
        var edited = FileServiceEditFileResponse.Parser.ParseFrom(editedBytes);
        var expectedEdit = Encoding.UTF8.GetBytes("unrelated recent change");
        Assert.True(NodeShapes.IsValid(edited));
        Assert.Equal(1U, edited.Value.Result.Replacements);
        Assert.Equal(SHA256.HashData(expectedEdit), edited.Value.Result.Sha256.ToByteArray());
        Assert.Equal(expectedEdit, File.ReadAllBytes(path));
        Assert.Equal(alternate, File.ReadAllBytes(streamPath));
        using (var root = WorkspacePath.OpenRoot(rootPath)) Assert.True(identity.SameObject(root.InspectEntry("target.txt").Identity));
        var editStatus = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, edit.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Completed, editStatus!.State);
        Assert.Equal(SHA256.HashData(editRaw), editStatus.RequestSha256.ToByteArray());
        var unrelated = Encoding.UTF8.GetBytes("another unrelated change");
        File.WriteAllBytes(path, unrelated);
        Assert.Equal(editedBytes, await Invoke(edit, actor));
        Assert.Equal(unrelated, File.ReadAllBytes(path));

        var script = calls.Relay(Origin.Script);
        var pendingApproval = Request(SHA256.HashData(unrelated), intended);
        var pendingError = await Record.ExceptionAsync(async () => await Invoke(pendingApproval, script));
        Assert.IsAssignableFrom<NotSupportedException>(pendingError); // Real approval remains unfinished; no fabricated decision.
        Assert.Equal(unrelated, File.ReadAllBytes(path));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal WHERE command_id = $id;",
            ("$id", pendingApproval.Meta.CommandId.Value.ToByteArray()))));
        var agent = calls.Relay(Origin.Agent);
        var deniedRequest = Request(SHA256.HashData(unrelated), intended);
        var denied = FileServiceWriteFileResponse.Parser.ParseFrom(await Invoke(deniedRequest, agent));
        Assert.Equal("permission_denied", denied.Error.Code);
        Assert.Equal(unrelated, File.ReadAllBytes(path));

        var failingPath = Path.Combine(rootPath, "fail.txt");
        File.WriteAllBytes(failingPath, original);
        File.SetAttributes(failingPath, FileAttributes.Archive);
        var fail = Request(SHA256.HashData(original), intended);
        fail.Path.Path = "fail.txt";
        node.Runtime.Store.Write(transaction => transaction.Execute("""
            CREATE TRIGGER test_fail_write_audit BEFORE INSERT ON file_workspace_audit
            WHEN NEW.path = 'fail.txt' BEGIN SELECT RAISE(ABORT, 'test_write_audit_failure'); END;
            """));
        var error = await Record.ExceptionAsync(async () => await Invoke(fail, actor));
        Assert.NotNull(error);
        Assert.Equal(intended, File.ReadAllBytes(failingPath)); // real effect happened; no result was returned
        var pending = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, fail.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Prepared, pending!.State);
        node.Runtime.Store.Write(transaction => transaction.Execute("DROP TRIGGER test_fail_write_audit;"));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var recovered = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, fail.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Unknown, recovered!.State);
        Assert.True(recovered.Held);
        Assert.Equal("file_outcome_unknown", recovered.Error.Details.State.Reason);
        Assert.Equal(fail.Meta.CorrelationId, recovered.Error.CorrelationId);
        Assert.Equal(intended, File.ReadAllBytes(failingPath));
        foreach (var db in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(db)) continue;
            using var file = new FileStream(db, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            file.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(original));
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(intended));
        }
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "linux-real")]
    public async Task LinuxCandidateRefusesBeforeTargetEffectWhileItsNativeLeaseCoordinatorIsUnproven()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux lease-coordinator refusal.");
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "linux-write-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: token);
        var path = Path.Combine(rootPath, "target.txt");
        var original = Encoding.UTF8.GetBytes("linux-existing-unchanged");
        File.WriteAllBytes(path, original);
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target.txt" },
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original)),
            Data = ByteString.CopyFromUtf8("new-content"),
        };
        var now = node.Runtime.Clock.GetUtcNow();
        var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: actor)
        {
            CellsOrigin = CenterRouting.CellsOrigin(actor, node.Runtime.NodeId.Span),
            RemoteCommandId = request.Meta.CommandId.Clone(),
            RawRequest = request.ToByteArray(),
            Routed = new RoutedContext(calls.Link, node.Runtime.Lifecycle, now.AddSeconds(30), TimeSpan.FromSeconds(15),
                node.Runtime.Clock, node.Runtime.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true),
        };
        var raw = await calls.Dispatcher.FileHandlerForTests!.WriteExistingCandidateAsync(caller, token);
        var reply = FileServiceWriteFileResponse.Parser.ParseFrom(raw);
        Assert.True(NodeShapes.IsValid(reply));
        Assert.Equal("enforcement_unavailable", reply.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, reply.Error.Effect);
        Assert.Equal(original, File.ReadAllBytes(path));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal;")));
    }
}
