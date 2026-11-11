// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual internal create candidate and SQLite on owned Windows files; the routed caller is synthetic.</summary>
public sealed class FileCreateCandidateTests
{
    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task WindowsCreateWritesOnceRecordsCollisionAndHoldsAnInterruptedCreation()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native expected-absent candidate."); return; }
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "create-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        var body = Encoding.UTF8.GetBytes("actual-create-private-body-7a239b");
        FileServiceWriteFileRequest Request(string path) => new()
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = path },
            Data = ByteString.CopyFrom(body),
            ExpectedAbsent = true,
        };
        async Task<byte[]?> Invoke(FileServiceWriteFileRequest request)
        {
            var raw = request.ToByteArray();
            var now = node.Runtime.Clock.GetUtcNow();
            var routed = new RoutedContext(calls.Link, node.Runtime.Lifecycle, now.AddSeconds(30), TimeSpan.FromSeconds(15),
                node.Runtime.Clock, node.Runtime.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
            var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: actor.Clone())
            {
                CellsOrigin = CenterRouting.CellsOrigin(actor, node.Runtime.NodeId.Span),
                RemoteCommandId = request.Meta.CommandId.Clone(),
                RawRequest = raw,
                Routed = routed,
            };
            return await calls.Dispatcher.FileHandlerForTests!.WriteExistingCandidateAsync(caller, token);
        }
        var handler = calls.Dispatcher.FileHandlerForTests!;
        var create = Request("created.txt");
        var createdPath = Path.Combine(root, create.Path.Path);
        Assert.False(File.Exists(createdPath));
        var responseBytes = await Invoke(create);
        var response = FileServiceWriteFileResponse.Parser.ParseFrom(responseBytes);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Null(response.Error);
        Assert.Equal(create.Meta.CommandId, response.Value.Result.CommandId);
        Assert.Equal(create.Meta.CorrelationId, response.Meta.CorrelationId);
        Assert.Equal((ulong)body.Length, response.Value.Result.SizeBytes);
        Assert.Equal(SHA256.HashData(body), response.Value.Result.Sha256.ToByteArray());
        Assert.Equal(body, File.ReadAllBytes(createdPath));
        Assert.True((File.GetAttributes(createdPath) & FileAttributes.Archive) != 0);
        var completed = node.Runtime.Store.Read(reader =>
            FileMutationJournal.GetForCaller(reader, create.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Completed, completed!.State);
        Assert.Equal(SHA256.HashData(create.ToByteArray()), completed.RequestSha256.ToByteArray());
        Assert.False(completed.Held);

        var external = Encoding.UTF8.GetBytes("later-other-file-data");
        File.WriteAllBytes(createdPath, external);
        Assert.Equal(responseBytes, await Invoke(create));
        Assert.Equal(external, File.ReadAllBytes(createdPath));

        var collision = Request("raced.txt");
        var collisionPath = Path.Combine(root, collision.Path.Path);
        handler.BeforeCreateForTests = () =>
        {
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Tasks.TestLoad,
                ["hold", "--hold-ms", "0", "--file", collisionPath])
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            }) ?? throw new InvalidOperationException("The owned competitor did not start.");
            try
            {
                Assert.True(process.WaitForExit(5_000), "The owned competing create did not finish.");
                Assert.Equal(0, process.ExitCode);
            }
            finally
            {
                if (!process.HasExited)
                {
                    process.Kill();
                    process.WaitForExit();
                }
            }
        };
        byte[]? collisionBytes;
        try { collisionBytes = await Invoke(collision); }
        finally { handler.BeforeCreateForTests = null; }
        var conflict = FileServiceWriteFileResponse.Parser.ParseFrom(collisionBytes);
        Assert.True(NodeShapes.IsValid(conflict));
        Assert.Equal("file_changed", conflict.Error.Code);
        Assert.Equal("expected_absent_conflict", conflict.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, conflict.Error.Effect);
        Assert.Equal(RetryMode.Never, conflict.Error.Retry.Mode);
        Assert.Equal(collision.Meta.CorrelationId, conflict.Error.CorrelationId);
        Assert.Equal("ready", File.ReadAllText(collisionPath));
        var collisionStatus = node.Runtime.Store.Read(reader =>
            FileMutationJournal.GetForCaller(reader, collision.Meta.CommandId.Value.Span, actor));
        Assert.True(NodeShapes.IsValid(collisionStatus));
        Assert.Equal(FileOperationState.Completed, collisionStatus!.State);
        Assert.False(collisionStatus.Held);
        Assert.Equal("expected_absent_conflict", collisionStatus.Error.Details.State.Reason);
        Assert.Equal(collision.Meta.CorrelationId, collisionStatus.Error.CorrelationId);
        Assert.Equal(SHA256.HashData(collision.ToByteArray()), collisionStatus.RequestSha256.ToByteArray());
        File.Delete(collisionPath);
        Assert.Equal(collisionBytes, await Invoke(collision));
        Assert.False(File.Exists(collisionPath));

        var interrupted = Request("interrupted.txt");
        var interruptedPath = Path.Combine(root, interrupted.Path.Path);
        handler.AfterCreateForTests = () => throw new IOException("test interruption after real create");
        byte[]? unknownBytes;
        try { unknownBytes = await Invoke(interrupted); }
        finally { handler.AfterCreateForTests = null; }
        var uncertain = FileServiceWriteFileResponse.Parser.ParseFrom(unknownBytes);
        Assert.True(NodeShapes.IsValid(uncertain));
        Assert.Equal("file_outcome_unknown", uncertain.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, uncertain.Error.Effect);
        Assert.Equal(RetryMode.Never, uncertain.Error.Retry.Mode);
        Assert.Equal(interrupted.Meta.CorrelationId, uncertain.Error.CorrelationId);
        Assert.True(File.Exists(interruptedPath)); // the empty object was actually created before the injected interruption
        Assert.Empty(File.ReadAllBytes(interruptedPath));
        var held = node.Runtime.Store.Read(reader =>
            FileMutationJournal.GetForCaller(reader, interrupted.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Unknown, held!.State);
        Assert.True(held.Held);
        var blocked = Request("blocked.txt");
        var blockedResponse = FileServiceWriteFileResponse.Parser.ParseFrom(await Invoke(blocked));
        Assert.Equal("invalid_state", blockedResponse.Error.Code);
        Assert.Equal("file_recovery_pending", blockedResponse.Error.Details.State.Reason);
        Assert.False(File.Exists(Path.Combine(root, blocked.Path.Path)));

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var afterRestart = node.Runtime.Store.Read(reader =>
            FileMutationJournal.GetForCaller(reader, interrupted.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Unknown, afterRestart!.State);
        Assert.True(afterRestart.Held);
        Assert.Equal(unknownBytes, await Invoke(interrupted));
        Assert.Empty(File.ReadAllBytes(interruptedPath));
        // The in-process interactive peer is a synthetic HUMAN; the endpoint and SQLite acknowledgment are real.
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            var ack = new FileServiceAcknowledgeFileOperationRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                OperationCommandId = interrupted.Meta.CommandId.Clone(),
                OperationDigest = ByteString.CopyFrom(SHA256.HashData(interrupted.ToByteArray())),
            };
            var acknowledged = await human.Files.AcknowledgeFileOperationAsync(ack, cancellationToken: token);
            Assert.Null(acknowledged.Error);
            Assert.True(acknowledged.Value.Operation.Acknowledged);
            Assert.False(acknowledged.Value.Operation.Held);
            Assert.Equal(FileOperationState.Unknown, acknowledged.Value.Operation.State);
        }
        Assert.Empty(File.ReadAllBytes(interruptedPath));

        foreach (var database in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(database)) continue;
            using var file = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            file.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(body));
        }
    }
}
