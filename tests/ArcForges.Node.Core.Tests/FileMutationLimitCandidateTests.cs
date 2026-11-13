// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Request-bound refusals in the internal candidate; the caller and transport are isolated test substitutes.</summary>
public sealed class FileMutationLimitCandidateTests
{
    [Fact(Timeout = 120_000)]
    public async Task DecodableOversizedMutationRequestsReturnTheirActualResourceLimitWithoutFileEffects()
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "mutation-limits")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        var target = Path.Combine(root, "target.txt");
        var initial = Encoding.UTF8.GetBytes("request-limit-fixture-a93b");
        File.WriteAllBytes(target, initial);

        NodeFilePath PathValue(string path) => new()
        {
            WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) },
            Path = path,
        };
        FileServiceWriteFileRequest Write(int count) => new()
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = PathValue("target.txt"),
            Data = ByteString.CopyFrom(Enumerable.Repeat((byte)0x5a, count).ToArray()),
            ExpectedSha256 = ByteString.CopyFrom(new byte[32]),
        };
        FileServiceEditFileRequest Edit(string oldText, string newText) => new()
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = PathValue("target.txt"),
            OldText = oldText,
            NewText = newText,
            ExpectedOccurrences = 1,
            ExpectedSha256 = ByteString.CopyFrom(new byte[32]),
        };
        async Task<byte[]> Invoke(IMessage request)
        {
            var meta = request switch
            {
                FileServiceWriteFileRequest write => write.Meta,
                FileServiceEditFileRequest edit => edit.Meta,
                _ => throw new InvalidOperationException(),
            };
            var now = node.Runtime.Clock.GetUtcNow();
            var routed = new RoutedContext(calls.Link, node.Runtime.Lifecycle, now.AddSeconds(30), TimeSpan.FromSeconds(15),
                node.Runtime.Clock, node.Runtime.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
            var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: actor.Clone())
            {
                CellsOrigin = CenterRouting.CellsOrigin(actor, node.Runtime.NodeId.Span),
                RemoteCommandId = meta.CommandId.Clone(),
                RawRequest = request.ToByteArray(),
                Routed = routed,
            };
            var handler = calls.Dispatcher.FileHandlerForTests!;
            return (request is FileServiceWriteFileRequest
                ? await handler.WriteExistingCandidateAsync(caller, token)
                : await handler.EditExistingCandidateAsync(caller, token))!;
        }
        static void Limit(ArcError error, string name, string maximum, Id correlation)
        {
            Assert.Equal(ErrorCategory.Resource, error.Category);
            Assert.Equal("too_large", error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
            Assert.Equal(RetryMode.Never, error.Retry.Mode);
            Assert.Equal(name, error.Details.Limit.LimitName);
            Assert.Equal(maximum, error.Details.Limit.Maximum.Value);
            Assert.Equal(correlation, error.CorrelationId);
        }

        var oversizedWrite = Write(196_609);
        Assert.False(NodeShapes.IsValid(oversizedWrite)); // actual published 450.1 shape includes the bound
        var writeResponse = FileServiceWriteFileResponse.Parser.ParseFrom(await Invoke(oversizedWrite));
        Assert.True(NodeShapes.IsValid(writeResponse));
        Limit(writeResponse.Error, "file_write_bytes", "196608", oversizedWrite.Meta.CorrelationId);

        var oversizedOld = Edit(new string('é', 32_769), "new");
        Assert.False(NodeShapes.IsValid(oversizedOld));
        var oldResponse = FileServiceEditFileResponse.Parser.ParseFrom(await Invoke(oversizedOld));
        Assert.True(NodeShapes.IsValid(oldResponse));
        Limit(oldResponse.Error, "file_edit_text_bytes", "65536", oversizedOld.Meta.CorrelationId);

        var oversizedNew = Edit("old", new string('x', 65_537));
        var newResponse = FileServiceEditFileResponse.Parser.ParseFrom(await Invoke(oversizedNew));
        Assert.True(NodeShapes.IsValid(newResponse));
        Limit(newResponse.Error, "file_edit_text_bytes", "65536", oversizedNew.Meta.CorrelationId);

        var oversizedPath = Write(1);
        oversizedPath.Path.Path = string.Concat(Enumerable.Repeat("a/", 2_048)) + "b";
        var pathResponse = FileServiceWriteFileResponse.Parser.ParseFrom(await Invoke(oversizedPath));
        Assert.True(NodeShapes.IsValid(pathResponse));
        Limit(pathResponse.Error, "path_bytes", "4096", oversizedPath.Meta.CorrelationId);

        var malformed = Write(196_609);
        malformed.ExpectedSha256 = ByteString.CopyFrom(new byte[31]);
        var malformedResponse = FileServiceWriteFileResponse.Parser.ParseFrom(await Invoke(malformed));
        Assert.Equal(ErrorCategory.Validation, malformedResponse.Error.Category);
        Assert.Equal("invalid_argument", malformedResponse.Error.Code);

        var malformedPath = Write(1);
        malformedPath.Path.Path = "../" + string.Concat(Enumerable.Repeat("a/", 2_048)) + "b";
        var malformedPathResponse = FileServiceWriteFileResponse.Parser.ParseFrom(await Invoke(malformedPath));
        Assert.Equal(ErrorCategory.Validation, malformedPathResponse.Error.Category);
        Assert.Equal("invalid_argument", malformedPathResponse.Error.Code);

        var atLimit = Write(196_608);
        Assert.True(NodeShapes.IsValid(atLimit));
        var boundedResponse = FileServiceWriteFileResponse.Parser.ParseFrom(await Invoke(atLimit));
        Assert.NotEqual("too_large", boundedResponse.Error.Code); // Windows: hash conflict; Linux: guard refusal
        Assert.Equal(EffectCertainty.DidNotHappen, boundedResponse.Error.Effect);
        Assert.Equal(initial, File.ReadAllBytes(target));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        foreach (var database in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(database)) continue;
            using var file = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            file.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(Enumerable.Repeat((byte)0x5a, 128).ToArray()));
        }
    }
}
