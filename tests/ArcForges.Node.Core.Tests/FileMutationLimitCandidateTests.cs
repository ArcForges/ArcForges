// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
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
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "mutation-limits-fixture" });
        using var log = new NodeLog(Path.Combine(fixture.DataRoot, "logs", "node"), LogLevel.Info, fixture.Clock);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        using var node = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(fixture.ConfigPath, fixture.DataRoot, log), fixture.DataRoot, "offline-fixture", fixture.Clock,
            new RecoveryReport(false, false, null, store.Opening), new CapabilityReport());
        using var handler = new FileServiceHandler(node);
        var actor = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = RoutedCalls.Account.Clone(),
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(node.NodeId.Span) },
            LocalOrigin = Origin.Human,
            LocalSessionId = CommandIds.New(),
        };
        var workspace = CommandIds.New();

        NodeFilePath PathValue(string path) => new()
        {
            WorkspaceId = workspace.Clone(),
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
            var now = node.Clock.GetUtcNow();
            var routed = new RoutedContext(new RoutedCalls.TestLink(), node.Lifecycle, now.AddSeconds(30), TimeSpan.FromSeconds(15),
                node.Clock, node.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
            var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: actor.Clone())
            {
                CellsOrigin = CenterRouting.CellsOrigin(actor, node.NodeId.Span),
                RemoteCommandId = meta.CommandId.Clone(),
                RawRequest = request.ToByteArray(),
                Routed = routed,
            };
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
        Assert.True(NodeShapes.IsValid(boundedResponse));
        Assert.Equal(ErrorCategory.Execution, boundedResponse.Error.Category);
        Assert.Equal("operation_failed", boundedResponse.Error.Code);
        Assert.Equal("file_outcome_unknown", boundedResponse.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, boundedResponse.Error.Effect);
        Assert.Equal(RetryMode.Never, boundedResponse.Error.Retry.Mode);
        Assert.Equal(atLimit.Meta.CorrelationId, boundedResponse.Error.CorrelationId);
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM file_private_stage_reservation;")));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        foreach (var database in new[] { store.DatabasePath, store.DatabasePath + "-wal" })
        {
            if (!File.Exists(database)) continue;
            using var file = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            file.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(Enumerable.Repeat((byte)0x5a, 128).ToArray()));
        }
    }
}
