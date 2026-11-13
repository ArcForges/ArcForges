// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>In-process refusal never establishes a producer reservation to recover.
/// PrivateStageTerminalTests separately exercises the real FULL writer/producer fence and retained-slot capacity;
/// FileStageProducerHostTests covers actual Host producer restart and approval.</summary>
public sealed class RoutedFileApprovalRecoveryTests
{
    [Fact(Timeout = 120_000)]
    public async Task InProcessRefusalLeavesNoProducerReservationForRecoveryToAdopt()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "routed-fence")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(directory, cancellationToken: ct);
        var request = Request(workspace.Id);
        var handler = calls.Dispatcher.FileHandlerForTests!;
        var reachedReservation = false;
        handler.AfterApprovalReservationForTests = () =>
        {
            reachedReservation = true;
            return Task.FromException(new IOException("an in-process request must not reserve a Host producer"));
        };
        try
        {
            var error = await Refusal(calls, caller, request);
            Assert.False(reachedReservation);
            Assert.Equal(0, node.Runtime.Store.Write(PrivateStageTerminal.RecoverUnraised, CommitDurability.Full));
            Assert.Equal((0, 0L), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_terminal;")));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal;")));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM approval;")));
            Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, request.Meta.CommandId.Value.Span, caller)));
            Assert.Empty(Directory.EnumerateFileSystemEntries(directory));
            Assert.Equal(error, await Refusal(calls, caller, request));
            Assert.Equal(0, await node.StopAsync());
            await node.StartAsync();
            Assert.Equal(error, await Refusal(new RoutedCalls(node), caller, request));
            Assert.Equal((0, 0L), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
            Assert.Empty(Directory.EnumerateFileSystemEntries(directory));
        }
        finally { handler.AfterApprovalReservationForTests = null; }
    }

    [Fact(Timeout = 180_000)]
    public async Task SixtyFiveNonHostRefusalsConsumeNoProducerSlotsOrRetainedBytes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "routed-failure-capacity")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(directory, cancellationToken: ct);
        for (var index = 0; index < 65; index++)
            _ = await Refusal(calls, caller, Request(workspace.Id));
        Assert.Equal((0, 0L), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        foreach (var table in new[] { "file_private_stage_reservation", "file_private_stage_object", "file_private_stage_terminal", "file_operation_journal", "approval", "command_dedup" })
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM " + table + ";")));
        Assert.Empty(Directory.EnumerateFileSystemEntries(directory));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        _ = await Refusal(new RoutedCalls(node), caller, Request(workspace.Id));
        Assert.Equal((0, 0L), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Empty(Directory.EnumerateFileSystemEntries(directory));
    }

    private static async Task<ArcError> Refusal(RoutedCalls calls, CenterCaller caller, FileServiceWriteFileRequest request)
    {
        var dispatched = await calls.CallAsync(caller, RoutedMethod.WriteNodeFile, request.ToByteArray(), request.Meta.CommandId);
        Assert.NotNull(dispatched.Answer);
        Assert.Equal(RoutedOutcome.Executed, dispatched.Answer.Outcome);
        var response = FileServiceWriteFileResponse.Parser.ParseFrom(dispatched.Answer.Response);
        Assert.Equal("enforcement_unavailable", response.Error.Code);
        Assert.Equal("file_guard_unavailable", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(request.Meta.CorrelationId, response.Error.CorrelationId);
        return response.Error;
    }

    private static FileServiceWriteFileRequest Request(byte[] workspace) => new()
    {
        Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
        Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = "target" },
        ExpectedAbsent = true,
        Data = ByteString.CopyFrom(Encoding.UTF8.GetBytes("routed-failure-intended-63ac")),
    };
}
