// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
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

/// <summary>Owned routed producer races on Windows, through a synthetic post-verification seam, not a real center.</summary>
public sealed class RoutedFileApprovalRecoveryTests
{
    [Fact(Timeout = 120_000)]
    public async Task CancelledRoutedProducerCannotResumeAfterRecoveryFencesItsReservation()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Windows named approval producer; Linux guard is not yet available.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var foreign = calls.Relay(Origin.Script);
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "routed-fence")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(directory, cancellationToken: ct);
        var request = Request(workspace.Id);
        var raw = request.ToByteArray();
        var id = request.Meta.CommandId.Value.ToByteArray();
        var handler = calls.Dispatcher.FileHandlerForTests!;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.AfterApprovalReservationForTests = async () =>
        {
            entered.TrySetResult();
            await release.Task.ConfigureAwait(false);
        };
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        try
        {
            var dispatched = calls.CallAsync(caller, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId, cancellationToken: cancellation.Token);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            var producer = Assert.IsAssignableFrom<Task>(handler.LastApprovalProducerForTests);
            Assert.False(producer.IsCompleted);
            Assert.Equal((1, (long)request.Data.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await dispatched.WaitAsync(TimeSpan.FromSeconds(5), ct));
            Assert.False(producer.IsCompleted); // A returned/cancelled caller did not prove physical producer completion.

            // The same startup recovery writer races an actually still-running old producer.
            Assert.Equal(1, node.Runtime.Store.Write(PrivateStageTerminal.RecoverUnraised, CommitDurability.Full));
            Assert.Equal((0, (long)request.Data.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
            Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_terminal;")));
            release.TrySetResult();
            await producer.WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.Empty(Directory.EnumerateFiles(directory));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_object WHERE phase <> 1;")));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal;")));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM approval WHERE command_id = $id;", ("$id", id))));

            var replay = await calls.CallAsync(caller, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId);
            var response = FileServiceWriteFileResponse.Parser.ParseFrom(replay.Answer!.Response);
            Assert.Equal("invalid_state", response.Error.Code);
            Assert.Equal("file_preparation_abandoned", response.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
            Assert.Equal(request.Meta.CorrelationId, response.Meta.CorrelationId);
            Assert.Equal(request.Meta.CorrelationId, response.Error.CorrelationId);
            var errorAudit = node.Runtime.Store.Read(r => r.Scalar("""
                SELECT count(*) FROM audit_log WHERE remote_command_id = $id AND decision = $deny AND outcome_summary = 'replayed: invalid_state';
                """, ("$id", id), ("$deny", (int)PermissionDecision.Deny)));
            Assert.Equal(1L, errorAudit);

            var different = request.Clone();
            different.Data = ByteString.CopyFromUtf8("different-intended");
            var conflict = await calls.CallAsync(caller, RoutedMethod.WriteNodeFile, different.ToByteArray(), request.Meta.CommandId);
            Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(conflict.Answer!.Response).Error.Code);
            var crossed = await calls.CallAsync(foreign, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId);
            Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(crossed.Answer!.Response).Error.Code);
            Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, foreign)));
            var operation = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller))!;
            Assert.Equal(FileOperationState.Completed, operation.State);
            Assert.Equal(SHA256.HashData(raw), operation.RequestSha256.ToByteArray());
            Assert.False(operation.Held);
            Assert.Equal(0, await node.StopAsync());
            await node.StartAsync();
            var afterRestart = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller))!;
            Assert.Equal(FileOperationState.Completed, afterRestart.State);
            Assert.Equal("file_preparation_abandoned", afterRestart.Error.Details.State.Reason);
            Assert.Empty(Directory.EnumerateFiles(directory));
        }
        finally
        {
            release.TrySetResult();
            handler.AfterApprovalReservationForTests = null;
        }
    }

    [Fact(Timeout = 180_000)]
    public async Task SixtyFiveFailedRoutedProducersDoNotPermanentlyExhaustActiveSlots()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Windows named approval producer; Linux guard is not yet available.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "routed-failure-capacity")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(directory, cancellationToken: ct);
        var handler = calls.Dispatcher.FileHandlerForTests!;
        handler.AfterApprovalReservationForTests = () => Task.FromException(new IOException("owned producer failure after reservation"));
        var ids = new List<byte[]>();
        var bodyLength = 0;
        for (var index = 0; index < 65; index++)
        {
            var request = Request(workspace.Id);
            var raw = request.ToByteArray();
            bodyLength = request.Data.Length;
            var result = await calls.CallAsync(caller, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId);
            Assert.Null(result.Answer); // An ended producer is not a fabricated signed reply.
            Assert.True(handler.LastApprovalProducerForTests!.IsCompleted);
            var id = request.Meta.CommandId.Value.ToByteArray();
            ids.Add(id);
            var operation = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller))!;
            Assert.Equal(FileOperationState.Completed, operation.State);
            Assert.Equal("file_preparation_abandoned", operation.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, operation.Error.Effect);
            Assert.Equal(SHA256.HashData(raw), operation.RequestSha256.ToByteArray());
        }

        Assert.Equal((0, (long)bodyLength * 65), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Equal(65L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_terminal;")));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.AfterApprovalReservationForTests = async () =>
        {
            entered.TrySetResult();
            await release.Task.ConfigureAwait(false);
            throw new IOException("owned final producer failure");
        };
        try
        {
            var next = Request(workspace.Id);
            var pending = calls.CallAsync(caller, RoutedMethod.WriteNodeFile, next.ToByteArray(), next.Meta.CommandId);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.Equal((1, (long)bodyLength * 66), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
            release.TrySetResult();
            Assert.Null((await pending.WaitAsync(TimeSpan.FromSeconds(10), ct)).Answer);
            Assert.Equal((0, (long)bodyLength * 66), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        }
        finally { release.TrySetResult(); handler.AfterApprovalReservationForTests = null; }
        Assert.Empty(Directory.EnumerateFiles(directory));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM approval;")));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        Assert.All(ids, id => Assert.Equal(FileOperationState.Completed,
            node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller))!.State));
        Assert.Equal((0, (long)bodyLength * 66), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Empty(Directory.EnumerateFiles(directory));
    }

    private static FileServiceWriteFileRequest Request(byte[] workspace) => new()
    {
        Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
        Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = "target" },
        ExpectedAbsent = true,
        Data = ByteString.CopyFrom(Encoding.UTF8.GetBytes("routed-failure-intended-63ac")),
    };
}
