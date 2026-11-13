// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual Node writer serialization and native named stages; callers are synthetic, not a real center.</summary>
public sealed class PrivateStageConcurrencyTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(RoutedMethod.ReadNodeFile)]
    [InlineData(RoutedMethod.SearchNodeFiles)]
    [InlineData(RoutedMethod.ListNodeDirectory)]
    public Task OldSnapshotFinishesBeforeProducerCreatesAndBinds(RoutedMethod method) => RunAsync(method, producerFirst: false, TestContext.Current.CancellationToken);

    [Theory(Timeout = 120_000)]
    [InlineData(RoutedMethod.ReadNodeFile)]
    [InlineData(RoutedMethod.SearchNodeFiles)]
    [InlineData(RoutedMethod.ListNodeDirectory)]
    public Task ReaderWaitsWhileReservedStageIsCreatedButNotBound(RoutedMethod method) => RunAsync(method, producerFirst: true, TestContext.Current.CancellationToken);

    private static async Task RunAsync(RoutedMethod method, bool producerFirst, CancellationToken ct)
    {
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var outer = Directory.CreateDirectory(Path.Combine(node.Root, "stage-race")).FullName;
        var inner = Directory.CreateDirectory(Path.Combine(outer, "nested")).FullName;
        var workspaces = new RegisteredWorkspaces(node.Runtime.Store);
        var readerWorkspace = workspaces.RegisterFromVerifiedHuman(outer, cancellationToken: ct);
        var producerWorkspace = workspaces.RegisterFromVerifiedHuman(inner, cancellationToken: ct);
        Assert.NotEqual(readerWorkspace.Id, producerWorkspace.Id);
        var body = Encoding.UTF8.GetBytes("unapproved-private-concurrent-7e208b");
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(producerWorkspace.Id) }, Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(body),
        };
        var raw = request.ToByteArray();
        var id = request.Meta.CommandId.Value.ToByteArray();
        var spec = new PrivateStageSpec(2, Path.Combine(inner, "stage"), body.Length, SHA256.HashData(body));
        Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t,
            new FileStageBudget(), FileOperationKind.Write, id, producerWorkspace.Id,
            request.Meta.CorrelationId.Value.Span, actor, raw, [spec]), CommitDurability.Full));
        Assert.Empty(node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities));
        using var root = WorkspacePath.OpenRoot(inner);
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = calls.Dispatcher.FileHandlerForTests!;
        Task<WorkspaceEmptyNamedStage>? producer = null;
        WorkspaceEmptyNamedStage? stage = null;
        var acquired = false;
        try
        {
            Task<(RoutedAnswer? Answer, long LogId)> pending;
            if (producerFirst)
            {
                producer = PrivateStageProducer.CreateBoundAsync(node.Runtime.Processor, id, 2, root, root, "stage", ct, () =>
                {
                    entered.TrySetResult();
                    if (!release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Owned producer coordination timed out.");
                });
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(3), ct);
                Assert.True(File.Exists(Path.Combine(inner, "stage")));
                pending = calls.CallAsync(actor, method, Request(method, readerWorkspace.Id, body).ToByteArray());
                Assert.NotSame(pending, await Task.WhenAny(pending, Task.Delay(200, ct)));
                release.Set();
                stage = await producer.WaitAsync(TimeSpan.FromSeconds(5), ct);
            }
            else
            {
                handler.AfterWorkspaceSnapshotForTests = () =>
                {
                    entered.TrySetResult();
                    if (!release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Owned read coordination timed out.");
                };
                pending = calls.CallAsync(actor, method, Request(method, readerWorkspace.Id, body).ToByteArray());
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(3), ct);
                producer = PrivateStageProducer.CreateBoundAsync(node.Runtime.Processor, id, 2, root, root, "stage", ct);
                Assert.NotSame(producer, await Task.WhenAny(producer, Task.Delay(200, ct)));
                Assert.False(File.Exists(Path.Combine(inner, "stage")));
                release.Set();
                var old = await pending.WaitAsync(TimeSpan.FromSeconds(5), ct);
                AssertPrivate(method, Assert.IsType<ByteString>(old.Answer?.Response), body);
                handler.AfterWorkspaceSnapshotForTests = null;
                stage = await producer.WaitAsync(TimeSpan.FromSeconds(5), ct);
            }
            acquired = true;
            Assert.Single(node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities));
            PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2, actor, raw, stage, body, ct);
            Assert.Equal(3L, node.Runtime.Store.Read(r => r.Scalar("SELECT phase FROM file_private_stage_object;")));
            stage.Dispose();
            stage = null;
            if (producerFirst)
            {
                var concurrent = await pending.WaitAsync(TimeSpan.FromSeconds(5), ct);
                AssertPrivate(method, Assert.IsType<ByteString>(concurrent.Answer?.Response), body);
            }

            foreach (var routedMethod in new[] { RoutedMethod.ReadNodeFile, RoutedMethod.SearchNodeFiles, RoutedMethod.ListNodeDirectory })
            {
                var after = await calls.CallAsync(actor, routedMethod, Request(routedMethod, readerWorkspace.Id, body).ToByteArray());
                AssertPrivate(routedMethod, Assert.IsType<ByteString>(after.Answer?.Response), body);
            }
        }
        finally
        {
            release.Set();
            handler.AfterWorkspaceSnapshotForTests = null;
            stage?.Dispose();
            if (!acquired && producer is not null)
            {
                try { using var orphan = await producer.WaitAsync(TimeSpan.FromSeconds(5), ct); }
                catch (Exception exception) when (exception is not OutOfMemoryException) { }
            }
        }
    }

    private static IMessage Request(RoutedMethod method, byte[] workspace, byte[] body)
    {
        var workspaceId = new Id { Value = ByteString.CopyFrom(workspace) };
        return method switch
        {
            RoutedMethod.ReadNodeFile => new FileServiceReadFileRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = workspaceId, Path = "nested/stage" },
                Offset = 0,
                Length = 128,
            },
            RoutedMethod.SearchNodeFiles => new FileServiceSearchFilesRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = workspaceId, Path = "" },
                Pattern = Encoding.UTF8.GetString(body),
                Mode = FileSearchMode.Literal,
            },
            RoutedMethod.ListNodeDirectory => new FileServiceListDirectoryRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = workspaceId, Path = "nested" },
            },
            _ => throw new ArgumentOutOfRangeException(nameof(method)),
        };
    }

    private static void AssertPrivate(RoutedMethod method, ByteString bytes, byte[] body)
    {
        Assert.Equal(-1, bytes.Span.IndexOf(body));
        switch (method)
        {
            case RoutedMethod.ReadNodeFile:
                var read = FileServiceReadFileResponse.Parser.ParseFrom(bytes);
                Assert.Null(read.Value);
                Assert.NotNull(read.Error);
                break;
            case RoutedMethod.SearchNodeFiles:
                var search = FileServiceSearchFilesResponse.Parser.ParseFrom(bytes);
                Assert.Null(search.Error);
                Assert.Empty(search.Value.Matches);
                break;
            case RoutedMethod.ListNodeDirectory:
                var list = FileServiceListDirectoryResponse.Parser.ParseFrom(bytes);
                Assert.Null(list.Error);
                Assert.DoesNotContain(list.Value.Entries, entry => entry.Name == "stage");
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(method));
        }
    }
}
