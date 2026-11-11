// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real native stages and SQLite combined accounting; routed callers and local HUMAN decisions are synthetic.</summary>
public sealed class FileStageCombinedCapacityTests
{
    [Fact(Timeout = 120_000)]
    public async Task SameCommandCountsOnceButDistinctNativeStagesAndHeldRecoveryBytesRemainCharged()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var caller = new RoutedCalls(node).Relay(Origin.Human);
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "combined-capacity")).FullName;
        var original = Encoding.UTF8.GetBytes("before");
        var intended = Encoding.UTF8.GetBytes("after!!");
        File.WriteAllBytes(Path.Combine(directory, "target"), original);
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(directory, cancellationToken: ct);
        using var root = WorkspacePath.OpenRoot(directory);
        var budget = node.Runtime.FileStages;
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" },
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original)),
            Data = ByteString.CopyFrom(intended),
        };
        var raw = request.ToByteArray();
        var id = request.Meta.CommandId.Value.ToByteArray();
        using var first = Assert.IsType<WorkspaceStagePair>(node.Runtime.Store.Write(t =>
            WorkspaceStagePair.TryCreateForCommand(root, budget, t, id, original, intended, ct), CommitDurability.Full));
        Assert.Equal((1, (long)(original.Length + intended.Length)), node.Runtime.Store.Read(budget.CombinedUsage));
        var rootId = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        var targetId = RegisteredWorkspaces.RootIdentity.Encode(root.InspectEntry("target").Identity, directory: false);
        var intent = new FileJournalIntent(FileOperationKind.Write, id, request.Meta.CorrelationId.Value.ToByteArray(), caller,
            workspace.Id, "target", rootId.Platform, rootId.Bytes, rootId.Bytes, targetId.Bytes,
            original.Length, SHA256.HashData(original), first.Original!.Identity.Bytes,
            intended.Length, SHA256.HashData(intended), first.Intended.Identity.Bytes);
        Assert.Equal(FileJournalPreparation.Prepared, node.Runtime.Store.Write(t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
        Assert.Equal((1, (long)(original.Length + intended.Length)), node.Runtime.Store.Read(budget.CombinedUsage));
        using var second = Assert.IsType<WorkspaceStagePair>(node.Runtime.Store.Write(t =>
            WorkspaceStagePair.TryCreateForCommand(root, budget, t, id, original, intended, ct), CommitDurability.Full));
        Assert.NotEqual(first.Original.Identity.Bytes, second.Original!.Identity.Bytes);
        Assert.NotEqual(first.Intended.Identity.Bytes, second.Intended.Identity.Bytes);
        Assert.Equal((1, 2L * (original.Length + intended.Length)), node.Runtime.Store.Read(budget.CombinedUsage));
        Assert.Equal(FileJournalPreparation.Existing, node.Runtime.Store.Write(t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
        _ = node.Runtime.Store.Write(t => FileMutationJournal.MarkUnknown(t, id), CommitDurability.Full);
        first.Dispose();
        second.Dispose();
        Assert.Equal((1, (long)(original.Length + intended.Length)), node.Runtime.Store.Read(budget.CombinedUsage));
        Assert.Equal(original, File.ReadAllBytes(Path.Combine(directory, "target")));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        budget = node.Runtime.FileStages;
        Assert.Equal((1, (long)(original.Length + intended.Length)), node.Runtime.Store.Read(budget.CombinedUsage));

        var named = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "other" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFromUtf8("n"),
        };
        var namedRaw = named.ToByteArray();
        var namedSpec = new PrivateStageSpec(2, Path.Combine(directory, "other-stage"), 1, SHA256.HashData("n"u8));
        PrivateStageReservationResult ReserveNamed(byte[] bytes, PrivateStageSpec spec) => node.Runtime.Store.Write(t =>
            PrivateStageRegistry.Reserve(t, budget, FileOperationKind.Write, named.Meta.CommandId.Value.Span, workspace.Id,
                named.Meta.CorrelationId.Value.Span, caller, bytes, [spec]), CommitDurability.Full);
        Assert.Equal(PrivateStageReservationResult.Reserved, ReserveNamed(namedRaw, namedSpec));
        Assert.Equal(PrivateStageReservationResult.Existing, ReserveNamed(namedRaw, namedSpec));
        var changed = named.Clone();
        changed.Data = ByteString.CopyFromUtf8("x");
        Assert.Equal(PrivateStageReservationResult.Conflict, ReserveNamed(changed.ToByteArray(),
            namedSpec with { ExpectedSha256 = SHA256.HashData("x"u8) }));
        Assert.Equal((2, (long)(original.Length + intended.Length + 1)), node.Runtime.Store.Read(budget.CombinedUsage));

        var leases = new List<FileStageBudget.Lease>();
        try
        {
            node.Runtime.Store.Write(t =>
            {
                for (var index = 0; index < 62; index++)
                    leases.Add(Assert.IsType<FileStageBudget.Lease>(budget.TryReserveCommand(t, CommandIds.New().Value.Span, 0, 0)));
                Assert.Equal(64, budget.CombinedUsage(t).Active);
                Assert.Null(budget.TryReserveCommand(t, CommandIds.New().Value.Span, 0, 0));
                using var sameCommandExtra = Assert.IsType<FileStageBudget.Lease>(budget.TryReserveCommand(t, id, 0, 1));
                Assert.Equal((64, (long)(original.Length + intended.Length + 2)), budget.CombinedUsage(t));
            }, CommitDurability.Full);
            var human = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli };
            Assert.Equal(FileJournalAcknowledgment.Acknowledged, node.Runtime.Store.Write(t =>
                FileMutationJournal.AcknowledgeFromVerifiedHuman(t, id, SHA256.HashData(raw), human), CommitDurability.Full));
            Assert.Equal(63, node.Runtime.Store.Read(budget.CombinedUsage).Active);
        }
        finally
        {
            foreach (var lease in leases) lease.Dispose();
        }
        Assert.Equal((1, 1L), node.Runtime.Store.Read(budget.CombinedUsage));
        Assert.Equal(original, File.ReadAllBytes(Path.Combine(directory, "target")));
    }

    [Fact(Timeout = 120_000)]
    public async Task ByteLimitRefusesBeforeNativeStageCreation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var path = Directory.CreateDirectory(Path.Combine(node.Root, "combined-bytes")).FullName;
        using var root = WorkspacePath.OpenRoot(path);
        var budget = node.Runtime.FileStages;
        var leases = new List<FileStageBudget.Lease>();
        try
        {
            node.Runtime.Store.Write(t =>
            {
                for (var index = 0; index < 32; index++)
                    leases.Add(Assert.IsType<FileStageBudget.Lease>(budget.TryReserveCommand(t, CommandIds.New().Value.Span,
                        FileStageBudget.MaximumFileBytes, FileStageBudget.MaximumFileBytes)));
                Assert.Equal((32, FileStageBudget.MaximumBytes), budget.CombinedUsage(t));
                var creationReached = false;
                var stage = WorkspaceStagePair.TryCreateForCommand(root, budget, t, CommandIds.New().Value.Memory,
                    original: null, new byte[] { 1 }, ct, () => creationReached = true);
                Assert.Null(stage);
                Assert.False(creationReached);
                Assert.Equal((32, FileStageBudget.MaximumBytes), budget.CombinedUsage(t));
            }, CommitDurability.Full);
        }
        finally
        {
            foreach (var lease in leases) lease.Dispose();
        }
        Assert.Equal((0, 0L), node.Runtime.Store.Read(budget.CombinedUsage));
    }

    [Fact(Timeout = 120_000)]
    public async Task ConcurrentDistinctCommandsCannotReserveMoreThanSixtyFour()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var budget = node.Runtime.FileStages;
        var leases = new ConcurrentBag<FileStageBudget.Lease>();
        var tasks = Enumerable.Range(0, 80).Select(_ => Task.Run(() =>
        {
            var id = CommandIds.New().Value.ToByteArray();
            var lease = node.Runtime.Store.Write(t => budget.TryReserveCommand(t, id, 0, 0), CommitDurability.Full);
            if (lease is not null) leases.Add(lease);
        }, ct)).ToArray();
        try
        {
            await Task.WhenAll(tasks);
            Assert.Equal(64, leases.Count);
            Assert.Equal((64, 0L), node.Runtime.Store.Read(budget.CombinedUsage));
        }
        finally
        {
            foreach (var lease in leases) lease.Dispose();
        }
        Assert.Equal((0, 0L), node.Runtime.Store.Read(budget.CombinedUsage));
    }
}
