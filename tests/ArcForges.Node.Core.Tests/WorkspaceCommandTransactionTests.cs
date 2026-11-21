// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real SQLite and command processor; the registry is not yet represented as an RPC or a center end-to-end test here.</summary>
[Trait("feature", "workspace-command-transaction")]
public sealed class WorkspaceCommandTransactionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 120_000)]
    public async Task RegistrationAndCommandReceiptCommitOrRollBackTogetherAndReplayExactly()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = InProcessNode.Create();
        using var store = OpenHistory(fixture);
        await using var processor = new CommandProcessor(store, EventJournal.Open(store), new StreamHub());
        var manager = new RegisteredWorkspaces(store);
        var path = Directory.CreateDirectory(Path.Combine(fixture.Root, "registered")).FullName;
        var commandId = InProcessNode.Command().CommandId.Value.ToByteArray();
        var digest = SHA256.HashData("registration request"u8);
        using var prepared = manager.PrepareRegistration(path, cancellationToken: Ct);

        // Fail after the actual workspace INSERT, before dedup completion; SQLite must roll both back.
        await Assert.ThrowsAsync<InvalidOperationException>(() => processor.ExecuteIdempotentAsync(commandId,
            "WorkspaceService/RegisterWorkspace", digest, Origin.Human, command =>
            {
                _ = manager.RegisterPreparedFromVerifiedHuman(command.Transaction, prepared, cancellationToken: Ct);
                throw new InvalidOperationException("test-owned fault after registration insert");
            }));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace;")));
        Assert.Equal(0L, store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id=$id;", ("$id", commandId))));

        var first = await processor.ExecuteIdempotentAsync(commandId, "WorkspaceService/RegisterWorkspace", digest, Origin.Human,
            command => manager.RegisterPreparedFromVerifiedHuman(command.Transaction, prepared, cancellationToken: Ct).Id);
        Assert.Null(first.Error);
        Assert.False(first.Replayed);
        Assert.NotNull(first.Outcome);
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        Assert.Equal(1L, store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id=$id AND outcome IS NOT NULL;", ("$id", commandId))));

        var replay = await processor.ExecuteIdempotentAsync(commandId, "WorkspaceService/RegisterWorkspace", digest, Origin.Human,
            _ => throw new InvalidOperationException("a replay must not execute"));
        Assert.True(replay.Replayed);
        Assert.Equal(first.Outcome, replay.Outcome);
        var different = await processor.ExecuteIdempotentAsync(commandId, "WorkspaceService/RegisterWorkspace",
            SHA256.HashData("different request"u8), Origin.Human, _ => throw new InvalidOperationException("conflict must not execute"));
        Assert.Equal("command_id_reused", different.Error?.Code);
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
    }

    [Fact(Timeout = 120_000)]
    public async Task DuplicateRegistrationRechecksBeforeReturningAndRecordingAReceipt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = InProcessNode.Create();
        using var store = OpenHistory(fixture);
        await using var processor = new CommandProcessor(store, EventJournal.Open(store), new StreamHub());
        var manager = new RegisteredWorkspaces(store);
        var path = Directory.CreateDirectory(Path.Combine(fixture.Root, "duplicate")).FullName;
        var existing = manager.RegisterFromVerifiedHuman(path, cancellationToken: Ct);
        using var prepared = manager.PrepareRegistration(path, cancellationToken: Ct);
        var id = InProcessNode.Command().CommandId.Value.ToByteArray();
        await Assert.ThrowsAsync<InvalidOperationException>(() => processor.ExecuteIdempotentAsync(id,
            "WorkspaceService/RegisterWorkspace", SHA256.HashData("duplicate"u8), Origin.Human, command =>
            {
                _ = manager.RegisterPreparedFromVerifiedHuman(command.Transaction, prepared,
                    beforeEffect: () => throw new InvalidOperationException("pre-effect refused"), cancellationToken: Ct);
                return Array.Empty<byte>();
            }));
        Assert.Equal(0L, store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id=$id;", ("$id", id))));
        Assert.Equal(existing.Id, manager.Get(existing.Id, Ct).Id);
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
    }

    [Fact(Timeout = 120_000)]
    public async Task UseLeaseAndQueuedUnregisterHaveOneLockOrderAndRealReceipt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = InProcessNode.Create();
        using var store = OpenHistory(fixture);
        await using var processor = new CommandProcessor(store, EventJournal.Open(store), new StreamHub());
        var manager = new RegisteredWorkspaces(store);
        var path = Directory.CreateDirectory(Path.Combine(fixture.Root, "root")).FullName;
        File.WriteAllText(Path.Combine(path, "marker"), "unchanged");
        var workspace = manager.RegisterFromVerifiedHuman(path, cancellationToken: Ct);
        using var held = manager.OpenForUse(workspace.Id, Ct);
        var open = Task.Run(() => manager.OpenForUse(workspace.Id, Ct), Ct);
        var commandId = InProcessNode.Command().CommandId.Value.ToByteArray();
        var digest = SHA256.HashData("unregister while used"u8);
        var unregister = processor.ExecuteIdempotentAsync(commandId, "WorkspaceService/UnregisterWorkspace", digest, Origin.Human,
            command =>
            {
                try
                {
                    manager.UnregisterPreparedFromVerifiedHuman(command.Transaction, workspace.Id, cancellationToken: Ct);
                    return Encoding.UTF8.GetBytes("unexpected-success");
                }
                catch (RegisteredWorkspaceException error)
                {
                    return Encoding.UTF8.GetBytes(error.Reason);
                }
            });
        using var anotherUse = await open.WaitAsync(TimeSpan.FromSeconds(15), Ct);
        var refused = await unregister.WaitAsync(TimeSpan.FromSeconds(15), Ct);
        Assert.Equal("workspace_in_use", Encoding.UTF8.GetString(refused.Outcome!));
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        Assert.Equal("unchanged", File.ReadAllText(Path.Combine(path, "marker")));
        held.Dispose();
        anotherUse.Dispose();

        var removeId = InProcessNode.Command().CommandId.Value.ToByteArray();
        var removed = await processor.ExecuteIdempotentAsync(removeId, "WorkspaceService/UnregisterWorkspace",
            SHA256.HashData("remove"u8), Origin.Human, command =>
            {
                manager.UnregisterPreparedFromVerifiedHuman(command.Transaction, workspace.Id, cancellationToken: Ct);
                return Encoding.UTF8.GetBytes("removed");
            });
        Assert.Equal("removed", Encoding.UTF8.GetString(removed.Outcome!));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        Assert.Equal("unchanged", File.ReadAllText(Path.Combine(path, "marker")));
    }

    private static NodeStore OpenHistory(InProcessNode fixture) => NodeStore.Open(new NodeStoreOptions
    {
        DataRoot = fixture.DataRoot,
        BootIdentity = "workspace-command-history",
    }, StoreMigrations.Expanded);
}
