// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

/// <summary>Retained Task ownership and native workspace identities without starting a Node or a Task.</summary>
[Trait("feature", "workspace-submit-registry")]
public sealed class WorkspaceSubmitRegistryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RetainedTaskHoldsItsOriginalWorkspaceWhenNestedRegistrationChanges(bool registerChild)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "workspace-history-fixture" });
        var manager = new RegisteredWorkspaces(store);
        var parent = Directory.CreateDirectory(Path.Combine(fixture.Root, "parent"));
        var child = parent.CreateSubdirectory("child");
        var marker = Path.Combine(child.FullName, "preserved");
        File.WriteAllText(marker, "owned data");
        var original = manager.RegisterFromVerifiedHuman(parent.FullName, cancellationToken: ct);
        var task = SeedRetainedTask(store, original, TaskState.Queued);

        if (registerChild)
        {
            var nested = manager.RegisterFromVerifiedHuman(child.FullName, cancellationToken: ct);
            manager.UnregisterFromVerifiedHuman(nested.Id, ct);
        }

        Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(
            () => manager.UnregisterFromVerifiedHuman(original.Id, ct)).Reason);
        AssertRetainedTask(store, task, original, TaskState.Queued);

        store.Write(transaction => Assert.Equal(1, transaction.Execute(
            "UPDATE task SET state = $state WHERE task_id = $task;",
            ("$state", (int)TaskState.Cancelled), ("$task", task))), CommitDurability.Full);
        manager.UnregisterFromVerifiedHuman(original.Id, ct);

        AssertRetainedTask(store, task, original, TaskState.Cancelled);
        Assert.Equal("owned data", File.ReadAllText(marker));
    }

    [Fact]
    public async Task ReleasedChildHistoryIsNeverReassignedToItsParentOrReplacement()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "workspace-history-fixture" });
        var manager = new RegisteredWorkspaces(store);
        var parent = Directory.CreateDirectory(Path.Combine(fixture.Root, "parent"));
        var child = parent.CreateSubdirectory("child");
        var marker = Path.Combine(child.FullName, "preserved");
        File.WriteAllText(marker, "owned data");
        var enclosing = manager.RegisterFromVerifiedHuman(parent.FullName, cancellationToken: ct);
        var original = manager.RegisterFromVerifiedHuman(child.FullName, cancellationToken: ct);
        var task = SeedRetainedTask(store, original, TaskState.Cancelled);

        manager.UnregisterFromVerifiedHuman(original.Id, ct);
        var replacement = manager.RegisterFromVerifiedHuman(child.FullName, cancellationToken: ct);
        Assert.False(original.Id.AsSpan().SequenceEqual(replacement.Id));
        manager.UnregisterFromVerifiedHuman(replacement.Id, ct);
        manager.UnregisterFromVerifiedHuman(enclosing.Id, ct);

        Assert.Equal(1L, store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM workspace_root_identity WHERE workspace_id = $id AND released_at IS NOT NULL;
            """, ("$id", original.Id))));
        AssertRetainedTask(store, task, original, TaskState.Cancelled);
        Assert.Equal("owned data", File.ReadAllText(marker));
    }

    private static byte[] SeedRetainedTask(NodeStore store, RegisteredWorkspace workspace, TaskState state) =>
        store.Write(transaction =>
        {
            var id = LegacyTaskHistoryFixture.SeedQueued(transaction, new ActorRef { Origin = Origin.Human }).Value.ToByteArray();
            Assert.Equal(1, transaction.Execute("""
                UPDATE task SET workspace_id = $workspace, state = $state, side_effect = $effect, side_effect_source = $source
                WHERE task_id = $task;
                """, ("$workspace", workspace.Id), ("$state", (int)state), ("$effect", (int)SideEffectClass.Idempotent),
                ("$source", (int)SideEffectSource.Policy), ("$task", id)));
            return id;
        }, CommitDurability.Full);

    private static void AssertRetainedTask(NodeStore store, byte[] task, RegisteredWorkspace owner, TaskState state)
    {
        Assert.Equal(1L, store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM task WHERE task_id = $task AND workspace_id = $workspace AND state = $state
              AND side_effect = $effect AND side_effect_source = $source;
            """, ("$task", task), ("$workspace", owner.Id), ("$state", (int)state), ("$effect", (int)SideEffectClass.Idempotent),
            ("$source", (int)SideEffectSource.Policy))));
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
    }
}
