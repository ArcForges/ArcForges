// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual Windows directory identity and retained SQLite provenance in an isolated fixture.</summary>
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class AttemptTempProvenanceWindowsTests
{
    [Fact(Timeout = 120_000)]
    public async Task RetainedAttemptPreservesItsOwnerAndNativeDirectoryIdentityAcrossRestart()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows directory identity.");
        await using var node = InProcessNode.Create();
        var (attempt, directory, owner) = RetainedWindowsAttemptFixture.Seed(node, "retained");
        await node.StartAsync();
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var name = IdText.Format(attempt);

        var tempRoot = Path.Combine(node.DataRoot, "tmp");
        using var root = WorkspacePath.OpenRoot(tempRoot);
        using var child = root.OpenDirectory(name);
        var expectedRoot = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        var expectedChild = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(child));
        node.Runtime.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("""
                SELECT m.state, m.owner_kind, m.owner_id, m.root_class, m.relative_path, p.root_platform,
                       p.root_identity, p.directory_identity, p.owner, t.owner, r.path
                FROM file_attempt_temp_identity p
                JOIN managed_directory m ON m.directory_id = p.directory_id
                JOIN attempt a ON a.attempt_id = p.attempt_id
                JOIN task t ON t.task_id = a.task_id AND t.task_id = p.task_id
                JOIN root_location r ON r.root_class = m.root_class
                WHERE p.attempt_id = $attempt;
                """);
            command.Parameters.AddWithValue("$attempt", attempt.Value.ToByteArray());
            using var row = command.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal(2, row.GetInt32(0));
            Assert.Equal(1, row.GetInt32(1));
            Assert.Equal(attempt.Value.ToByteArray(), (byte[])row.GetValue(2));
            Assert.Equal("tmp", row.GetString(3));
            Assert.Equal(name, row.GetString(4));
            Assert.Equal(expectedRoot.Platform, row.GetInt32(5));
            Assert.Equal(expectedRoot.Bytes, (byte[])row.GetValue(6));
            Assert.Equal(expectedChild.Bytes, (byte[])row.GetValue(7));
            Assert.Equal((byte[])row.GetValue(9), (byte[])row.GetValue(8));
            Assert.Equal(owner, ActorRef.Parser.ParseFrom((byte[])row.GetValue(8)).CenterCaller);
            Assert.Equal(root.RootPath, row.GetString(10), ignoreCase: true);
            Assert.False(row.Read());
            return 0;
        });
        Assert.Equal(0, node.Runtime.Execution!.RemoveExpiredTemp());
        Assert.Equal("retained", File.ReadAllText(Path.Combine(directory, "keep.txt")));
    }

    [Fact]
    public void AnExistingDirectoryIsNeverAdoptedAsANewAttemptDirectory()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Native Windows directory creation.");
        var temporary = Directory.CreateTempSubdirectory("arcforges-attempt-provenance-").FullName;
        try
        {
            var existing = Directory.CreateDirectory(Path.Combine(temporary, "occupied")).FullName;
            var file = Path.Combine(existing, "keep.txt");
            File.WriteAllText(file, "unowned-fixture");
            using var root = WorkspacePath.OpenRoot(temporary);
            var before = WorkspacePath.Identity(root.OpenDirectory("occupied"));
            Assert.Throws<WorkspacePathException>(() => root.CreateWindowsAttemptDirectory("occupied"));
            Assert.True(before.SameObject(WorkspacePath.Identity(root.OpenDirectory("occupied"))));
            Assert.Equal("unowned-fixture", File.ReadAllText(file));
        }
        finally
        {
            Directory.Delete(temporary, recursive: true);
        }
    }
}

internal static class RetainedWindowsAttemptFixture
{
    // Model on-disk history with the exact Windows provenance writer; there is no legacy Task call or launch.
    internal static (Id Attempt, string Path, CenterCaller Owner) Seed(InProcessNode node, string contents)
    {
        var (task, attempt) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Starting);
        var attemptId = attempt.Value.ToByteArray();
        var taskId = task.Value.ToByteArray();
        var name = IdText.Format(attempt);
        var temporary = Directory.CreateDirectory(Path.Combine(node.DataRoot, "tmp")).FullName;
        using var root = WorkspacePath.OpenRoot(temporary);
        using var child = root.CreateWindowsAttemptDirectory(name);
        var path = Path.Combine(root.RootPath, name);
        File.WriteAllText(Path.Combine(path, "keep.txt"), contents);
        using var store = NodeStore.Open(new NodeStoreOptions
        {
            DataRoot = node.DataRoot,
            BootIdentity = BootIdentity.Read(),
            Clock = node.Clock,
        });
        var owner = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = RoutedCalls.Account.Clone(),
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(store.Metadata.NodeId.Span) },
            LocalOrigin = Origin.Agent,
            LocalSessionId = CommandIds.New(),
        };
        var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = owner, RemoteCommandId = CommandIds.New() };
        store.Write(transaction =>
        {
            Assert.Equal(1, transaction.Execute("""
                UPDATE task SET owner = $owner, owner_origin = $origin, remote_command_id = $command WHERE task_id = $id;
                """, ("$owner", actor.ToByteArray()), ("$origin", (int)actor.Origin),
                ("$command", actor.RemoteCommandId.Value.ToByteArray()), ("$id", taskId)));
            AttemptTempProvenance.Record(transaction, root, child, name, attemptId, taskId);
            var now = transaction.NowMicroseconds;
            Assert.Equal(1, transaction.Execute("""
                UPDATE attempt SET state = $finished, finished_at = $now, exit_code = 0, termination_reason = $exited, effect = $effect
                WHERE attempt_id = $id;
                """, ("$finished", (int)AttemptState.Finished), ("$now", now), ("$exited", (int)TerminationReason.Exited),
                ("$effect", (int)EffectCertainty.Happened), ("$id", attemptId)));
            Assert.Equal(1, transaction.Execute("UPDATE task SET state = $state, finished_at = $now WHERE task_id = $id;",
                ("$state", (int)TaskState.Succeeded), ("$now", now), ("$id", taskId)));
            AttemptTempProvenance.MarkIdle(transaction, attemptId);
        }, CommitDurability.Full);
        return (attempt, path, owner);
    }
}
