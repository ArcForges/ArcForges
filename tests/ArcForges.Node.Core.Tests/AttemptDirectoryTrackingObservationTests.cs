// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real native directory observations and SQLite rows; no caller ownership or cleanup effect is asserted.</summary>
public sealed class AttemptDirectoryTrackingObservationTests
{
    [Fact]
    public void MatchesARecordedDirectoryByNativeIdentityAndPreservesUnknownRecords()
    {
        var owned = Directory.CreateTempSubdirectory("arcforges-attempt-tracking-").FullName;
        try
        {
            var managed = Directory.CreateDirectory(Path.Combine(owned, "managed")).FullName;
            var tree = Directory.CreateDirectory(Path.Combine(managed, "tree")).FullName;
            Directory.CreateDirectory(Path.Combine(tree, "tracked"));
            Directory.CreateDirectory(Path.Combine(tree, "untracked"));
            File.WriteAllText(Path.Combine(tree, "file.txt"), "test body");
            using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = Path.Combine(owned, "store"), BootIdentity = "tracking-test" });
            store.Write(transaction =>
            {
                transaction.Execute("INSERT INTO root_location (root_class, path) VALUES ('tmp', $path);", ("$path", managed));
                InsertDirectory(transaction, "tmp", "tree/tracked");
            }, CommitDurability.Full);
            using var root = WorkspacePath.OpenRoot(managed);
            var snapshot = WorkspaceRemovalPlan.Capture(root, "tree", TestContext.Current.CancellationToken);
            var known = store.Read(reader => AttemptDirectoryTrackingObservation.Read(reader, snapshot,
                TestContext.Current.CancellationToken.ThrowIfCancellationRequested));
            Assert.Equal(AttemptDirectoryTracking.Tracked, known["tree/tracked"]);
            Assert.Equal(AttemptDirectoryTracking.Untracked, known["tree/untracked"]);
            Assert.False(known.ContainsKey("tree/file.txt"));

            // A row whose configured root is absent leaves nonmatching directory facts unknown.
            store.Write(transaction => InsertDirectory(transaction, "cache", "not-observable"), CommitDurability.Full);
            var incomplete = store.Read(reader => AttemptDirectoryTrackingObservation.Read(reader, snapshot,
                TestContext.Current.CancellationToken.ThrowIfCancellationRequested));
            Assert.Equal(AttemptDirectoryTracking.Tracked, incomplete["tree/tracked"]);
            Assert.Equal(AttemptDirectoryTracking.Unknown, incomplete["tree/untracked"]);
        }
        finally
        {
            Directory.Delete(owned, recursive: true);
        }
    }

    private static void InsertDirectory(StoreTransaction transaction, string rootClass, string relative)
    {
        transaction.Execute("""
            INSERT INTO managed_directory
              (directory_id, owner_kind, owner_id, root_class, relative_path, created_at, last_used_at, pinned, state, rev)
            VALUES ($id, 5, $owner, $root, $path, $now, $now, 0, 2, 0);
            """, ("$id", Guid.NewGuid().ToByteArray()), ("$owner", Guid.NewGuid().ToByteArray()),
            ("$root", rootClass), ("$path", relative), ("$now", transaction.NowMicroseconds));
    }
}
