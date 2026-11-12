// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed partial class FileMutationJournalTests
{
    [Fact]
    public void UnknownTargetHoldFollowsTheSameNativeFileAcrossNestedRegisteredRoots()
    {
        using var fixture = new TargetHoldFixture();
        var child = Directory.CreateDirectory(Path.Combine(fixture.Workspace, "child")).FullName;
        var target = Path.Combine(child, "target.txt");
        File.WriteAllText(target, "same actual object");
        FileJournalIntent first;
        byte[] firstRaw;
        byte[] childWorkspace;
        using (var store = fixture.Open())
        {
            var workspaces = new RegisteredWorkspaces(store);
            var outer = workspaces.RegisterFromVerifiedHuman(fixture.Workspace, cancellationToken: TestContext.Current.CancellationToken);
            var inner = workspaces.RegisterFromVerifiedHuman(child, cancellationToken: TestContext.Current.CancellationToken);
            childWorkspace = inner.Id;
            (first, firstRaw) = fixture.Intent(outer.Id, fixture.Workspace, "child/target.txt", "first result");
            Assert.Equal(FileJournalPreparation.Prepared, store.Write(
                transaction => FileMutationJournal.Prepare(transaction, first, firstRaw), CommitDurability.Full));
        }

        using (var restarted = fixture.Open())
        {
            Assert.Equal(1, restarted.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
            Assert.Equal(FileOperationState.Unknown, restarted.Read(
                reader => FileMutationJournal.GetForCaller(reader, first.CommandId, first.Caller))!.State);
            var (alias, aliasRaw) = fixture.Intent(childWorkspace, child, "target.txt", "second result");
            Assert.Equal(first.TargetIdentity, alias.TargetIdentity);
            Assert.Equal(first.ParentIdentity, alias.ParentIdentity);
            Assert.Equal(FileJournalPreparation.WorkspaceHeld, restarted.Write(
                transaction => FileMutationJournal.Prepare(transaction, alias, aliasRaw), CommitDurability.Full));
            Assert.Equal("same actual object", File.ReadAllText(target));
            var human = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli };
            Assert.Equal(FileJournalAcknowledgment.Acknowledged, restarted.Write(
                transaction => FileMutationJournal.AcknowledgeFromVerifiedHuman(
                    transaction, first.CommandId, SHA256.HashData(firstRaw), human), CommitDurability.Full));
            Assert.Equal(FileJournalPreparation.Prepared, restarted.Write(
                transaction => FileMutationJournal.Prepare(transaction, alias, aliasRaw), CommitDurability.Full));
        }
    }

    [Fact]
    public void UnknownTargetHoldDoesNotBlockAnIndependentFileInTheSameWorkspace()
    {
        using var fixture = new TargetHoldFixture();
        var firstPath = Path.Combine(fixture.Workspace, "first.txt");
        var otherPath = Path.Combine(fixture.Workspace, "second.txt");
        File.WriteAllText(firstPath, "first original");
        File.WriteAllText(otherPath, "second original");
        FileJournalIntent first;
        byte[] firstRaw;
        byte[] workspaceId;
        using (var store = fixture.Open())
        {
            workspaceId = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(
                fixture.Workspace, cancellationToken: TestContext.Current.CancellationToken).Id;
            (first, firstRaw) = fixture.Intent(workspaceId, fixture.Workspace, "first.txt", "first result");
            Assert.Equal(FileJournalPreparation.Prepared, store.Write(
                transaction => FileMutationJournal.Prepare(transaction, first, firstRaw), CommitDurability.Full));
        }

        using (var restarted = fixture.Open())
        {
            Assert.Equal(1, restarted.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
            var (other, otherRaw) = fixture.Intent(workspaceId, fixture.Workspace, "second.txt", "second result");
            Assert.NotEqual(first.TargetIdentity, other.TargetIdentity);
            using var selectedRoot = WorkspacePath.OpenRoot(fixture.Workspace);
            Assert.Equal(FileJournalPreparation.Prepared, restarted.Write(
                transaction => FileMutationJournal.Prepare(transaction, other, otherRaw, selectedRoot), CommitDurability.Full));
            Assert.False(selectedRoot.RootHandle.IsClosed);
            Assert.True(WorkspacePath.Identity(selectedRoot.RootHandle).SameObject(selectedRoot.RootIdentity));
            Assert.Equal(WorkspaceEntryType.File, selectedRoot.InspectEntry("second.txt").Kind);
            Assert.Equal("first original", File.ReadAllText(firstPath));
            Assert.Equal("second original", File.ReadAllText(otherPath));
        }
    }

    [Fact]
    public void DistinctNestedTargetKeepsOwnedDirectoryHandlesUsableUntilWorkspaceDisposal()
    {
        using var fixture = new TargetHoldFixture();
        var child = Directory.CreateDirectory(Path.Combine(fixture.Workspace, "nested")).FullName;
        var firstPath = Path.Combine(child, "first.txt");
        var otherPath = Path.Combine(child, "second.txt");
        File.WriteAllText(firstPath, "first original");
        File.WriteAllText(otherPath, "second original");
        byte[] workspaceId;
        using (var store = fixture.Open())
        {
            workspaceId = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(
                fixture.Workspace, cancellationToken: TestContext.Current.CancellationToken).Id;
            var (first, firstRaw) = fixture.Intent(workspaceId, fixture.Workspace, "nested/first.txt", "first result");
            Assert.Equal(FileJournalPreparation.Prepared, store.Write(
                transaction => FileMutationJournal.Prepare(transaction, first, firstRaw), CommitDurability.Full));
        }

        using var restarted = fixture.Open();
        Assert.Equal(1, restarted.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
        var (other, otherRaw) = fixture.Intent(workspaceId, fixture.Workspace, "nested/second.txt", "second result");
        var selectedRoot = WorkspacePath.OpenRoot(fixture.Workspace);
        var rootHandle = selectedRoot.RootHandle;
        var childHandle = selectedRoot.OpenDirectory("nested");
        try
        {
            Assert.Equal(FileJournalPreparation.Prepared, restarted.Write(
                transaction => FileMutationJournal.Prepare(transaction, other, otherRaw, selectedRoot), CommitDurability.Full));
            Assert.False(rootHandle.IsClosed);
            Assert.False(childHandle.IsClosed);
            Assert.True(WorkspacePath.Identity(rootHandle).SameObject(selectedRoot.RootIdentity));
            Assert.True(WorkspacePath.Identity(childHandle).IsDirectory);
            Assert.Equal(WorkspaceEntryType.File, selectedRoot.InspectEntry("nested/second.txt").Kind);
            Assert.Equal("first original", File.ReadAllText(firstPath));
            Assert.Equal("second original", File.ReadAllText(otherPath));
        }
        finally
        {
            selectedRoot.Dispose();
        }
        Assert.True(rootHandle.IsClosed);
        Assert.True(childHandle.IsClosed);
    }

    [Fact]
    public void UnknownHoldFollowsAnActualRenamedObjectIntoAnotherParent()
    {
        using var fixture = new TargetHoldFixture();
        var target = Path.Combine(fixture.Workspace, "target.txt");
        var movedDirectory = Directory.CreateDirectory(Path.Combine(fixture.Workspace, "moved")).FullName;
        var moved = Path.Combine(movedDirectory, "renamed.txt");
        File.WriteAllText(target, "original target");
        FileJournalIntent first;
        byte[] firstRaw;
        byte[] workspaceId;
        using (var store = fixture.Open())
        {
            workspaceId = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(
                fixture.Workspace, cancellationToken: TestContext.Current.CancellationToken).Id;
            (first, firstRaw) = fixture.Intent(workspaceId, fixture.Workspace, "target.txt", "first result");
            Assert.Equal(FileJournalPreparation.Prepared, store.Write(
                transaction => FileMutationJournal.Prepare(transaction, first, firstRaw), CommitDurability.Full));
        }
        using (var restarted = fixture.Open())
        {
            Assert.Equal(1, restarted.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
            File.Move(target, moved);
            var (candidate, raw) = fixture.Intent(workspaceId, fixture.Workspace, "moved/renamed.txt", "other result");
            Assert.Equal(first.TargetIdentity, candidate.TargetIdentity);
            Assert.NotEqual(first.ParentIdentity, candidate.ParentIdentity);
            using var selectedRoot = WorkspacePath.OpenRoot(fixture.Workspace);
            Assert.Equal(FileJournalPreparation.WorkspaceHeld, restarted.Write(
                transaction => FileMutationJournal.Prepare(transaction, candidate, raw, selectedRoot), CommitDurability.Full));
            Assert.Equal("original target", File.ReadAllText(moved));
        }
    }

    [Fact]
    public void UnknownHoldBlocksAReplacementAtTheOriginalNativeName()
    {
        using var fixture = new TargetHoldFixture();
        var target = Path.Combine(fixture.Workspace, "target.txt");
        var movedDirectory = Directory.CreateDirectory(Path.Combine(fixture.Workspace, "moved")).FullName;
        File.WriteAllText(target, "original target");
        FileJournalIntent first;
        byte[] firstRaw;
        byte[] workspaceId;
        using (var store = fixture.Open())
        {
            workspaceId = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(
                fixture.Workspace, cancellationToken: TestContext.Current.CancellationToken).Id;
            (first, firstRaw) = fixture.Intent(workspaceId, fixture.Workspace, "target.txt", "first result");
            Assert.Equal(FileJournalPreparation.Prepared, store.Write(
                transaction => FileMutationJournal.Prepare(transaction, first, firstRaw), CommitDurability.Full));
        }
        using (var restarted = fixture.Open())
        {
            Assert.Equal(1, restarted.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
            File.Move(target, Path.Combine(movedDirectory, "old.txt"));
            File.WriteAllText(target, "replacement object");
            var (candidate, raw) = fixture.Intent(workspaceId, fixture.Workspace, "target.txt", "other result");
            Assert.NotEqual(first.TargetIdentity, candidate.TargetIdentity);
            using var selectedRoot = WorkspacePath.OpenRoot(fixture.Workspace);
            Assert.Equal(FileJournalPreparation.WorkspaceHeld, restarted.Write(
                transaction => FileMutationJournal.Prepare(transaction, candidate, raw, selectedRoot), CommitDurability.Full));
            Assert.Equal("replacement object", File.ReadAllText(target));
        }
    }

    [Fact]
    [Trait("env", "windows-real")]
    public void WindowsUnknownHoldResolvesAReplacementUsingTheDirectorysNativeCaseSemantics()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native case semantics."); return; }
        using var fixture = new TargetHoldFixture();
        var target = Path.Combine(fixture.Workspace, "target.txt");
        var alias = Path.Combine(fixture.Workspace, "TARGET.TXT");
        var movedDirectory = Directory.CreateDirectory(Path.Combine(fixture.Workspace, "moved")).FullName;
        File.WriteAllText(target, "original target");
        if (!File.Exists(alias)) { Assert.Skip("This test-owned directory is case-sensitive."); return; }
        FileJournalIntent first;
        byte[] firstRaw;
        byte[] workspaceId;
        using (var store = fixture.Open())
        {
            workspaceId = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(
                fixture.Workspace, cancellationToken: TestContext.Current.CancellationToken).Id;
            (first, firstRaw) = fixture.Intent(workspaceId, fixture.Workspace, "target.txt", "first result");
            Assert.Equal(FileJournalPreparation.Prepared, store.Write(
                transaction => FileMutationJournal.Prepare(transaction, first, firstRaw), CommitDurability.Full));
        }
        using (var restarted = fixture.Open())
        {
            Assert.Equal(1, restarted.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
            File.Move(target, Path.Combine(movedDirectory, "old.txt"));
            File.WriteAllText(target, "replacement object");
            var (candidate, raw) = fixture.Intent(workspaceId, fixture.Workspace, "TARGET.TXT", "other result");
            Assert.NotEqual(first.TargetIdentity, candidate.TargetIdentity);
            using var selectedRoot = WorkspacePath.OpenRoot(fixture.Workspace);
            Assert.Equal(FileJournalPreparation.WorkspaceHeld, restarted.Write(
                transaction => FileMutationJournal.Prepare(transaction, candidate, raw, selectedRoot), CommitDurability.Full));
            Assert.Equal("replacement object", File.ReadAllText(alias));
        }
    }

    private sealed class TargetHoldFixture : IDisposable
    {
        private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("arcforges-target-hold-");

        internal TargetHoldFixture()
        {
            Workspace = Directory.CreateDirectory(Path.Combine(_root.FullName, "workspace")).FullName;
        }

        internal string Workspace { get; }

        internal NodeStore Open() => NodeStore.Open(new NodeStoreOptions
        {
            DataRoot = Path.Combine(_root.FullName, "node-data"),
            BootIdentity = "target-hold-test",
        });

        internal (FileJournalIntent Intent, byte[] Raw) Intent(byte[] workspaceId, string workspace, string relative, string desired)
        {
            var targetPath = Path.Combine(workspace, relative.Replace('/', Path.DirectorySeparatorChar));
            var original = File.ReadAllBytes(targetPath);
            var content = Encoding.UTF8.GetBytes(desired);
            var oldPath = Path.Combine(_root.FullName, Guid.NewGuid().ToString("N") + "-old");
            var newPath = Path.Combine(_root.FullName, Guid.NewGuid().ToString("N") + "-new");
            WriteFlushed(oldPath, original);
            WriteFlushed(newPath, content);
            using var root = WorkspacePath.OpenRoot(workspace);
            var rootId = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            var slash = relative.LastIndexOf('/');
            var parent = root.OpenDirectory(slash < 0 ? "" : relative[..slash]);
            var parentId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(parent));
            using var target = File.OpenHandle(targetPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var oldStage = File.OpenHandle(oldPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var newStage = File.OpenHandle(newPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var targetId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(target), directory: false);
            var oldId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(oldStage), directory: false);
            var newId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(newStage), directory: false);
            var meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
            var request = new FileServiceWriteFileRequest
            {
                Meta = meta,
                Path = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspaceId) }, Path = relative },
                Data = ByteString.CopyFrom(content),
                ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original)),
            };
            var caller = new CenterCaller
            {
                Kind = CenterCallerKind.AccountSession,
                AccountId = CommandIds.New(),
                UserId = CommandIds.New(),
                SessionId = CommandIds.New(),
            };
            var intent = new FileJournalIntent(FileOperationKind.Write, meta.CommandId.Value.ToByteArray(),
                meta.CorrelationId.Value.ToByteArray(), caller, workspaceId, relative, rootId.Platform, rootId.Bytes,
                parentId.Bytes, targetId.Bytes, original.LongLength, SHA256.HashData(original), oldId.Bytes,
                content.LongLength, SHA256.HashData(content), newId.Bytes);
            return (intent, request.ToByteArray());
        }

        private static void WriteFlushed(string path, byte[] bytes)
        {
            using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            file.Write(bytes);
            file.Flush(flushToDisk: true);
        }

        public void Dispose() => _root.Delete(recursive: true);
    }
}
