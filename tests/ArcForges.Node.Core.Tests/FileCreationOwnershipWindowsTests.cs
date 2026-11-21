// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using static ArcForges.Node.Core.Tests.FileCreateCandidateTests;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Real markers on test-owned Windows objects and the retained SQLite ledger. Fresh routed creation and native update
/// assertions remain at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
/// </summary>
public sealed class FileCreationOwnershipWindowsTests
{
    [Fact(Timeout = 30_000)]
    [Trait("env", "windows-real")]
    public async Task RetainedCreationMarkerSurvivesRestartAndBindsTheOriginalOwnerAndObject()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows native marker readback.");
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        // Synthetic AGENT provenance exercises the retained ownership observer only.
        var owner = calls.Relay(Origin.Agent);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "retained-ownership")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: ct);
        var content = "historical-owner-created-body"u8.ToArray();
        var request = Request(workspace.Id, "created.txt", content);
        var path = Path.Combine(rootPath, request.Path.Path);
        var evidence = CreateOwnedMarkerFixture(path, content);
        var raw = node.Runtime.Store.Write(transaction =>
        {
            using var root = WorkspacePath.OpenRoot(rootPath);
            SeedPrepared(transaction, owner, root, request);
            return FileMutationJournal.CompleteVerifiedEffect(transaction, request.Meta.CommandId.Value.Span, request.ToByteArray(),
                content.Length, SHA256.HashData(content), replacements: null, createdOwnership: evidence);
        }, CommitDurability.Full);

        bool IsOwned(CenterCaller caller)
        {
            using var root = WorkspacePath.OpenRoot(rootPath);
            var selected = Assert.Single(WorkspaceRemovalPlan.Capture(root, request.Path.Path, ct).Entries);
            return node.Runtime.Store.Read(reader => FileCreationOwnership.IsVerifiedAgent(reader, caller, workspace.Id, root, selected, ct));
        }

        Assert.True(IsOwned(owner));
        Assert.False(IsOwned(calls.Relay(Origin.Agent)));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        Assert.True(IsOwned(owner));
        Assert.Equal(raw, await ReplayAsync(calls, owner, request, ct));
        using (var root = WorkspacePath.OpenRoot(rootPath))
        using (var file = root.OpenReadForOwnership(request.Path.Path))
            Assert.Equal(evidence.Marker, WorkspaceCreationMarker.Read(file));

        var external = (byte[])content.Clone();
        external[0] ^= 1;
        File.WriteAllBytes(path, external);
        Assert.False(IsOwned(owner));
        Assert.Equal(raw, await ReplayAsync(calls, owner, request, ct));
        Assert.Equal(external, File.ReadAllBytes(path));
        Assert.Equal(SHA256.HashData(content), node.Runtime.Store.Read(reader =>
            reader.Scalar("SELECT last_written_sha256 FROM file_creation_ownership;")) as byte[]);
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "windows-real")]
    public async Task RolledBackHistoricalSettlementLeavesOnlyTheHeldIntentAndNoClaimableMarkerRecord()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows native marker readback.");
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var owner = calls.Relay(Origin.Human);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "retained-rollback")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: ct);
        var content = "rolled-back-historical-created-body"u8.ToArray();
        var request = Request(workspace.Id, "created.txt", content);
        var path = Path.Combine(rootPath, request.Path.Path);
        var evidence = CreateOwnedMarkerFixture(path, content);
        using (var root = WorkspacePath.OpenRoot(rootPath))
            node.Runtime.Store.Write(transaction => SeedPrepared(transaction, owner, root, request), CommitDurability.Full);

        Assert.Throws<IOException>(() => node.Runtime.Store.Write<int>(transaction =>
        {
            FileMutationJournal.CompleteVerifiedEffect(transaction, request.Meta.CommandId.Value.Span, request.ToByteArray(),
                content.Length, SHA256.HashData(content), replacements: null, createdOwnership: evidence);
            Assert.Equal(1L, transaction.Scalar("SELECT count(*) FROM file_creation_ownership;"));
            throw new IOException("Synthetic rollback after writing the historical settlement.");
        }, CommitDurability.Full));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_creation_ownership;")));
        var prepared = node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, request.Meta.CommandId.Value.Span, owner));
        Assert.Equal(FileOperationState.Prepared, prepared!.State);
        Assert.True(prepared.Held);

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var recovered = node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, request.Meta.CommandId.Value.Span, owner));
        Assert.Equal(FileOperationState.Unknown, recovered!.State);
        Assert.True(recovered.Held);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_creation_ownership;")));
        Assert.Equal(content, File.ReadAllBytes(path));
        using var anchor = WorkspacePath.OpenRoot(rootPath);
        using var file = anchor.OpenReadForOwnership(request.Path.Path);
        Assert.Equal(evidence.Marker, WorkspaceCreationMarker.Read(file));
    }

    private static WorkspaceCreatedOwnership CreateOwnedMarkerFixture(string path, byte[] content)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        file.Write(content);
        file.Flush(flushToDisk: true);
        var marker = Assert.IsType<byte[]>(WorkspaceCreationMarker.TryWriteNew(file.SafeFileHandle));
        var identity = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file.SafeFileHandle), directory: false);
        return new WorkspaceCreatedOwnership(identity, marker);
    }
}
