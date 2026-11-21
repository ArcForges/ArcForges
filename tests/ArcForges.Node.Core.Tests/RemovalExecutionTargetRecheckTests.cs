// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Recovers retained removal records with real identities and test-owned namespace changes.</summary>
/// <remarks>The original V1 target checks, including the native capture race and traversal bounds, are
/// executable in this class at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.</remarks>
public sealed partial class RemovalExecutionTargetRecheckTests
{
    [Theory(Timeout = 120_000)]
    [InlineData("directory")]
    [InlineData("file")]
    [InlineData("different_tree")]
    [InlineData("symlink")]
    public async Task RecoveryKeepsTheOriginalIdentityAndHoldWithoutTouchingAReplacement(string replacement)
    {
        if (replacement == "symlink")
            Assert.SkipUnless(OperatingSystem.IsLinux(), "This fixture uses an unprivileged native Linux symlink.");

        var token = TestContext.Current.CancellationToken;
        await using var files = InProcessNode.Create();
        var root = Directory.CreateDirectory(Path.Combine(files.Root, "target")).FullName;
        var selected = Path.Combine(root, "selected");
        var saved = Path.Combine(root, "original-saved");
        var originalFile = replacement == "directory";
        if (originalFile)
            File.WriteAllText(selected, "original remains");
        else
        {
            Directory.CreateDirectory(selected);
            File.WriteAllText(Path.Combine(selected, "original"), "original remains");
        }

        var outside = Directory.CreateDirectory(Path.Combine(files.Root, "outside")).FullName;
        var sentinel = Path.Combine(outside, "sentinel");
        File.WriteAllText(sentinel, "outside remains");
        var custody = Path.Combine(files.Root, "retained-location");
        File.WriteAllText(custody, "custody remains");
        var caller = Caller();
        var snapshot = RetainedRemovalFixture.Capture(root, "selected", token);
        FileRemovalPlan plan;
        FileServiceExecuteRemovalRequest request;
        byte[] approvalId;
        using (var store = Open(files))
        {
            plan = RetainedRemovalFixture.SeedPlan(store, caller, root, "selected", snapshot, token);
            await using var processor = new CommandProcessor(store, EventJournal.Open(store), new StreamHub());
            (request, approvalId) = await RetainedRemovalFixture.SeedInterruptedAsync(processor, caller, plan, snapshot, custody, token);
        }

        if (originalFile) File.Move(selected, saved);
        else Directory.Move(selected, saved);
        var replacementFile = selected;
        switch (replacement)
        {
            case "directory":
            case "different_tree":
                Directory.CreateDirectory(selected);
                replacementFile = Path.Combine(selected, "replacement");
                File.WriteAllText(replacementFile, "replacement remains");
                break;
            case "file":
                File.WriteAllText(selected, "replacement remains");
                break;
            case "symlink":
                Directory.CreateSymbolicLink(selected, outside);
                break;
            default:
                throw new InvalidOperationException("Unknown fixture replacement.");
        }

        using var reopened = Open(files);
        var id = request.Meta.CommandId.Value.ToByteArray();
        Assert.Equal(FileOperationState.Prepared, reopened.Read(reader => FileMutationJournal.GetForCaller(reader, id, caller))?.State);
        Assert.Equal(1, reopened.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
        Assert.Equal(0, reopened.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
        AssertUnknownAndHeld(reopened, caller, request, custody);
        var approval = reopened.Read(reader => Approvals.Get(reader, approvalId));
        Assert.Equal(ApprovalState.Approved, approval?.State);
        Assert.Null(approval!.Outcome);
        Assert.Equal(snapshot.Entries[0].NativeIdentity.Bytes, reopened.Read(reader => reader.Scalar(
            "SELECT target_identity FROM file_operation_journal WHERE command_id = $id;", ("$id", id))) as byte[]);
        Assert.Equal(3L, reopened.Read(reader => reader.Scalar("SELECT state FROM cleanup_plan WHERE plan_id = $id;",
            ("$id", plan.PlanId.Value.ToByteArray()))));
        Assert.Equal(0L, reopened.Read(reader => reader.Scalar("SELECT count(*) FROM quarantine_entry;")));
        Assert.Equal("original remains", File.ReadAllText(originalFile ? saved : Path.Combine(saved, "original")));
        Assert.Equal("outside remains", File.ReadAllText(sentinel));
        Assert.Equal("custody remains", File.ReadAllText(custody));
        if (replacement == "symlink")
            Assert.Equal(outside, new DirectoryInfo(selected).LinkTarget);
        else
            Assert.Equal("replacement remains", File.ReadAllText(replacementFile));
    }

    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AcknowledgmentReleasesOnlyTheHoldWhenAnAliasAppears(bool linkAfterRecovery)
    {
        var human = new ActorRef { Origin = Origin.Human };
        var token = TestContext.Current.CancellationToken;
        await using var files = InProcessNode.Create();
        var root = Directory.CreateDirectory(Path.Combine(files.Root, "target")).FullName;
        var selected = Path.Combine(root, "selected");
        var alias = Path.Combine(files.Root, "alias");
        var custody = Path.Combine(files.Root, "retained-location");
        File.WriteAllText(selected, "both names remain");
        File.WriteAllText(custody, "custody remains");
        var caller = Caller();
        var snapshot = RetainedRemovalFixture.Capture(root, "selected", token);
        FileRemovalPlan plan;
        FileServiceExecuteRemovalRequest request;
        byte[] approvalId;
        using (var store = Open(files))
        {
            plan = RetainedRemovalFixture.SeedPlan(store, caller, root, "selected", snapshot, token);
            await using var processor = new CommandProcessor(store, EventJournal.Open(store), new StreamHub());
            (request, approvalId) = await RetainedRemovalFixture.SeedInterruptedAsync(processor, caller, plan, snapshot, custody, token);
        }

        using var reopened = Open(files);
        if (!linkAfterRecovery) CreateAlias(selected, alias);
        Assert.Equal(1, reopened.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
        if (linkAfterRecovery) CreateAlias(selected, alias);
        AssertUnknownAndHeld(reopened, caller, request, custody);
        var approval = reopened.Read(reader => Approvals.Get(reader, approvalId));
        Assert.Equal(ApprovalState.Approved, approval?.State);
        Assert.Null(approval!.Outcome);
        var id = request.Meta.CommandId.Value.ToByteArray();
        var workspace = plan.WorkspacePath.WorkspaceId.Value.ToByteArray();
        Assert.Equal(FileJournalAcknowledgment.DigestMismatch, reopened.Write(tx =>
            FileMutationJournal.AcknowledgeFromVerifiedHuman(tx, id, new byte[32], human), CommitDurability.Full));
        Assert.True(reopened.Read(reader => FileMutationJournal.HasWorkspaceHold(reader, workspace)));
        Assert.Equal(FileJournalAcknowledgment.Acknowledged, reopened.Write(tx =>
            FileMutationJournal.AcknowledgeFromVerifiedHuman(tx, id, SHA256.HashData(request.ToByteArray()), human), CommitDurability.Full));
        var acknowledged = reopened.Read(reader => FileMutationJournal.GetForCaller(reader, id, caller));
        Assert.NotNull(acknowledged);
        Assert.Equal(FileOperationState.Unknown, acknowledged.State);
        Assert.False(acknowledged.Held);
        Assert.True(acknowledged.Acknowledged);
        Assert.False(reopened.Read(reader => FileMutationJournal.HasWorkspaceHold(reader, workspace)));
        Assert.Equal(5L, reopened.Read(reader => reader.Scalar("SELECT state FROM cleanup_plan WHERE plan_id = $id;",
            ("$id", plan.PlanId.Value.ToByteArray()))));
        Assert.Equal(custody, reopened.Read(reader => FileMutationJournal.RemovalRecoveryLocation(reader, id)));
        using var heldRoot = WorkspacePath.OpenRoot(root);
        Assert.Equal(2u, heldRoot.InspectEntry("selected").Identity.Links);
        Assert.Equal("both names remain", File.ReadAllText(selected));
        Assert.Equal("both names remain", File.ReadAllText(alias));
        Assert.Equal("custody remains", File.ReadAllText(custody));
    }

    private static NodeStore Open(InProcessNode files) => NodeStore.Open(new NodeStoreOptions
    {
        DataRoot = files.DataRoot,
        BootIdentity = "retained-removal-fixture",
    });

    private static CenterCaller Caller() => new()
    {
        Kind = CenterCallerKind.NodeRelay,
        AccountId = RoutedCalls.Account.Clone(),
        RelayingNodeId = CommandIds.New(),
        LocalOrigin = Origin.Human,
        LocalSessionId = CommandIds.New(),
    };

    private static void AssertUnknownAndHeld(
        NodeStore store, CenterCaller caller, FileServiceExecuteRemovalRequest request, string custody)
    {
        var id = request.Meta.CommandId.Value.ToByteArray();
        var operation = store.Read(reader => FileMutationJournal.GetForCaller(reader, id, caller));
        Assert.NotNull(operation);
        Assert.Equal(FileOperationState.Unknown, operation.State);
        Assert.True(operation.Held);
        Assert.False(operation.Acknowledged);
        Assert.Equal(EffectCertainty.Unknown, operation.Error.Effect);
        Assert.Equal(RetryMode.Never, operation.Error.Retry.Mode);
        Assert.Equal("file_outcome_unknown", operation.Error.Details.State.Reason);
        Assert.Equal(SHA256.HashData(request.ToByteArray()), operation.RequestSha256.ToByteArray());
        Assert.Equal(custody, store.Read(reader => FileMutationJournal.RemovalRecoveryLocation(reader, id)));
    }

    private static void CreateAlias(string selected, string alias)
    {
        if (OperatingSystem.IsWindows())
            Assert.True(CreateHardLink(alias, selected, 0), $"Native hardlink failed: {Marshal.GetLastPInvokeError()}");
        else
            Assert.Equal(0, Link(selected, alias));
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateHardLinkW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateHardLink(string name, string existing, nint security);

    [LibraryImport("libc", EntryPoint = "link", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Link(string existing, string name);
}
