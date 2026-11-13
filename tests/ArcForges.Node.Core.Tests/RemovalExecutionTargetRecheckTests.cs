// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual test-owned namespace replacements; no cleanup effect or synthetic filesystem identity.</summary>
public sealed partial class RemovalExecutionTargetRecheckTests
{
    [Theory(Timeout = 120_000)]
    [InlineData("file_to_directory")]
    [InlineData("directory_to_oversized_file")]
    [InlineData("replacement_directory_over_bound")]
    [InlineData("directory_to_symlink")]
    public async Task AChangedKnownTargetIsAConflictBeforeCapturingTheReplacement(string replacement)
    {
        if (replacement == "directory_to_symlink")
            Assert.SkipUnless(OperatingSystem.IsLinux(), "This fixture creates an unprivileged native Linux symlink.");
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "target-recheck-root")).FullName;
        var selected = Path.Combine(root, "selected");
        var saved = Path.Combine(root, "original-saved");
        var originalFile = replacement == "file_to_directory";
        if (originalFile) File.WriteAllText(selected, "original remains");
        else
        {
            Directory.CreateDirectory(selected);
            File.WriteAllText(Path.Combine(selected, "original"), "original remains");
        }
        var outside = Directory.CreateDirectory(Path.Combine(node.Root, "external-owned")).FullName;
        File.WriteAllText(Path.Combine(outside, "sentinel"), "external unchanged");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var planRequest = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "selected" },
        };
        var planned = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, planRequest.ToByteArray(), planRequest.Meta.CommandId);
        var plan = FileServicePlanRemovalResponse.Parser.ParseFrom(planned.Answer!.Response);
        Assert.Null(plan.Error);
        if (originalFile) File.Move(selected, saved);
        else Directory.Move(selected, saved);
        switch (replacement)
        {
            case "file_to_directory":
                Directory.CreateDirectory(selected);
                break;
            case "directory_to_oversized_file":
                using (var file = File.Create(selected)) file.SetLength(checked((long)WorkspaceRemovalPlan.MaximumTotalBytes + 1));
                break;
            case "replacement_directory_over_bound":
                Directory.CreateDirectory(selected);
                for (var i = 0; i <= WorkspaceRemovalPlan.MaximumDescendants; i++)
                    File.WriteAllBytes(Path.Combine(selected, i.ToString(System.Globalization.CultureInfo.InvariantCulture)), []);
                break;
            case "directory_to_symlink":
                Directory.CreateSymbolicLink(selected, outside);
                break;
            default:
                throw new InvalidOperationException("Unknown test replacement.");
        }
        var request = new FileServiceExecuteRemovalRequest
        {
            Meta = Tasks.Meta(),
            PlanId = plan.Value.Plan.PlanId.Clone(),
            PlanDigest = plan.Value.Plan.Digest,
        };
        var result = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        var response = FileServiceExecuteRemovalResponse.Parser.ParseFrom(result.Answer!.Response);
        Assert.Equal(ErrorCategory.Conflict, response.Error.Category);
        Assert.Equal("file_changed", response.Error.Code);
        Assert.Equal("planned_tree_changed", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(RetryMode.Never, response.Error.Retry.Mode);
        Assert.Equal("original remains", File.ReadAllText(originalFile ? saved : Path.Combine(saved, "original")));
        Assert.Equal("external unchanged", File.ReadAllText(Path.Combine(outside, "sentinel")));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT state FROM cleanup_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
    }
    [Fact(Timeout = 120_000)]
    public async Task ARealReplacementAfterTheSnapshotCannotKeepTheOldPlanClassification()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "late-recheck-root")).FullName;
        var selected = Path.Combine(root, "selected");
        var saved = Path.Combine(root, "saved");
        File.WriteAllText(selected, "original remains");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var plannedRequest = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "selected" },
        };
        var planned = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, plannedRequest.ToByteArray(), plannedRequest.Meta.CommandId);
        var plan = FileServicePlanRemovalResponse.Parser.ParseFrom(planned.Answer!.Response);
        Assert.Null(plan.Error);
        var called = false;
        calls.Dispatcher.FileHandlerForTests!.AfterRemovalExecutionCaptureForTests = () =>
        {
            called = true;
            File.Move(selected, saved);
            File.WriteAllText(selected, "replacement remains");
        };
        var request = new FileServiceExecuteRemovalRequest
        {
            Meta = Tasks.Meta(),
            PlanId = plan.Value.Plan.PlanId.Clone(),
            PlanDigest = plan.Value.Plan.Digest,
        };
        var result = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        calls.Dispatcher.FileHandlerForTests.AfterRemovalExecutionCaptureForTests = null;
        Assert.True(called);
        var response = FileServiceExecuteRemovalResponse.Parser.ParseFrom(result.Answer!.Response);
        Assert.Equal(ErrorCategory.Conflict, response.Error.Category);
        Assert.Equal("file_changed", response.Error.Code);
        Assert.Equal("planned_tree_changed", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal("original remains", File.ReadAllText(saved));
        Assert.Equal("replacement remains", File.ReadAllText(selected));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
    }

    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnObservedNewHardLinkIsAConflictBeforeAndAfterCapture(bool afterCapture)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "hardlink-recheck-root")).FullName;
        var selected = Path.Combine(root, "selected");
        var alias = Path.Combine(node.Root, "owned-alias");
        File.WriteAllText(selected, "both names remain");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var plannedRequest = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "selected" },
        };
        var planned = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, plannedRequest.ToByteArray(), plannedRequest.Meta.CommandId);
        var plan = FileServicePlanRemovalResponse.Parser.ParseFrom(planned.Answer!.Response);
        Assert.Null(plan.Error);
        var called = false;
        void AddRealLink()
        {
            if (OperatingSystem.IsWindows())
                Assert.True(CreateHardLink(alias, selected, 0), $"Native hardlink failed: {Marshal.GetLastPInvokeError()}");
            else
                Assert.Equal(0, Link(selected, alias));
            using var heldRoot = WorkspacePath.OpenRoot(root);
            Assert.Equal(2u, heldRoot.InspectEntry("selected").Identity.Links);
            called = true;
        }
        if (afterCapture) calls.Dispatcher.FileHandlerForTests!.AfterRemovalExecutionCaptureForTests = AddRealLink;
        else AddRealLink();
        var request = new FileServiceExecuteRemovalRequest
        {
            Meta = Tasks.Meta(),
            PlanId = plan.Value.Plan.PlanId.Clone(),
            PlanDigest = plan.Value.Plan.Digest,
        };
        var result = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        calls.Dispatcher.FileHandlerForTests!.AfterRemovalExecutionCaptureForTests = null;
        Assert.True(called);
        var response = FileServiceExecuteRemovalResponse.Parser.ParseFrom(result.Answer!.Response);
        Assert.Equal(ErrorCategory.Conflict, response.Error.Category);
        Assert.Equal("file_changed", response.Error.Code);
        Assert.Equal("planned_tree_changed", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(RetryMode.Never, response.Error.Retry.Mode);
        Assert.Equal("both names remain", File.ReadAllText(selected));
        Assert.Equal("both names remain", File.ReadAllText(alias));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT state FROM cleanup_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateHardLinkW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateHardLink(string name, string existing, nint security);

    [LibraryImport("libc", EntryPoint = "link", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Link(string existing, string name);

}
