// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using Google.Protobuf;
using Microsoft.Win32.SafeHandles;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real node SQLite catalogue and native roots via the dispatcher seam, not real-center acceptance.</summary>
public sealed partial class WorkspaceCatalogRoutedTests
{
    [Fact(Timeout = 120_000)]
    public async Task CompleteCatalogueRetainsUnavailableRootsAndInvalidatesChangedInventoryCursors()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        var a = Directory.CreateDirectory(Path.Combine(node.Root, "catalog-a")).FullName;
        var b = Directory.CreateDirectory(Path.Combine(node.Root, "catalog-missing")).FullName;
        var c = Directory.CreateDirectory(Path.Combine(node.Root, "catalog-replaced")).FullName;
        var first = manager.RegisterFromVerifiedHuman(a, "available", cancellationToken: ct);
        var missing = manager.RegisterFromVerifiedHuman(b, "missing", cancellationToken: ct);
        var replaced = manager.RegisterFromVerifiedHuman(c, "replaced", cancellationToken: ct);
        Directory.Move(b, b + "-held");
        Directory.Move(c, c + "-held");
        Directory.CreateDirectory(c);
        Directory.CreateDirectory(Path.Combine(c, ".git"));
        File.WriteAllText(Path.Combine(c, ".git", "HEAD"), "ref: refs/heads/unverified-replacement\n");
        var managed = CommandIds.New();
        var remote = CommandIds.New();
        node.Runtime.Store.Write(transaction =>
        {
            transaction.Execute("""
                INSERT INTO workspace (workspace_id, kind, state, name, root_path, repository_identity, base_workspace_id,
                    base_ref, branch, routing_mode, concurrency_mode, created_at, last_used_at, rev)
                VALUES ($id, 2, 3, 'managed', $root, 'synthetic-repository', $base, 'main', 'feature', 1, 2, 1, 1, 0);
                """, ("$id", managed.Value.ToByteArray()), ("$root", Path.Combine(node.Root, "managed-record")), ("$base", first.Id));
            transaction.Execute("""
                INSERT INTO workspace (workspace_id, kind, state, name, root_path, origin_node_id, origin_workspace_key,
                    remote_slot, created_at, last_used_at, rev)
                VALUES ($id, 3, 2, 'remote', $root, $origin, 'synthetic-origin', 2, 1, 1, 0);
                """, ("$id", remote.Value.ToByteArray()), ("$root", Path.Combine(node.Root, "remote-record")),
                ("$origin", CommandIds.New().Value.ToByteArray()));
        });

        var caller = calls.Relay(Origin.Agent);
        var request = new WorkspaceServiceListWorkspacesRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            Page = new PageRequest { Limit = 2 },
        };
        var seen = new List<Workspace>();
        do
        {
            var call = await calls.CallAsync(caller, RoutedMethod.ListNodeWorkspaces, request.ToByteArray());
            Assert.Equal(RoutedOutcome.Executed, call.Answer!.Outcome);
            var response = WorkspaceServiceListWorkspacesResponse.Parser.ParseFrom(call.Answer.Response);
            Assert.Null(response.Error);
            Assert.True(NodeShapes.IsValid(response));
            Assert.InRange(response.CalculateSize(), 1, 131_072);
            Assert.Equal(WorkspaceAuditMetadata.ForRecords(response.Value.Workspaces), response.Audit);
            seen.AddRange(response.Value.Workspaces);
            if (!response.Value.Page.HasMore) break;
            request.Page.Cursor = response.Value.Page.NextCursor;
        }
        while (true);
        Assert.Equal(5, seen.Count);
        Assert.Equal(5, seen.Select(item => item.WorkspaceId).Distinct().Count());
        Assert.Equal(new[] { WorkspaceKind.Registered, WorkspaceKind.Registered, WorkspaceKind.Registered, WorkspaceKind.ManagedWorktree, WorkspaceKind.Remote }.Order(),
            seen.Select(item => item.Kind).Order());
        foreach (var item in seen.Where(item => item.Name is "missing" or "replaced"))
        {
            Assert.Equal(GitStatusQuality.Unknown, item.Git.Quality);
            Assert.False(item.Git.HasBranch);
            Assert.False(item.Git.HasHead);
            Assert.False(item.Git.HasDirty);
            Assert.False(item.Git.HasModifiedFiles);
            Assert.False(item.Git.HasUntrackedFiles);
            Assert.False(item.Git.HasLocked);
        }

        var filtered = new WorkspaceServiceListWorkspacesRequest();
        filtered.Kinds.Add(WorkspaceKind.Remote);
        var filteredCall = await calls.CallAsync(caller, RoutedMethod.ListNodeWorkspaces, filtered.ToByteArray());
        var filteredResponse = WorkspaceServiceListWorkspacesResponse.Parser.ParseFrom(filteredCall.Answer!.Response);
        Assert.Null(filteredResponse.Error);
        Assert.Equal(remote, Assert.Single(filteredResponse.Value.Workspaces).WorkspaceId);

        var worktree = Assert.Single(seen, item => item.Kind == WorkspaceKind.ManagedWorktree);
        Assert.Equal(new Id { Value = ByteString.CopyFrom(first.Id) }, worktree.BaseWorkspaceId);
        Assert.Equal("synthetic-repository", worktree.RepositoryIdentity);
        Assert.Equal("main", worktree.BaseRef);
        Assert.Equal(WorkspaceState.Idle, worktree.State);
        Assert.Equal(WorkspaceConcurrency.Serial, worktree.ConcurrencyMode);
        var remoteRecord = Assert.Single(seen, item => item.Kind == WorkspaceKind.Remote);
        Assert.NotNull(remoteRecord.OriginNodeId);
        Assert.Equal(2U, remoteRecord.RemoteSlot);

        foreach (var id in new[] { managed, remote })
        {
            var get = await calls.CallAsync(caller, RoutedMethod.GetNodeWorkspace,
                new WorkspaceServiceGetWorkspaceRequest { WorkspaceId = id }.ToByteArray());
            var response = WorkspaceServiceGetWorkspaceResponse.Parser.ParseFrom(get.Answer!.Response);
            Assert.Null(response.Error);
            Assert.Equal(id, response.Value.Workspace.WorkspaceId);
            Assert.Equal(GitStatusQuality.Unknown, response.Value.Workspace.Git.Quality);
        }

        var missingGet = await calls.CallAsync(caller, RoutedMethod.GetNodeWorkspace,
            new WorkspaceServiceGetWorkspaceRequest { WorkspaceId = new Id { Value = ByteString.CopyFrom(missing.Id) } }.ToByteArray());
        var missingResponse = WorkspaceServiceGetWorkspaceResponse.Parser.ParseFrom(missingGet.Answer!.Response);
        Assert.Equal("file_changed", missingResponse.Error.Code);
        Assert.Equal("workspace_root_changed", missingResponse.Error.Details.State.Reason);
        var replacedGet = await calls.CallAsync(caller, RoutedMethod.GetNodeWorkspace,
            new WorkspaceServiceGetWorkspaceRequest { WorkspaceId = new Id { Value = ByteString.CopyFrom(replaced.Id) } }.ToByteArray());
        Assert.Equal("workspace_root_changed", WorkspaceServiceGetWorkspaceResponse.Parser.ParseFrom(replacedGet.Answer!.Response).Error.Details.State.Reason);

        // Losing a registered root does not change the catalogue generation and must not invalidate a continuation.
        request.Page.ClearCursor();
        var start = await calls.CallAsync(caller, RoutedMethod.ListNodeWorkspaces, request.ToByteArray());
        var page = WorkspaceServiceListWorkspacesResponse.Parser.ParseFrom(start.Answer!.Response);
        Assert.True(page.Value.Page.HasMore);
        request.Page.Cursor = page.Value.Page.NextCursor;
        Directory.Move(a, a + "-held");
        var continued = await calls.CallAsync(caller, RoutedMethod.ListNodeWorkspaces, request.ToByteArray());
        Assert.Null(WorkspaceServiceListWorkspacesResponse.Parser.ParseFrom(continued.Answer!.Response).Error);

        // A real metadata insert by any compatible writer changes the durable generation, so the old cursor is rejected.
        var newId = CommandIds.New();
        node.Runtime.Store.Write(transaction => transaction.Execute("""
            INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
            VALUES ($id, 1, 2, 'legacy', $root, 1, 1, 0);
            """, ("$id", newId.Value.ToByteArray()), ("$root", Path.Combine(node.Root, "legacy-record"))));
        var stale = await calls.CallAsync(caller, RoutedMethod.ListNodeWorkspaces, request.ToByteArray());
        var invalid = WorkspaceServiceListWorkspacesResponse.Parser.ParseFrom(stale.Answer!.Response);
        Assert.Equal("invalid_cursor", invalid.Error.Code);
        Assert.True(NodeShapes.IsValid(invalid));

        var remove = new WorkspaceServiceUnregisterWorkspaceRequest
        {
            Meta = Tasks.Meta(),
            WorkspaceId = new Id { Value = ByteString.CopyFrom(missing.Id) },
        };
        var removed = await calls.CallAsync(calls.Relay(Origin.Human), RoutedMethod.UnregisterNodeWorkspace, remove.ToByteArray(), remove.Meta.CommandId);
        Assert.Null(WorkspaceServiceUnregisterWorkspaceResponse.Parser.ParseFrom(removed.Answer!.Response).Error);
        Assert.True(Directory.Exists(b + "-held"));
        Assert.True(Directory.Exists(c));
    }

    [Fact(Timeout = 120_000)]
    public async Task WorkspacePreEffectErrorsUseThePublishedBoundsAndDeniedAudit()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var registration = new WorkspaceServiceRegisterWorkspaceRequest
        {
            Meta = Tasks.Meta(),
            Path = Path.Combine(node.Root, new string('x', 4097)),
            Name = "too-long",
        };
        var refused = await calls.CallAsync(caller, RoutedMethod.RegisterNodeWorkspace, registration.ToByteArray(), registration.Meta.CommandId);
        var response = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(refused.Answer!.Response);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Equal("too_large", response.Error.Code);
        Assert.Equal(ErrorCategory.Resource, response.Error.Category);
        Assert.Equal("workspace_root_path_bytes", response.Error.Details.Limit.LimitName);
        Assert.Equal("4096", response.Error.Details.Limit.Maximum.Value);
        Assert.Equal(registration.Meta.CorrelationId, response.Error.CorrelationId);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace;")));
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM audit_log WHERE operation = 'workspace.register WorkspaceService.RegisterWorkspace'
              AND decision = 3 AND outcome_summary = 'refused: too_large';
            """))! >= 1);

        var unregister = new WorkspaceServiceUnregisterWorkspaceRequest { Meta = Tasks.Meta(), WorkspaceId = CommandIds.New() };
        var first = await calls.CallAsync(caller, RoutedMethod.UnregisterNodeWorkspace, unregister.ToByteArray(), unregister.Meta.CommandId);
        var unknown = WorkspaceServiceUnregisterWorkspaceResponse.Parser.ParseFrom(first.Answer!.Response);
        Assert.Equal("not_found", unknown.Error.Code);
        Assert.Equal(unregister.Meta.CorrelationId, unknown.Error.CorrelationId);
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM audit_log WHERE operation = 'workspace.unregister WorkspaceService.UnregisterWorkspace'
              AND decision = 3 AND remote_command_id = $command AND outcome_summary = 'refused: not_found';
            """, ("$command", unregister.Meta.CommandId.Value.ToByteArray())))! >= 1);
        var replay = await calls.CallAsync(caller, RoutedMethod.UnregisterNodeWorkspace, unregister.ToByteArray(), unregister.Meta.CommandId);
        Assert.Equal(first.Answer.Response, replay.Answer!.Response);
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "linux-real")]
    public async Task LinuxInaccessibleRegisteredRootRemainsListedAndRecovers()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux directory permission semantics");
            return;
        }

        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var parent = Directory.CreateDirectory(Path.Combine(node.Root, "catalog-restricted-parent")).FullName;
        var root = Directory.CreateDirectory(Path.Combine(parent, "root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var original = File.GetUnixFileMode(parent);
        try
        {
            File.SetUnixFileMode(parent, UnixFileMode.None);
            await AssertUnavailableAsync(calls, workspace.Id);
        }
        finally
        {
            File.SetUnixFileMode(parent, original);
        }

        await AssertRecoveredAsync(calls, workspace.Id);
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task WindowsInaccessibleRegisteredRootRemainsListedAndRecovers()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows directory sharing semantics");
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "catalog-exclusive-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        using (var blocker = CreateFile(root, 0x81, 0, 0, 3, 0x02000000, 0))
        {
            Assert.False(blocker.IsInvalid, "the owned test directory must be opened with no sharing; Win32 error " + Marshal.GetLastPInvokeError());
            await AssertUnavailableAsync(calls, workspace.Id);
        }

        await AssertRecoveredAsync(calls, workspace.Id);
    }

    private static async Task AssertUnavailableAsync(RoutedCalls calls, byte[] workspace)
    {
        var caller = calls.Relay(Origin.Human);
        var listCall = await calls.CallAsync(caller, RoutedMethod.ListNodeWorkspaces, new WorkspaceServiceListWorkspacesRequest { Meta = new RequestMeta { CorrelationId = CommandIds.New() } }.ToByteArray());
        var list = WorkspaceServiceListWorkspacesResponse.Parser.ParseFrom(listCall.Answer!.Response);
        Assert.Null(list.Error);
        var recorded = Assert.Single(list.Value.Workspaces);
        Assert.Equal(workspace, recorded.WorkspaceId.Value.ToByteArray());
        Assert.Equal(GitStatusQuality.Unknown, recorded.Git.Quality);
        Assert.False(recorded.Git.HasBranch);
        Assert.False(recorded.Git.HasDirty);
        var getCall = await calls.CallAsync(caller, RoutedMethod.GetNodeWorkspace,
            new WorkspaceServiceGetWorkspaceRequest { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) } }.ToByteArray());
        var get = WorkspaceServiceGetWorkspaceResponse.Parser.ParseFrom(getCall.Answer!.Response);
        Assert.Equal("file_access_denied", get.Error.Code);
        Assert.Equal("file_access_denied", get.Error.Details.State.Reason);
    }

    private static async Task AssertRecoveredAsync(RoutedCalls calls, byte[] workspace)
    {
        var getCall = await calls.CallAsync(calls.Relay(Origin.Human), RoutedMethod.GetNodeWorkspace,
            new WorkspaceServiceGetWorkspaceRequest { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) } }.ToByteArray());
        var get = WorkspaceServiceGetWorkspaceResponse.Parser.ParseFrom(getCall.Answer!.Response);
        Assert.Null(get.Error);
        Assert.Equal(workspace, get.Value.Workspace.WorkspaceId.Value.ToByteArray());
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFile(string path, uint access, uint sharing, nint security, uint creation, uint flags, nint template);
}
