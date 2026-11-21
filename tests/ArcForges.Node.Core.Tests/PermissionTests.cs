// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

/// <summary>The local permission matrix, verified client kind and Node operation audit.</summary>
public sealed class PermissionTests
{
    private const PermissionDecision A = PermissionDecision.Allow;
    private const PermissionDecision P = PermissionDecision.Approval;
    private const PermissionDecision D = PermissionDecision.Deny;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>11 section 1's default matrix, written out from the Design table (HUMAN, SCRIPT, AGENT) and its REMOTE command kinds.</summary>
    public static TheoryData<string, PermissionDecision, PermissionDecision, PermissionDecision, string?> Defaults => new()
    {
        { PermissionMatrix.TaskSubmit, A, A, A, "run_task" },
        { PermissionMatrix.TaskRead, A, A, A, "refresh" },
        { PermissionMatrix.TaskReadOutput, A, A, A, "read_output_tail" },
        { PermissionMatrix.TaskCancelOwn, A, A, A, "cancel_task" },
        { PermissionMatrix.TaskCancelOthers, A, P, P, "cancel_task" },
        { PermissionMatrix.TaskRetry, A, A, A, null },
        { PermissionMatrix.TaskSetPriority, A, A, P, "set_priority" },
        { PermissionMatrix.PoolPause, A, A, P, "pause_queue" },
        { PermissionMatrix.ParallelismChange, A, P, P, "set_parallelism" },
        { PermissionMatrix.ParallelismLowerOwnSession, A, P, A, "set_parallelism" },
        { PermissionMatrix.PolicyChange, A, P, P, null },
        { PermissionMatrix.ApprovalDecide, A, D, D, "decide_approval" },
        { PermissionMatrix.WorkspaceRegister, A, D, D, "register_node_workspace" },
        { PermissionMatrix.WorkspaceUnregister, A, D, D, "unregister_node_workspace" },
        { PermissionMatrix.WorkspaceRead, A, A, A, "list_node_workspaces" },
        { PermissionMatrix.FileRead, A, A, A, "read_node_file" },
        { PermissionMatrix.FileWrite, A, P, D, null },
        { PermissionMatrix.FileRemove, A, P, D, null },
        { PermissionMatrix.CleanupPlan, A, A, A, null },
        { PermissionMatrix.CleanupExecute, A, P, P, null },
        { PermissionMatrix.ProcessAdopt, A, D, D, null },
        { PermissionMatrix.ProcessTerminate, A, P, P, null },
        { PermissionMatrix.Integrations, A, D, D, null },
        { PermissionMatrix.SignInRead, A, A, D, null },
        { PermissionMatrix.NodeStop, A, A, D, "stop_node" },
        { PermissionMatrix.NodeUpdate, A, A, D, "apply_update" },
        { PermissionMatrix.NodeRollback, A, D, D, null },
        { PermissionMatrix.TaskPause, A, A, P, null },
        { PermissionMatrix.TaskPurge, A, D, D, null },
        { PermissionMatrix.NodeSettings, A, P, D, null },
        { PermissionMatrix.NodeRename, A, A, D, null },
        { PermissionMatrix.NotificationsMarkRead, A, D, D, null },
        { PermissionMatrix.PolicyRetrySafety, A, D, D, null },
        { PermissionMatrix.PolicyPermissions, A, D, D, null },
        { PermissionMatrix.PolicyCenterRouted, A, D, D, null },
    };

    [Theory]
    [MemberData(nameof(Defaults))]
    public void TheDefaultMatrixDecidesPerOrigin(string operation, PermissionDecision human, PermissionDecision script, PermissionDecision agent, string? remoteKind)
    {
        Assert.Equal(human, PermissionMatrix.Decide(Origin.Human, operation, []).Decision);
        Assert.Equal(script, PermissionMatrix.Decide(Origin.Script, operation, []).Decision);
        Assert.Equal(agent, PermissionMatrix.Decide(Origin.Agent, operation, []).Decision);
        var remote = PermissionMatrix.Decide(Origin.Remote, operation, []);
        Assert.Equal(remoteKind is null ? D : PermissionDecision.RemotePolicy, remote.Decision);
        Assert.Equal(remoteKind, PermissionMatrix.Find(operation)!.RemoteKind);

        // Origins the matrix does not grant fail closed.
        Assert.Equal(D, PermissionMatrix.Decide(Origin.Unspecified, operation, []).Decision);
        Assert.Equal(D, PermissionMatrix.Decide(Origin.Guest, operation, []).Decision);
        Assert.Equal(PermissionMatrix.DefaultSource, PermissionMatrix.Decide(Origin.Script, operation, []).Source);
    }

    [Fact]
    public void ASignInFlowCanNeverBeReadByAnAgent()
    {
        // AF-CTR-04 N2 (node-12 item 2, N2 decision F-3): GetSignInFlow is HUMAN A, SCRIPT A, AGENT D and the row is fixed, because the
        // flow holds the approval URL and the user code; an override can neither admit an agent nor deny a script.
        var row = PermissionMatrix.Find(PermissionMatrix.SignInRead)!;
        Assert.True(row.Fixed);
        List<PermissionOverride> overrides =
        [
            new() { Operation = PermissionMatrix.SignInRead, Origin = Origin.Agent, Decision = A },
            new() { Operation = PermissionMatrix.SignInRead, Origin = Origin.Script, Decision = D },
        ];
        Assert.Equal(D, PermissionMatrix.Decide(Origin.Agent, PermissionMatrix.SignInRead, overrides).Decision);
        Assert.Equal(A, PermissionMatrix.Decide(Origin.Script, PermissionMatrix.SignInRead, overrides).Decision);
        Assert.NotNull(PermissionMatrix.Valid(overrides[0]));
    }

    [Fact]
    public void WorkspaceMutationRemainsHumanOnlyAcrossLocalAndRoutedCells()
    {
        foreach (var operation in new[] { PermissionMatrix.WorkspaceRegister, PermissionMatrix.WorkspaceUnregister })
        {
            var attemptedOverride = new PermissionOverride { Operation = operation, Origin = Origin.Agent, Decision = A };
            Assert.True(PermissionMatrix.Find(operation)!.Fixed);
            Assert.NotNull(PermissionMatrix.Valid(attemptedOverride));
            Assert.Equal(A, PermissionMatrix.Decide(Origin.Human, operation, []).Decision);
            Assert.Equal(D, PermissionMatrix.Decide(Origin.Agent, operation, [attemptedOverride]).Decision);
            Assert.Equal(D, PermissionMatrix.Decide(Origin.Script, operation, []).Decision);
            Assert.Equal(A, PermissionMatrix.DecideRouted(operation, Origin.Human, []).Decision);
            Assert.Equal(A, PermissionMatrix.DecideRouted(operation, Origin.Remote, []).Decision);
            Assert.Equal(D, PermissionMatrix.DecideRouted(operation, Origin.Script, []).Decision);
            Assert.Equal(D, PermissionMatrix.DecideRouted(operation, Origin.Agent, [attemptedOverride]).Decision);
        }

        Assert.Equal(A, PermissionMatrix.DecideRouted(PermissionMatrix.WorkspaceRead, Origin.Agent, []).Decision);
    }

    [Fact]
    public void OverridesChangeOnlyTheirOriginAndNeverAHumanOrFixedRow()
    {
        Assert.Equal(PermissionMatrix.Rows.Count, Defaults.Count);
        List<PermissionOverride> overrides =
        [
            new() { Operation = PermissionMatrix.ParallelismChange, Origin = Origin.Script, Decision = A },
            new() { Operation = PermissionMatrix.TaskSetPriority, Origin = Origin.Agent, Decision = D },
            new() { Operation = PermissionMatrix.TaskSetPriority, Origin = Origin.Agent, Decision = A },
            new() { Operation = PermissionMatrix.ApprovalDecide, Origin = Origin.Agent, Decision = A },
            new() { Operation = PermissionMatrix.TaskSubmit, Origin = Origin.Remote, Decision = D },
        ];
        var verdict = PermissionMatrix.Decide(Origin.Script, PermissionMatrix.ParallelismChange, overrides);
        Assert.Equal((A, "policy permissions[0]"), (verdict.Decision, verdict.Source));
        Assert.Equal(P, PermissionMatrix.Decide(Origin.Agent, PermissionMatrix.ParallelismChange, overrides).Decision);
        Assert.Equal((A, "policy permissions[2]"), (PermissionMatrix.Decide(Origin.Agent, PermissionMatrix.TaskSetPriority, overrides).Decision,
            PermissionMatrix.Decide(Origin.Agent, PermissionMatrix.TaskSetPriority, overrides).Source));

        // The approver must be HUMAN (fixed row); a REMOTE override can only deny.
        Assert.Equal(D, PermissionMatrix.Decide(Origin.Agent, PermissionMatrix.ApprovalDecide, overrides).Decision);
        Assert.Equal(D, PermissionMatrix.Decide(Origin.Remote, PermissionMatrix.TaskSubmit, overrides).Decision);
        Assert.Equal(PermissionDecision.RemotePolicy, PermissionMatrix.Decide(Origin.Remote, PermissionMatrix.TaskSubmit, []).Decision);
        Assert.Equal(RiskClass.High, PermissionMatrix.Decide(Origin.Remote, PermissionMatrix.TaskSubmit, []).RemoteRisk);

        // Validation (policy.proto: a matrix operation; SCRIPT, AGENT or REMOTE; HUMAN rows are fixed).
        Assert.Null(PermissionMatrix.Valid(overrides[0]));
        Assert.Contains("fixed", PermissionMatrix.Valid(overrides[3]), StringComparison.Ordinal);
        Assert.Contains("operation", PermissionMatrix.Valid(new PermissionOverride { Operation = "task.fly", Origin = Origin.Agent, Decision = A }), StringComparison.Ordinal);
        Assert.Contains("HUMAN rows are fixed", PermissionMatrix.Valid(new PermissionOverride { Operation = PermissionMatrix.TaskSubmit, Origin = Origin.Human, Decision = D }),
            StringComparison.Ordinal);
        Assert.NotNull(PermissionMatrix.Valid(new PermissionOverride { Operation = PermissionMatrix.TaskSubmit, Origin = Origin.Remote, Decision = A }));
    }

    /// <summary>
    /// The node's own operations per origin (11 section 1 and node.proto): stopping the node and renaming it are denied to AGENT callers,
    /// marking notifications read is HUMAN-only; each refusal and each privileged action that ran is audited.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task NodeOperationsFollowTheMatrixAndAreAudited()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        Assert.Equal("permission_denied", (await agent.Node.StopNodeAsync(new NodeServiceStopNodeRequest { Meta = InProcessNode.Command() }, cancellationToken: Ct)).Error?.Code);
        Assert.Equal("permission_denied", (await agent.Node.RenameNodeAsync(new NodeServiceRenameNodeRequest { Meta = InProcessNode.Command(), Name = "agent's" }, cancellationToken: Ct)).Error?.Code);
        Assert.Null((await script.Node.RenameNodeAsync(new NodeServiceRenameNodeRequest { Meta = InProcessNode.Command(), Name = "script's" }, cancellationToken: Ct)).Error);
        var mark = new NodeServiceMarkNotificationsReadRequest { UpTo = ProtoTime.ToInstant(DateTimeOffset.UtcNow) };
        Assert.Equal("permission_denied", (await script.Node.MarkNotificationsReadAsync(mark, cancellationToken: Ct)).Error?.Code);
        Assert.Null((await human.Node.MarkNotificationsReadAsync(mark, cancellationToken: Ct)).Error);
        var audit = node.Runtime.Store.Read(reader => AuditLog.Recent(reader));
        Assert.Contains(audit, entry => entry.Operation == PermissionMatrix.NodeStop + " NodeService.StopNode" && entry.Decision == D && entry.Actor.Origin == Origin.Agent);
        Assert.Contains(audit, entry => entry.Operation == PermissionMatrix.NodeRename + " NodeService.RenameNode" && entry.Decision == D);
        Assert.Contains(audit, entry => entry.Operation == PermissionMatrix.NotificationsMarkRead + " NodeService.MarkNotificationsRead" && entry.Decision == D);
        // Review round 1: the allowed executions of privileged actions are audited too (RenameNode by SCRIPT, MarkNotificationsRead by HUMAN).
        Assert.Contains(audit, entry => entry.Operation == PermissionMatrix.NodeRename + " NodeService.RenameNode" && entry.Decision == A
            && entry.Actor.Origin == Origin.Script && entry.Outcome == "done: rename the node to 'script's'");
        Assert.Contains(audit, entry => entry.Operation == PermissionMatrix.NotificationsMarkRead + " NodeService.MarkNotificationsRead" && entry.Decision == A
            && entry.Actor.Origin == Origin.Human && entry.Outcome == "done: mark notifications read up to a time");

        // StopNode by a HUMAN runs, audited in its own transaction.
        Assert.Null((await human.Node.StopNodeAsync(new NodeServiceStopNodeRequest { Meta = InProcessNode.Command() }, cancellationToken: Ct)).Error);
        Assert.Equal(0, await node.Exit.WaitAsync(TimeSpan.FromSeconds(30), Ct));
        using var store = ArcForges.Node.Store.NodeStore.Open(new ArcForges.Node.Store.NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "audit" });
        Assert.Contains(store.Read(reader => AuditLog.Recent(reader)), entry => entry.Operation == PermissionMatrix.NodeStop + " NodeService.StopNode" && entry.Decision == A
            && entry.Actor.Origin == Origin.Human && entry.Outcome == "done: stop the node");
    }

    /// <summary>
    /// The client kind is verified against the peer (11 section 1): an executable verifies a kind by path or by its content (a version
    /// directory reached through a link), the Desktop kind only by the Desktop executable; a CLI under a registered agent root is AGENT.
    /// </summary>
    [Fact(Timeout = 60_000)]
    public async Task TheClientKindIsVerifiedAgainstThePeerExecutableAndAgentRoots()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var root = Directory.CreateTempSubdirectory("arcforges-images-").FullName;
        try
        {
            var node = Path.Combine(root, "arcforges");
            var desktop = Path.Combine(root, "arcforges-desktop");
            var copy = Path.Combine(root, "other", "arcforges");
            Directory.CreateDirectory(Path.GetDirectoryName(copy)!);
            await File.WriteAllTextAsync(node, "node binary", Ct);
            await File.WriteAllTextAsync(desktop, "desktop binary", Ct);
            await File.WriteAllTextAsync(copy, "node binary", Ct);
            var images = new ClientImages([node], [desktop]);
            Assert.True(images.Verifies(ClientKind.Cli, node));
            Assert.True(images.Verifies(ClientKind.Cli, copy), "the same executable reached through another path (content)");
            Assert.True(images.Verifies(ClientKind.McpAdapter, node));
            Assert.False(images.Verifies(ClientKind.Desktop, node), "the node's executable is not the Desktop");
            Assert.True(images.Verifies(ClientKind.Desktop, desktop));
            Assert.False(images.Verifies(ClientKind.Cli, desktop));
            Assert.False(images.Verifies(ClientKind.Desktop, null));
            Assert.False(images.Verifies(ClientKind.Supervisor, node));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        // A CLI under a registered agent root is AGENT (AF-AI-01 registers roots): this process as a root covers its real child, and a root
        // whose recorded start differs (a reused ID) covers nothing.
        var roots = new AgentRoots();
        var started = ProtoTime.ToDateTimeOffset(ClientProcess.Identity(Environment.ProcessId)!.StartTime)!.Value;
        using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Tasks.TestLoad, ["hold", "--hold-ms", "30000"])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        try
        {
            Assert.False(roots.Contains(child.Id));
            roots.Register(Environment.ProcessId, started.AddMinutes(-5));
            Assert.False(roots.Contains(child.Id), "a root whose start does not match is another process");
            roots.Register(Environment.ProcessId, started);
            Assert.True(roots.Contains(Environment.ProcessId));
            Assert.True(roots.Contains(child.Id), "the child descends from the registered root");
            roots.Remove(Environment.ProcessId);
            Assert.False(roots.Contains(child.Id));
        }
        finally
        {
            child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync(Ct);
        }
    }
}
