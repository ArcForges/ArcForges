// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// AF-CTR-05 N2-11/12: the real test-mode node without its SCRIPT allowance refuses a noninteractive CLI; a real Linux pty CLI or a
/// Windows Desktop-kind test connection can submit locally, and the resulting task is marked local diagnostic. The Windows connection uses
/// the isolated test-mode image hook, not the actual desktop application.
/// </summary>
[Trait("loop", "local")]
public sealed class LocalDiagnosticTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 180_000)]
    [Trait("env", "linux-real")]
    public async Task AHumanCliInARealPtyRunsALocalDiagnosticTask()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux() && File.Exists("/usr/bin/script"), "the HUMAN CLI pty case runs on Linux");
        Assert.SkipWhen(ArcForges.Tests.SystemdTestEnvironment.SkipReason is not null, ArcForges.Tests.SystemdTestEnvironment.SkipReason ?? string.Empty);
        await using var node = TestNode.Create();
        node.Environment[LocalSubmission.Variable] = null;
        await node.StartNodeAsync();
        await AssertScriptRefusedAsync(node);
        using var cli = CloudSignInHostTests.Pty(node, "run -- /bin/echo n2b-local-diagnostic");
        Assert.Equal(0, await cli.WaitExitAsync(TimeSpan.FromSeconds(90)));
        Assert.Contains("n2b-local-diagnostic", cli.Text, StringComparison.Ordinal);
        await using var human = await node.HumanChannelAsync();
        var list = await human.Tasks.ListTasksAsync(new TaskServiceListTasksRequest { Meta = Meta() }, cancellationToken: Ct);
        Assert.Null(list.Error);
        var task = Assert.Single(list.Value.Tasks);
        Assert.Equal((TaskState.Succeeded, Origin.Human, ClientKind.Cli, true), (task.State, task.Owner.Origin, task.Owner.ClientKind, task.LocalDiagnostic));
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    public async Task AVerifiedDesktopKindRunsALocalDiagnosticTaskOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "the Desktop-kind Windows case runs on Windows");
        await using var node = TestNode.Create();
        node.Environment[LocalSubmission.Variable] = null;
        await node.StartNodeAsync();
        await AssertScriptRefusedAsync(node);
        await using var human = await node.HumanChannelAsync();
        var argv = new ArgvCommand();
        argv.Argv.Add(new[] { TestNode.TestLoad, "hold", "--hold-ms", "100" });
        var submitted = await human.Tasks.SubmitTaskAsync(new TaskServiceSubmitTaskRequest
        {
            Meta = Meta(),
            Spec = new TaskSpec { Command = new CommandSpec { Argv = argv }, WorkingDirectory = node.Root, Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node } },
        }, cancellationToken: Ct);
        Assert.Null(submitted.Error);
        var waited = await human.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest { Meta = Meta(), TaskId = submitted.Value.TaskId, Target = WaitTarget.Terminal, WaitMs = 50_000 },
            deadline: DateTime.UtcNow.AddSeconds(58), cancellationToken: Ct);
        Assert.True(waited.Error is null && waited.Value.Reached, "the Desktop-kind task must end");
        var task = waited.Value.Task;
        Assert.Equal((TaskState.Succeeded, Origin.Human, ClientKind.Desktop, true), (task.State, task.Owner.Origin, task.Owner.ClientKind, task.LocalDiagnostic));
    }

    private static async Task AssertScriptRefusedAsync(TestNode node)
    {
        var result = await node.CliBytesAsync(TimeSpan.FromSeconds(30), "run", "--", TestNode.TestLoad, "hold", "--hold-ms", "100");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("AUTHORIZATION/permission_denied", Encoding.UTF8.GetString(result.Stderr), StringComparison.Ordinal);
    }

    private static RequestMeta Meta() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
}
