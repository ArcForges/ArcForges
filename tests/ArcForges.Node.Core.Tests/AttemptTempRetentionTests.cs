// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Tests;

/// <summary>Unproven temporary-directory cleanup leaves real files in place; this is not a successful removal test.</summary>
public sealed class AttemptTempRetentionTests
{
    [Fact(Timeout = 120_000)]
    public async Task HousekeepingRetainsUntrackedDirectoriesEvenWhenTheyAreOldAndAcrossRestart()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var root = Path.Combine(node.DataRoot, "tmp");
        var untracked = Directory.CreateDirectory(Path.Combine(root, "untracked", "nested")).FullName;
        var target = Path.Combine(untracked, "keep.txt");
        File.WriteAllText(target, "retained-untracked-fixture");
        Directory.SetLastWriteTimeUtc(Path.GetDirectoryName(untracked)!, DateTime.UtcNow.AddDays(-7));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM managed_directory;")));

        Assert.Equal(0, node.Runtime.Execution!.RemoveExpiredTemp());
        Assert.Equal("retained-untracked-fixture", File.ReadAllText(target));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        Assert.Equal(0, node.Runtime.Execution!.RemoveExpiredTemp());
        Assert.Equal("retained-untracked-fixture", File.ReadAllText(target));
    }

    [Fact(Timeout = 120_000)]
    public async Task FinishedRealAttemptRetainsItsDirectoryWhenCleanupProtectionIsUnavailable()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Sched.RequirePlatform();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, WriteFixtureToTemp(node.Root)));
        var result = task.CurrentAttempt?.Result;
        Assert.True(task.State == TaskState.Succeeded,
            $"state={task.State}; termination={result?.TerminationReason}; exit={result?.ExitCode}; detail={result?.Detail}");
        var attempt = task.CurrentAttempt!.AttemptId;
        var name = ArcForges.Client.IdText.Format(attempt);
        await Tasks.WaitForAsync(() => Sched.LogEvents(node, "execution.tmp.cleanup_unavailable")
            .Any(entry => Sched.Text(entry, "attempt") == name), Tasks.Bound, "the cleanup refusal");
        var payload = Path.Combine(Tasks.Files(node, attempt).TempDirectory, "keep.txt");
        Assert.Equal("retained", File.ReadAllText(payload).Trim());
        Assert.Equal(0, node.Runtime.Execution!.RemoveExpiredTemp());
        Assert.Equal("retained", File.ReadAllText(payload).Trim());
    }

    internal static TaskSpec WriteFixtureToTemp(string workingDirectory)
    {
        if (!OperatingSystem.IsWindows())
            return Tasks.Argv(workingDirectory, "/bin/sh", "-c", "printf retained > \"$TMPDIR/keep.txt\"");
        // CMD scripts must use the supported shell mode; passing quoted shell syntax as one ordinary argv item
        // subjects the embedded quotes to CommandLineToArgvW escaping, which CMD does not parse as shell quoting.
        return new TaskSpec
        {
            Command = new CommandSpec { Shell = new ShellCommand { Kind = ShellKind.Cmd, Script = "echo retained>\"%TEMP%\\keep.txt\"" } },
            WorkingDirectory = workingDirectory,
            Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
        };
    }
}
