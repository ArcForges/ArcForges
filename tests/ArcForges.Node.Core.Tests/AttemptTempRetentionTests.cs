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
        var spec = OperatingSystem.IsWindows()
            ? Tasks.Argv(node.Root, Tasks.Cmd, "/d", "/c", "echo retained>\"%TEMP%\\keep.txt\"")
            : Tasks.Argv(node.Root, "/bin/sh", "-c", "printf retained > \"$TMPDIR/keep.txt\"");
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, spec));
        Assert.Equal(TaskState.Succeeded, task.State);
        var attempt = task.CurrentAttempt.AttemptId;
        var name = ArcForges.Client.IdText.Format(attempt);
        await Tasks.WaitForAsync(() => Sched.LogEvents(node, "execution.tmp.cleanup_unavailable")
            .Any(entry => Sched.Text(entry, "attempt") == name), Tasks.Bound, "the cleanup refusal");
        var payload = Path.Combine(Tasks.Files(node, attempt).TempDirectory, "keep.txt");
        Assert.Equal("retained", File.ReadAllText(payload).Trim());
        Assert.Equal(0, node.Runtime.Execution!.RemoveExpiredTemp());
        Assert.Equal("retained", File.ReadAllText(payload).Trim());
    }
}
