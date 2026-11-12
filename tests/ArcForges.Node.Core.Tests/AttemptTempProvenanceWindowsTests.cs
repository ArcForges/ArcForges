// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual Windows directory creation and store provenance; neither test performs cleanup.</summary>
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class AttemptTempProvenanceWindowsTests
{
    [Fact(Timeout = 120_000)]
    public async Task ARealAttemptPersistsItsOwnerAndTheIdentityOfItsCreatedDirectory()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Native Windows directory creation.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var spec = Tasks.Argv(node.Root, Tasks.Cmd, "/d", "/c", "echo retained>\"%TEMP%\\keep.txt\"");
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, spec));
        Assert.Equal(TaskState.Succeeded, task.State);
        var attempt = task.CurrentAttempt.AttemptId;
        var name = IdText.Format(attempt);
        await Tasks.WaitForAsync(() => Sched.LogEvents(node, "execution.tmp.cleanup_unavailable")
            .Any(entry => Sched.Text(entry, "attempt") == name), Tasks.Bound, "the retained attempt directory");

        var tempRoot = Path.Combine(node.DataRoot, "tmp");
        using var root = WorkspacePath.OpenRoot(tempRoot);
        var child = root.OpenDirectory(name);
        var expectedRoot = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        var expectedChild = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(child));
        node.Runtime.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("""
                SELECT m.state, m.owner_kind, m.owner_id, m.root_class, m.relative_path, p.root_platform,
                       p.root_identity, p.directory_identity, p.owner, t.owner, r.path
                FROM file_attempt_temp_identity p
                JOIN managed_directory m ON m.directory_id = p.directory_id
                JOIN attempt a ON a.attempt_id = p.attempt_id
                JOIN task t ON t.task_id = a.task_id AND t.task_id = p.task_id
                JOIN root_location r ON r.root_class = m.root_class
                WHERE p.attempt_id = $attempt;
                """);
            command.Parameters.AddWithValue("$attempt", attempt.Value.ToByteArray());
            using var row = command.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal(2, row.GetInt32(0));
            Assert.Equal(1, row.GetInt32(1));
            Assert.Equal(attempt.Value.ToByteArray(), (byte[])row.GetValue(2));
            Assert.Equal("tmp", row.GetString(3));
            Assert.Equal(name, row.GetString(4));
            Assert.Equal(expectedRoot.Platform, row.GetInt32(5));
            Assert.Equal(expectedRoot.Bytes, (byte[])row.GetValue(6));
            Assert.Equal(expectedChild.Bytes, (byte[])row.GetValue(7));
            Assert.Equal((byte[])row.GetValue(9), (byte[])row.GetValue(8));
            Assert.Equal(root.RootPath, row.GetString(10), ignoreCase: true);
            Assert.False(row.Read());
            return 0;
        });
        Assert.Equal("retained", File.ReadAllText(Path.Combine(tempRoot, name, "keep.txt")).Trim());
        Assert.Equal(0, node.Runtime.Execution!.RemoveExpiredTemp());
    }

    [Fact]
    public void AnExistingDirectoryIsNeverAdoptedAsANewAttemptDirectory()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Native Windows directory creation.");
        var temporary = Directory.CreateTempSubdirectory("arcforges-attempt-provenance-").FullName;
        try
        {
            var existing = Directory.CreateDirectory(Path.Combine(temporary, "occupied")).FullName;
            var file = Path.Combine(existing, "keep.txt");
            File.WriteAllText(file, "unowned-fixture");
            using var root = WorkspacePath.OpenRoot(temporary);
            var before = WorkspacePath.Identity(root.OpenDirectory("occupied"));
            Assert.Throws<WorkspacePathException>(() => root.CreateWindowsAttemptDirectory("occupied"));
            Assert.True(before.SameObject(WorkspacePath.Identity(root.OpenDirectory("occupied"))));
            Assert.Equal("unowned-fixture", File.ReadAllText(file));
        }
        finally
        {
            Directory.Delete(temporary, recursive: true);
        }
    }
}
