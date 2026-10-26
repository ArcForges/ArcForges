// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real RPC purge and replay over real SQLite/GCM, native attempts and an isolated external key backend (MR-14).</summary>
public sealed class PurgeSecretErasureTests
{
    [Theory(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    [InlineData(32, false)]
    [InlineData(8192, false)]
    [InlineData(32, true)]
    [InlineData(8192, true)]
    public async Task AManualPurgeCheckpointsOrReportsItsCommittedEffectAndReplaysOnWindows(int valueLength, bool holdSnapshot)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await PurgeAsync(valueLength, holdSnapshot);
    }

    [Theory(Timeout = 120_000)]
    [Trait("env", "linux-real")]
    [InlineData(32, false)]
    [InlineData(8192, false)]
    [InlineData(32, true)]
    [InlineData(8192, true)]
    public async Task AManualPurgeCheckpointsOrReportsItsCommittedEffectAndReplaysOnLinux(int valueLength, bool holdSnapshot)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "The Linux execution platform.");
        await PurgeAsync(valueLength, holdSnapshot);
    }

    private static async Task PurgeAsync(int valueLength, bool holdSnapshot)
    {
        var cancellation = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var spec = OperatingSystem.IsWindows()
            ? Tasks.Argv(node.Root, Tasks.Cmd, "/d", "/c", "exit 0")
            : Tasks.Argv(node.Root, "/bin/sh", "-c", "exit 0");
        spec.Environment.Set["API_TOKEN"] = new string('s', valueLength);
        var taskId = await Tasks.SubmitAsync(channel, spec);
        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, taskId)).State);
        var store = node.Runtime.Store;
        var ciphertext = store.Read(reader => (byte[])reader.Scalar(
            "SELECT ciphertext FROM task_secret WHERE task_id = $id;", ("$id", taskId.Value.ToByteArray()))!);
        Assert.True(store.Checkpoint());
        Assert.True(ContainsCiphertext(store.DatabasePath, ciphertext));

        using var snapshot = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = store.DatabasePath, Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        snapshot.Open();
        using var transaction = holdSnapshot ? snapshot.BeginTransaction(deferred: true) : null;
        using var query = snapshot.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = "SELECT ciphertext FROM task_secret WHERE task_id = $id;";
        query.Parameters.AddWithValue("$id", taskId.Value.ToByteArray());
        if (holdSnapshot)
        {
            Assert.Equal(ciphertext, (byte[])query.ExecuteScalar()!);
        }

        var request = new TaskServicePurgeTaskRecordRequest { Meta = Tasks.Meta(), TaskId = taskId };
        var purged = await channel.Tasks.PurgeTaskRecordAsync(request, deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: cancellation);
        if (holdSnapshot)
        {
            Assert.NotNull(purged.Error);
            Assert.Equal("internal", purged.Error.Code);
            Assert.Equal(ErrorCategory.Internal, purged.Error.Category);
            Assert.Equal(EffectCertainty.Happened, purged.Error.Effect);
            Assert.Equal(RetryMode.AfterTime, purged.Error.Retry.Mode);
            Assert.Equal(TaskSecrets.PurgedKeyId, store.Read(reader => reader.Scalar("SELECT key_id FROM task_secret WHERE task_id = $id;",
                ("$id", taskId.Value.ToByteArray()))));
            Assert.Equal(ciphertext, (byte[])query.ExecuteScalar()!);
            Assert.True(ContainsCiphertext(store.DatabasePath, ciphertext));
        }
        else
        {
            Assert.Null(purged.Error);
            Assert.Equal(EffectCertainty.Happened, purged.Value.Receipt.Effect);
            Assert.False(ContainsCiphertext(store.DatabasePath, ciphertext));
        }

        // Release the real blocking reader, then replay identical bytes under the same command ID.
        transaction?.Dispose();
        snapshot.Dispose();
        var replay = await channel.Tasks.PurgeTaskRecordAsync(request, deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: cancellation);
        Assert.Null(replay.Error);
        Assert.Equal(request.Meta.CommandId, replay.Value.Receipt.CommandId);
        Assert.Equal(EffectCertainty.Happened, replay.Value.Receipt.Effect);
        Assert.False(ContainsCiphertext(store.DatabasePath, ciphertext));
        Assert.Equal("ok", store.Read(reader => reader.Scalar("PRAGMA integrity_check;")));
        var retry = await channel.Tasks.RetryTaskAsync(new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = taskId },
            cancellationToken: cancellation);
        Assert.Equal("not_found", retry.Error.Code);
    }

    private static bool ContainsCiphertext(string database, byte[] ciphertext)
    {
        foreach (var path in new[] { database, database + "-wal" }.Where(File.Exists))
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            var bytes = copy.ToArray();
            foreach (var start in new[] { 0, ciphertext.Length / 2, ciphertext.Length - 16 })
            {
                if (bytes.AsSpan().IndexOf(ciphertext.AsSpan(start, 16)) >= 0)
                {
                    return true;
                }
            }
        }

        return false;
    }
}
