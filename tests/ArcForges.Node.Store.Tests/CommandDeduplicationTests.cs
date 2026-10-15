// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.Node.Store.Tests;

/// <summary>R-EXE-016 and contracts README section 6: idempotent replay and CONFLICT/command_id_reused, with FULL commits.</summary>
public sealed class CommandDeduplicationTests
{
    private const string Submit = "arcforges.node.v1.TaskService/SubmitTask";

    [Fact]
    public void AReplayReturnsTheStoredResponseWithoutExecutingAgain()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var request = Request("dotnet test", out var commandId);
        var executions = 0;
        byte[] first;
        using (var store = root.Open(clock))
        {
            var result = store.Commands.Execute(commandId, Submit, PayloadDigest.Compute(request), Origin.Agent, transaction =>
            {
                executions++;
                var taskId = Rows.InsertTask(transaction);
                return Response(commandId, taskId).ToByteArray();
            });

            Assert.False(result.Replayed);
            Assert.Null(result.Error);
            first = result.Outcome!.Value.ToArray();
        }

        // The record is durable: a restarted node replays it.
        clock.Advance(TimeSpan.FromHours(23));
        using (var store = root.Open(clock))
        {
            var retried = Request("dotnet test", out _, commandId, correlation: true);
            var replay = store.Commands.Execute(commandId, Submit, PayloadDigest.Compute(retried), Origin.Agent, _ =>
            {
                executions++;
                return [];
            });

            Assert.True(replay.Replayed);
            Assert.Null(replay.Error);
            Assert.Equal(first, replay.Outcome!.Value.ToArray());
            Assert.Equal(1, executions);
            Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
            var response = TaskServiceSubmitTaskResponse.Parser.ParseFrom(replay.Outcome.Value.Span);
            Assert.Equal(commandId, response.Value.Receipt.CommandId.Value.ToByteArray());
        }
    }

    [Fact]
    public void ADifferentPayloadWithTheSameCommandIdIsACommandIdReusedConflict()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        var original = Request("cargo build", out var commandId);
        store.Commands.Execute(commandId, Submit, PayloadDigest.Compute(original), Origin.Script, transaction =>
            Response(commandId, Rows.InsertTask(transaction)).ToByteArray());

        var executed = false;
        var different = Request("cargo test", out _, commandId);
        var conflict = store.Commands.Execute(commandId, Submit, PayloadDigest.Compute(different), Origin.Script, _ =>
        {
            executed = true;
            return [];
        });

        Assert.False(executed);
        Assert.False(conflict.Replayed);
        Assert.Null(conflict.Outcome);
        var error = Assert.IsType<ArcError>(conflict.Error);
        Assert.Equal("command_id_reused", error.Code);
        Assert.Equal(ErrorCategory.Conflict, error.Category);
        Assert.Equal("error.conflict.command_id_reused", error.MessageKey);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);

        // The same ID for another method is a different payload as well.
        var otherMethod = store.Commands.Execute(commandId, "arcforges.node.v1.TaskService/CancelTask", PayloadDigest.Compute(original), Origin.Script, _ => []);
        Assert.Equal("command_id_reused", otherMethod.Error?.Code);
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
    }

    [Fact]
    public void ThePayloadDigestIgnoresOnlyTheRequestMeta()
    {
        var first = Request("npm test", out var commandId);
        var retry = Request("npm test", out _, commandId, correlation: true);
        var other = Request("npm ci", out _, commandId);

        Assert.Equal(PayloadDigest.Compute(first), PayloadDigest.Compute(retry));
        Assert.NotEqual(first.ToByteArray(), retry.ToByteArray());
        Assert.NotEqual(PayloadDigest.Compute(first), PayloadDigest.Compute(other));
        Assert.Equal(32, PayloadDigest.Compute(first).Length);
    }

    [Fact]
    public void DeduplicationCommitsUseFullSynchronousAndOtherWritesNormal()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        var request = Request("make", out var commandId);
        long? during = null;

        store.Commands.Execute(commandId, Submit, PayloadDigest.Compute(request), Origin.Human, transaction =>
        {
            during = (long?)transaction.Scalar("PRAGMA synchronous;");
            return [1];
        });

        Assert.Equal(2L, during); // FULL
        Assert.Equal(1L, store.Write(transaction => (long?)transaction.Scalar("PRAGMA synchronous;"))); // NORMAL again
        var notFull = Assert.Throws<InvalidOperationException>(() => store.Write(transaction =>
            CommandDeduplication.Begin(transaction, StoreIds.NewUuid7(store.Clock), Submit, new byte[32], Origin.Human)));
        Assert.Contains("synchronous=FULL", notFull.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AFailedExecutionRecordsNothingAndCanBeRetried()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        var request = Request("pytest", out var commandId);
        var digest = PayloadDigest.Compute(request);

        Assert.Throws<IOException>(() => store.Commands.Execute(commandId, Submit, digest, Origin.Agent, transaction =>
        {
            Rows.InsertTask(transaction);
            throw new IOException("disk full");
        }));

        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
        var retried = store.Commands.Execute(commandId, Submit, digest, Origin.Agent, _ => [7]);
        Assert.False(retried.Replayed);
        Assert.Equal([7], retried.Outcome!.Value.ToArray());
    }

    [Fact]
    public void RecordsExpireAfter24HoursAndHousekeepingDeletesThem()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var request = Request("ctest", out var commandId);
        store.Commands.Execute(commandId, Submit, PayloadDigest.Compute(request), Origin.Agent, _ => [1]);

        clock.Advance(CommandDeduplication.Window - TimeSpan.FromSeconds(1));
        Assert.Equal(0, store.Commands.PurgeExpired());
        Assert.Equal("command_id_reused", store.Commands.Execute(commandId, Submit, PayloadDigest.Compute(Request("other", out _, commandId)), Origin.Agent, _ => []).Error?.Code);

        clock.Advance(TimeSpan.FromSeconds(1));
        var reused = store.Commands.Execute(commandId, Submit, PayloadDigest.Compute(Request("other", out _, commandId)), Origin.Agent, _ => [2]);
        Assert.False(reused.Replayed);
        Assert.Equal([2], reused.Outcome!.Value.ToArray());

        clock.Advance(CommandDeduplication.Window);
        Assert.Equal(1, store.Commands.PurgeExpired());
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
    }

    [Fact]
    public void AStartedCommandWithoutOutcomeIsInProgress()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        var id = StoreIds.NewUuid7(store.Clock);
        var digest = new byte[32];

        store.Write(transaction => Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id, "job", digest, Origin.Human).Status), CommitDurability.Full);
        var again = store.Write(transaction => CommandDeduplication.Begin(transaction, id, "job", digest, Origin.Human), CommitDurability.Full);

        Assert.Equal(DedupStatus.InProgress, again.Status);
        Assert.Throws<InvalidOperationException>(() => store.Commands.Execute(id, "job", digest, Origin.Human, _ => []));
        store.Write(transaction => CommandDeduplication.Complete(transaction, id, [9]), CommitDurability.Full);
        Assert.Equal(DedupStatus.Replay, store.Write(transaction => CommandDeduplication.Begin(transaction, id, "job", digest, Origin.Human), CommitDurability.Full).Status);
    }

    private static TaskServiceSubmitTaskRequest Request(string script, out byte[] commandId, byte[]? reuse = null, bool correlation = false)
    {
        commandId = reuse ?? Guid.CreateVersion7().ToByteArray(bigEndian: true);
        var meta = new RequestMeta { CommandId = new Id { Value = ByteString.CopyFrom(commandId) } };
        if (correlation)
        {
            meta.CorrelationId = new Id { Value = ByteString.CopyFrom(Guid.NewGuid().ToByteArray()) };
        }

        return new TaskServiceSubmitTaskRequest
        {
            Meta = meta,
            Spec = new TaskSpec
            {
                Command = new CommandSpec { Shell = new ShellCommand { Kind = ShellKind.Bash, Script = script } },
                WorkingDirectory = "/work",
            },
        };
    }

    private static TaskServiceSubmitTaskResponse Response(byte[] commandId, byte[] taskId) => new()
    {
        Value = new TaskServiceSubmitTaskValue
        {
            Receipt = new Receipt { CommandId = new Id { Value = ByteString.CopyFrom(commandId) }, Effect = EffectCertainty.Happened },
            TaskId = new Id { Value = ByteString.CopyFrom(taskId) },
            State = TaskState.Queued,
        },
    };
}
