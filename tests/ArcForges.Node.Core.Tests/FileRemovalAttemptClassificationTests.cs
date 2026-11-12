// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real task, SQLite and routed dispatcher; the test seam is not a signed channel or an actual Center.</summary>
public sealed class FileRemovalAttemptClassificationTests
{
    [Fact(Timeout = 120_000)]
    public async Task RunningOwnAttemptIsStillInUse()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Sched.RequirePlatform();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var submit = new TaskServiceSubmitTaskRequest
        {
            Meta = Tasks.Meta(),
            Spec = Sched.Hold(node, Path.Combine(node.Root, "running-marker"), 60_000),
        };
        var submitted = await calls.SubmitAsync(caller, submit);
        Assert.Equal(RoutedOutcome.Executed, submitted.Answer!.Outcome);
        Assert.Null(submitted.Response!.Error);
        var taskId = submitted.Response.Value.TaskId;
        try
        {
            var attempt = await Tasks.RunningAsync(human, taskId);
            var request = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.AttemptId };
            var result = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
            var refusal = FileServicePlanRemovalResponse.Parser.ParseFrom(result.Answer!.Response);
            Assert.Equal(ErrorCategory.State, refusal.Error.Category);
            Assert.Equal("in_use", refusal.Error.Code);
            Assert.Equal("attempt_in_use", refusal.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, refusal.Error.Effect);
            Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        }
        finally
        {
            var cancelled = await calls.CancelAsync(caller, taskId);
            Assert.Null(cancelled.Response!.Error);
            await Tasks.WaitAsync(human, taskId);
        }
    }

    [Fact(Timeout = 180_000)]
    public async Task FinishedOwnAttemptWithoutDirectoryProvenanceRefusesAndReplaysWithoutAPlan()
    {
        Sched.RequirePlatform();
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var submit = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = AttemptTempRetentionTests.WriteFixtureToTemp(node.Root) };
        var submitted = await calls.SubmitAsync(caller, submit);
        Assert.Equal(RoutedOutcome.Executed, submitted.Answer!.Outcome);
        Assert.Null(submitted.Response!.Error);

        Id attempt;
        string payload;
        const string fixtureBody = "attempt-plan-fixture-body-must-not-be-persisted-5351";
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            var task = await Tasks.WaitAsync(human, submitted.Response.Value.TaskId);
            Assert.Equal(TaskState.Succeeded, task.State);
            attempt = task.CurrentAttempt!.AttemptId;
            payload = Path.Combine(Tasks.Files(node, attempt).TempDirectory, "keep.txt");
            Assert.Equal("retained", File.ReadAllText(payload).Trim());
            File.WriteAllText(payload, fixtureBody);

            var attemptBytes = attempt.Value.ToByteArray();
            long directoryCount() => (long)node.Runtime.Store.Read(reader => reader.Scalar(
                "SELECT count(*) FROM managed_directory WHERE owner_kind = 1 AND owner_id = $id AND root_class = 'tmp';", ("$id", attemptBytes)))!;
            if (OperatingSystem.IsWindows())
            {
                // The real Windows producer creates provenance. Remove only this isolated test fixture's row to
                // exercise missing legacy metadata; Linux below observes the actual producer without such a mutation.
                Assert.Equal(1L, directoryCount());
                Assert.Equal(1, node.Runtime.Store.Write(transaction => transaction.Execute(
                    "DELETE FROM managed_directory WHERE owner_kind = 1 AND owner_id = $id AND root_class = 'tmp';",
                    ("$id", attemptBytes)), CommitDurability.Full));
            }

            Assert.Equal(0L, directoryCount());
            var request = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
            var raw = request.ToByteArray();
            var first = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, raw, request.Meta.CommandId);
            Assert.Equal(RoutedOutcome.Executed, first.Answer!.Outcome);
            var firstBytes = first.Answer.Response!;
            var refusal = FileServicePlanRemovalResponse.Parser.ParseFrom(firstBytes);
            Assert.True(NodeShapes.IsValid(refusal));
            Assert.Equal(ErrorCategory.State, refusal.Error.Category);
            Assert.Equal("file_access_denied", refusal.Error.Code);
            Assert.Equal("file", refusal.Error.Details.State.State);
            Assert.Equal("identity_unavailable", refusal.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, refusal.Error.Effect);
            Assert.Equal(RetryMode.Never, refusal.Error.Retry.Mode);
            Assert.Equal(request.Meta.CorrelationId, refusal.Meta.CorrelationId);
            Assert.Equal(request.Meta.CorrelationId, refusal.Error.CorrelationId);

            node.Runtime.Store.Read(reader =>
            {
                using var sql = reader.CreateCommand("""
                    SELECT d.payload_digest, d.outcome, o.caller
                    FROM command_dedup d JOIN file_removal_command_owner o ON o.command_id = d.command_id
                    WHERE d.command_id = $id;
                    """);
                sql.Parameters.AddWithValue("$id", request.Meta.CommandId.Value.ToByteArray());
                using var row = sql.ExecuteReader();
                Assert.True(row.Read());
                Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(0));
                Assert.Equal(firstBytes.ToByteArray(), (byte[])row.GetValue(1));
                Assert.Equal(caller, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2)));
                Assert.False(row.Read());
                return 0;
            });

            var foreign = caller.Clone();
            foreign.LocalSessionId = CommandIds.New();
            var foreignRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
            var foreignAnswer = await calls.CallAsync(foreign, RoutedMethod.PlanNodeRemoval, foreignRequest.ToByteArray(), foreignRequest.Meta.CommandId);
            Assert.Equal("not_found", FileServicePlanRemovalResponse.Parser.ParseFrom(foreignAnswer.Answer!.Response).Error.Code);
            var unknownRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = CommandIds.New() };
            var unknownAnswer = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, unknownRequest.ToByteArray(), unknownRequest.Meta.CommandId);
            Assert.Equal("not_found", FileServicePlanRemovalResponse.Parser.ParseFrom(unknownAnswer.Answer!.Response).Error.Code);

            Assert.Null((await human.Tasks.PinTaskAsync(new TaskServicePinTaskRequest
            {
                Meta = Tasks.Meta(),
                TaskId = task.TaskId,
                Pinned = true,
            }, cancellationToken: ct)).Error);
            var pinnedRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
            var pinned = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, pinnedRequest.ToByteArray(), pinnedRequest.Meta.CommandId);
            Assert.Equal("in_use", FileServicePlanRemovalResponse.Parser.ParseFrom(pinned.Answer!.Response).Error.Code);
            var replayWhilePinned = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, raw, request.Meta.CommandId);
            Assert.Equal(firstBytes, replayWhilePinned.Answer!.Response);
            var foreignReplay = await calls.CallAsync(foreign, RoutedMethod.PlanNodeRemoval, raw, request.Meta.CommandId);
            Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(foreignReplay.Answer!.Response).Error.Code);
            Assert.Null((await human.Tasks.PinTaskAsync(new TaskServicePinTaskRequest
            {
                Meta = Tasks.Meta(),
                TaskId = task.TaskId,
                Pinned = false,
            }, cancellationToken: ct)).Error);

            Assert.Equal(0, await node.StopAsync());
            await node.StartAsync();
            calls = new RoutedCalls(node);
            var afterRestart = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, raw, request.Meta.CommandId);
            Assert.Equal(firstBytes, afterRestart.Answer!.Response);
            Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
            Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
            Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
                SELECT count(*) FROM file_workspace_audit f JOIN audit_log a ON a.seq = f.audit_seq
                WHERE f.attempt_id = $id AND a.operation = 'cleanup.plan FileService.PlanRemoval'
                  AND a.outcome_summary LIKE '%file_access_denied%';
                """, ("$id", attemptBytes)))! >= 2);
            Assert.Equal(fixtureBody, File.ReadAllText(payload));

            foreach (var db in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
            {
                if (!File.Exists(db)) continue;
                using var stream = new FileStream(db, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var data = new MemoryStream();
                stream.CopyTo(data);
                Assert.False(data.ToArray().AsSpan().IndexOf(Encoding.UTF8.GetBytes(fixtureBody)) >= 0);
            }
        }
    }
}
