// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Proto;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// AF-CTR-05 N2-11/12. The original Linux PTY and Windows Desktop-kind execution evidence
/// remains at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a. Legacy diagnostics now reconcile and display
/// their stored owner and diagnostic marker without producing new Tasks.
/// </summary>
public sealed class LocalDiagnosticTests
{
    [Theory]
    [InlineData(ClientKind.Cli)]
    [InlineData(ClientKind.Desktop)]
    public async Task HumanClientsReconcileRetainedLocalDiagnosticsButCannotSubmitFreshTasks(ClientKind kind)
    {
        var ct = TestContext.Current.CancellationToken;
        var root = Directory.CreateTempSubdirectory("af-local-diagnostic-");
        try
        {
            using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = root.FullName, BootIdentity = "diagnostic-fixture" });
            using var log = new NodeLog(Path.Combine(root.FullName, "logs", "node"), LogLevel.Info);
            var journal = EventJournal.Open(store);
            var hub = new StreamHub();
            await using var processor = new CommandProcessor(store, journal, hub);
            using var runtime = new NodeRuntime(store, journal, hub, processor, log,
                new NodeSettingsManager(Path.Combine(root.FullName, "node.json"), root.FullName, log),
                root.FullName, "offline-diagnostic-fixture", TimeProvider.System,
                new RecoveryReport(false, false, null, store.Opening), new CapabilityReport());
            var tasks = new TaskServiceHandler(runtime, new ClientSessions());
            var human = new Caller(Origin.Human, kind, null);
            var script = new Caller(Origin.Script, ClientKind.Cli, null);
            var previous = new TaskServiceSubmitTaskRequest
            {
                Meta = Meta(),
                Spec = new TaskSpec
                {
                    Kind = TaskKind.Command,
                    Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "fixture-never-starts" } } },
                    WorkingDirectory = root.FullName,
                    Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
                },
            };
            var receipt = store.Write(transaction => SeedDiagnostic(transaction, previous, human.Actor), CommitDurability.Full);

            Assert.Null(runtime.Execution);
            var fresh = previous.Clone();
            fresh.Meta = Meta();
            var scriptError = (await tasks.SubmitTask(script, fresh, ct)).Error;
            Assert.Equal((ErrorCategory.Authorization, "permission_denied", "local_submission_human_only",
                    EffectCertainty.DidNotHappen, RetryMode.Never),
                (scriptError.Category, scriptError.Code, scriptError.Details.State.Reason, scriptError.Effect, scriptError.Retry.Mode));
            var humanError = (await tasks.SubmitTask(human, fresh, ct)).Error;
            Assert.Equal((ErrorCategory.Execution, "operation_failed", "legacy_task_outcome_unavailable", EffectCertainty.Unknown, RetryMode.Never),
                (humanError.Category, humanError.Code, humanError.Details.State.Reason, humanError.Effect, humanError.Retry.Mode));

            Assert.Equal(receipt, await tasks.SubmitTask(human, previous, ct));
            var history = await tasks.ListTasks(human, new TaskServiceListTasksRequest { Meta = Meta() }, ct);
            Assert.Null(history.Error);
            var task = Assert.Single(history.Value.Tasks);
            Assert.Equal(receipt.Value.TaskId, task.TaskId);
            Assert.Equal((TaskState.Succeeded, human.Actor, true), (task.State, task.Owner, task.LocalDiagnostic));
            Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
            Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    private static TaskServiceSubmitTaskResponse SeedDiagnostic(StoreTransaction transaction, TaskServiceSubmitTaskRequest request, ActorRef owner)
    {
        var taskId = StoreIds.NewUuid7(transaction.Clock);
        var spec = request.Spec.ToByteArray();
        transaction.Execute(
            """
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                              pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                              command_digest, created_at, queued_at, started_at, finished_at, rev, local_diagnostic)
            VALUES ($id, $state, 1, 'retained diagnostic fixture', 'retained diagnostic fixture', $spec, $digest, $owner, $origin,
                    'default', 3, 3, 4, 1, 'retained-diagnostic-fixture', $digest, $now, $now, $now, $now, 1, 1);
            """,
            ("$id", taskId), ("$state", (int)TaskState.Succeeded), ("$spec", spec), ("$digest", SHA256.HashData(spec)),
            ("$owner", owner.ToByteArray()), ("$origin", (int)owner.Origin), ("$now", transaction.NowMicroseconds));
        var receipt = new TaskServiceSubmitTaskResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new TaskServiceSubmitTaskValue
            {
                TaskId = new Id { Value = ByteString.CopyFrom(taskId) },
                State = TaskState.Queued,
                Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened },
            },
        };
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, request.Meta.CommandId.Value.Span,
            "arcforges.node.v1.TaskService/SubmitTask", PayloadDigest.Compute(request), owner.Origin).Status);
        CommandDeduplication.Complete(transaction, request.Meta.CommandId.Value.Span, receipt.ToByteArray());
        return receipt;
    }

    private static RequestMeta Meta() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
}
