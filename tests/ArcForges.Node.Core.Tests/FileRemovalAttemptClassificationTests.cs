// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed class FileRemovalAttemptClassificationTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public Task RetainedAttemptRefusalReplaysOnlyToItsOriginalCaller(bool wasInUse) =>
        LegacyPlannerHistoryFixture.WithStoreAsync((node, files) =>
        {
            var owner = LegacyPlannerHistoryFixture.Owner(node);
            var request = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = CommandIds.New() };
            var error = LegacyPlannerHistoryFixture.Refusal(ErrorCategory.State, wasInUse ? "in_use" : "file_access_denied",
                wasInUse ? "attempt_in_use" : "identity_unavailable", request.Meta.CorrelationId);
            if (wasInUse)
            {
                error.Retry.Mode = RetryMode.AfterTime;
                error.Retry.RetryAt = ProtoTime.ToInstant(node.Clock.GetUtcNow().AddMinutes(1));
            }

            var retained = LegacyPlannerHistoryFixture.RecordRefusal(node.Store, request, owner, error);
            var reply = LegacyPlannerHistoryFixture.Read(node, files, request, owner);
            Assert.Equal(retained, reply.Retained!.Value.ToArray());
            Assert.Equal(error, reply.Error);

            var foreign = owner.Clone();
            foreign.LocalSessionId = CommandIds.New();
            var foreignReply = LegacyPlannerHistoryFixture.Read(node, files, request, foreign);
            Assert.Null(foreignReply.Retained);
            Assert.Equal("command_id_reused", foreignReply.Error!.Code);

            var changed = request.Clone();
            changed.AttemptId = CommandIds.New();
            Assert.Equal("command_id_reused", LegacyPlannerHistoryFixture.Read(node, files, changed, owner).Error!.Code);

            var fresh = request.Clone();
            fresh.Meta = Tasks.Meta();
            var unknown = LegacyPlannerHistoryFixture.Read(node, files, fresh, owner);
            Assert.Null(unknown.Retained);
            Assert.Equal(EffectCertainty.Unknown, unknown.Error!.Effect);
            Assert.Equal("legacy_removal_plan_outcome_unavailable", unknown.Error.Details.State.Reason);
            Assert.Equal(1L, node.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
            Assert.Equal(0L, node.Store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
            Assert.Equal(0L, node.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
            return Task.CompletedTask;
        });
}

internal static class LegacyPlannerHistoryFixture
{
    internal static async Task WithStoreAsync(Func<NodeRuntime, FileServiceHandler, Task> exercise)
    {
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "legacy-planner-fixture" });
        using var log = new NodeLog(Path.Combine(fixture.DataRoot, "logs", "node"), LogLevel.Info, fixture.Clock);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(fixture.ConfigPath, fixture.DataRoot, log), fixture.DataRoot, "offline-fixture", fixture.Clock,
            new RecoveryReport(false, false, null, store.Opening), new CapabilityReport());
        using var files = new FileServiceHandler(runtime);
        await exercise(runtime, files);
    }

    internal static CenterCaller Owner(NodeRuntime node) => new()
    {
        Kind = CenterCallerKind.NodeRelay,
        AccountId = RoutedCalls.Account.Clone(),
        RelayingNodeId = new Id { Value = ByteString.CopyFrom(node.NodeId.Span) },
        LocalOrigin = Origin.Agent,
        LocalSessionId = CommandIds.New(),
    };

    internal static ArcError Refusal(ErrorCategory category, string code, string reason, Id correlation) => new()
    {
        Category = category,
        Code = code,
        MessageKey = $"error.{category.ToString().ToLowerInvariant()}.{code}",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = correlation.Clone(),
        Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = reason } },
    };

    internal static byte[] RecordRefusal(NodeStore store, FileServicePlanRemovalRequest request, CenterCaller owner, ArcError error)
    {
        var id = request.Meta.CommandId.Value.ToByteArray();
        var response = new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Error = error,
        };
        Assert.True(RoutedFileResponseValidation.RemovalPlanOutcome(response, request));
        var bytes = response.ToByteArray();
        store.Write(transaction =>
        {
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id,
                "arcforges.node.v1.FileService/PlanRemoval", SHA256.HashData(request.ToByteArray()), Origin.Remote).Status);
            Assert.Equal(1, transaction.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($id, $caller);",
                ("$id", id), ("$caller", owner.ToByteArray())));
            CommandDeduplication.Complete(transaction, id, bytes);
        }, CommitDurability.Full);
        return bytes;
    }

    internal static FileServiceHandler.RemovalReplay Read(NodeRuntime node, FileServiceHandler files,
        FileServicePlanRemovalRequest request, CenterCaller owner, byte[]? raw = null)
    {
        var route = new RoutedContext(new RoutedCalls.TestLink(), node.Lifecycle, node.Clock.GetUtcNow().AddMinutes(1),
            TimeSpan.FromSeconds(10), node.Clock, node.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
        var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: owner)
        {
            RawRequest = raw ?? request.ToByteArray(),
            RemoteCommandId = request.Meta.CommandId.Clone(),
            Routed = route,
        };
        return files.ReadRoutedRemoval(caller, request, TestContext.Current.CancellationToken);
    }

    internal static Id SeedWorkspace(StoreTransaction transaction, string root)
    {
        var id = CommandIds.New();
        Assert.Equal(1, transaction.Execute("""
            INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
            VALUES ($id, 1, 2, 'recorded workspace', $root, $now, $now, 1);
            """, ("$id", id.Value.ToByteArray()), ("$root", root), ("$now", transaction.NowMicroseconds)));
        return id;
    }
}
