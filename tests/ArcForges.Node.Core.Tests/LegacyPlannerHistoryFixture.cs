// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Exercises retained legacy FILE records through a temporary SQLite store.</summary>
internal static class LegacyPlannerHistoryFixture
{
    private const string Method = "arcforges.node.v1.FileService/PlanRemoval";

    internal static async Task WithStoreAsync(Func<NodeStore, Task> exercise)
    {
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "legacy-planner-fixture" });
        await exercise(store);
    }

    internal static CenterCaller Owner(NodeStore store) => new()
    {
        Kind = CenterCallerKind.NodeRelay,
        AccountId = CommandIds.New(),
        RelayingNodeId = new Id { Value = ByteString.CopyFrom(store.Metadata.NodeId.Span) },
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
        var bytes = response.ToByteArray();
        store.Write(transaction =>
        {
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id, Method,
                SHA256.HashData(request.ToByteArray()), Origin.Remote).Status);
            Assert.Equal(1, transaction.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($id, $caller);",
                ("$id", id), ("$caller", owner.ToByteArray())));
            CommandDeduplication.Complete(transaction, id, bytes);
        }, CommitDurability.Full);
        return bytes;
    }

    internal static DedupDecision ReadRetained(NodeStore store, Id commandId, byte[] raw) =>
        Assert.IsType<DedupDecision>(store.Read(reader => CommandDeduplication.ReadRetained(
            reader, commandId.Value.ToByteArray(), Method, SHA256.HashData(raw), reader.NowMicroseconds)));

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
