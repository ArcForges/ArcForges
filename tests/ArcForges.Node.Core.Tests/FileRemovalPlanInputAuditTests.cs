// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Store;
using Google.Protobuf;
using static ArcForges.Node.Core.Tests.FileRemovalPlanRoutedTests;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Replays historical content-free audit metadata from SQLite. Native input reads, repeated budget charging, partial
/// reads on competing changes, and cancellation during traversal remain exercised at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
/// </summary>
public sealed class FileRemovalPlanInputAuditTests
{
    private static readonly byte[] BodyMarker = "plan-input-owned-fixture-body-4c37"u8.ToArray();

    [Theory(Timeout = 30_000)]
    [InlineData("planned", 67_108_864L)]
    [InlineData("planned", 0L)]
    [InlineData("refused: too_large", 67_108_864L)]
    [InlineData("refused: file_changed", 65_536L)]
    public async Task HistoricalInputObservationReplaysExactlyAndWithoutReadingTheOriginalTree(string outcome, long size)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var request = Request(CommandIds.New());
        var root = Path.Combine(node.Root, "unavailable-audited-workspace");
        var digest = InputDigest(size);
        var audit = size == 0 ? null : new FileAuditMetadata
        {
            Observations =
            {
                new FileAuditObservation
                {
                    Kind = FileAuditKind.InputBytes,
                    SizeBytes = (ulong)size,
                    DigestInputBytes = (ulong)size,
                    Sha256 = ByteString.CopyFrom(digest),
                },
            },
        };
        var historical = outcome switch
        {
            "planned" => Plan(request, node.Runtime.Clock.GetUtcNow(),
                [Item("tree", FileEntryKind.Directory, 0), Item("tree/file.bin", FileEntryKind.File, (ulong)size)], audit),
            "refused: too_large" => Refusal(request, Limit(request, "removal_ownership_input_bytes", "67108864"), audit),
            "refused: file_changed" => Refusal(request, Changed(request), audit),
            _ => throw new InvalidOperationException("Unknown historical outcome fixture."),
        };
        var bytes = WithUnknownField(historical);
        node.Runtime.Store.Write(transaction => Seed(transaction, caller, request, historical, root, bytes), CommitDurability.Full);

        var initial = await RouteAsync(calls, caller, request, ct);
        Assert.Equal(bytes, initial.Response!.ToByteArray());
        var parsed = Parse(initial);
        Assert.True(RoutedFileResponseValidation.RemovalPlanOutcome(parsed, request));
        Assert.Equal(audit, parsed.Audit);

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var replay = await RouteAsync(new RoutedCalls(node), caller, request, ct);
        Assert.Equal(bytes, replay.Response!.ToByteArray());
        Assert.False(Directory.Exists(root));

        node.Runtime.Store.Read(reader =>
        {
            using var query = reader.CreateCommand("""
                SELECT a.outcome_summary, o.kind, o.size_bytes, o.digest_input_bytes, o.item_count, o.sha256
                FROM audit_log a JOIN file_workspace_audit f ON f.audit_seq = a.seq
                LEFT JOIN file_workspace_audit_observation o ON o.audit_seq = f.audit_seq
                WHERE a.operation = 'cleanup.plan FileService.PlanRemoval' AND a.remote_command_id = $id;
                """);
            query.Parameters.AddWithValue("$id", request.Meta.CommandId.Value.ToByteArray());
            using var row = query.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal(outcome, row.GetString(0));
            if (audit is null)
            {
                Assert.True(row.IsDBNull(1));
            }
            else
            {
                Assert.Equal((int)FileAuditKind.InputBytes, row.GetInt32(1));
                Assert.Equal(size, row.GetInt64(2));
                Assert.Equal(size, row.GetInt64(3));
                Assert.True(row.IsDBNull(4));
                Assert.Equal(digest, (byte[])row.GetValue(5));
            }
            Assert.False(row.Read());
            return 0;
        });
        foreach (var path in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(path)) continue;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(BodyMarker));
        }
    }

    private static byte[] InputDigest(long size)
    {
        var block = new byte[65_536];
        BodyMarker.CopyTo(block, 0);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        for (var remaining = size; remaining > 0; remaining -= block.Length)
            hash.AppendData(block.AsSpan(0, (int)Math.Min(remaining, block.Length)));
        return hash.GetHashAndReset();
    }

    private static ArcError Changed(FileServicePlanRemovalRequest request) => new()
    {
        Category = ErrorCategory.Conflict,
        Code = "file_changed",
        MessageKey = "error.conflict.file_changed",
        CorrelationId = request.Meta.CorrelationId.Clone(),
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "planned_tree_changed" } },
    };
}
