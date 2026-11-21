// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

public sealed class PlanRemovalHostTests
{
    // The native 1,001-entry traversal, response-size refusal and signed Host restart remain executable at
    // eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a (source blob 291ce0b33ea9a906f20aef89ed8555fb45a2c226).
    [Fact(Timeout = 30_000)]
    public async Task AStoredLargePlanAndOversizedRefusalReplayAfterTheStoreReopens()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var history = new LegacyFileHostHistory();
        var workspace = history.Workspace(ct);
        var owner = history.Caller(Origin.Human);
        var marker = Path.Combine(workspace.RootPath, "private.txt");
        var privateBody = "fixture content outside the retained plan"u8.ToArray();
        File.WriteAllBytes(marker, privateBody);

        var planned = Request("short-tree");
        var oversized = Request("tree");
        var root = LegacyFileHostHistory.RootIdentity(workspace.RootPath);
        var receipts = history.Store.Write(tx =>
        {
            // These entries model already committed metadata; the current dispatcher does not inspect their paths.
            var entries = new List<WorkspaceRemovalEntry> { Entry(planned.WorkspacePath.Path, WorkspaceEntryType.Directory, root) };
            for (var index = 0; index < 1_000; index++)
            {
                var name = planned.WorkspacePath.Path + "/" + index.ToString("D4", CultureInfo.InvariantCulture);
                entries.Add(Entry(name, WorkspaceEntryType.File, root));
            }

            var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = owner, RemoteCommandId = planned.Meta.CommandId };
            var snapshot = new WorkspaceRemovalSnapshot(root, entries, TotalBytes: 0);
            var prepared = FileRemovalPlans.PrepareWorkspace(tx, planned.Meta.CommandId.Value.Span, SHA256.HashData(planned.ToByteArray()),
                owner, actor, planned.WorkspacePath, workspace.RootPath, snapshot, tx.NowMicroseconds);
            FileRemovalPlans.RecordWorkspace(tx, prepared);
            var success = new FileServicePlanRemovalResponse
            {
                Meta = Reply(planned),
                Value = new FileServicePlanRemovalValue { Plan = prepared.Plan },
            };
            var recordedRefusal = new FileServicePlanRemovalResponse
            {
                Meta = Reply(oversized),
                Error = new ArcError
                {
                    Category = ErrorCategory.Resource,
                    Code = "too_large",
                    MessageKey = "error.resource.too_large",
                    Effect = EffectCertainty.DidNotHappen,
                    Retry = new RetryAdvice { Mode = RetryMode.Never },
                    CorrelationId = oversized.Meta.CorrelationId,
                    Details = new ErrorDetails
                    {
                        Limit = new LimitFailure
                        {
                            LimitName = "removal_plan_response_bytes",
                            Maximum = new ArcForges.Contracts.Foundation.V1.Decimal { Value = "1040384" },
                        },
                    },
                },
            };
            return (Plan: Retain(tx, planned, owner, success), Refusal: Retain(tx, oversized, owner, recordedRefusal));
        }, CommitDurability.Full);

        var successBytes = await RouteAsync(planned);
        Assert.Equal(receipts.Plan, successBytes);
        var plan = FileServicePlanRemovalResponse.Parser.ParseFrom(successBytes).Value.Plan;
        Assert.Equal(1_001, plan.Items.Count);
        Assert.Equal(planned.WorkspacePath, plan.WorkspacePath);
        Assert.True(plan.RequiresApproval);
        Assert.InRange(successBytes.Length, 1, 1_040_384);
        var refusalBytes = await RouteAsync(oversized);
        Assert.Equal(receipts.Refusal, refusalBytes);
        var refusal = FileServicePlanRemovalResponse.Parser.ParseFrom(refusalBytes);
        Assert.Equal((ErrorCategory.Resource, "too_large", EffectCertainty.DidNotHappen, RetryMode.Never),
            (refusal.Error.Category, refusal.Error.Code, refusal.Error.Effect, refusal.Error.Retry.Mode));
        Assert.Equal("removal_plan_response_bytes", refusal.Error.Details.Limit.LimitName);
        Assert.Equal("1040384", refusal.Error.Details.Limit.Maximum.Value);
        Assert.Null(refusal.Value);

        var changed = oversized.Clone();
        changed.WorkspacePath.Path = "different-tree";
        var conflict = FileServicePlanRemovalResponse.Parser.ParseFrom(await RouteAsync(changed));
        Assert.Equal("command_id_reused", conflict.Error.Code);
        var fresh = Request(oversized.WorkspacePath.Path);
        var unavailable = FileServicePlanRemovalResponse.Parser.ParseFrom(await RouteAsync(fresh));
        Assert.Null(unavailable.Value);
        Assert.Equal(("legacy_removal_plan_outcome_unavailable", EffectCertainty.Unknown, RetryMode.Never),
            (unavailable.Error.Details.State.Reason, unavailable.Error.Effect, unavailable.Error.Retry.Mode));

        await history.ReopenAsync();
        Assert.Equal(receipts.Plan, await RouteAsync(planned));
        Assert.Equal(receipts.Refusal, await RouteAsync(oversized));
        AssertReceipt(history.Store, planned, receipts.Plan);
        AssertReceipt(history.Store, oversized, receipts.Refusal);
        history.Store.Read(reader =>
        {
            Assert.Equal(2L, reader.Scalar("SELECT count(*) FROM command_dedup;"));
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM file_removal_plan;"));
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM cleanup_plan;"));
            Assert.Equal(1_001L, reader.Scalar("SELECT count(*) FROM file_removal_plan_item;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_operation_journal;"));
            return 0;
        });
        Assert.Equal(privateBody, File.ReadAllBytes(marker));
        Assert.False(Directory.Exists(Path.Combine(workspace.RootPath, planned.WorkspacePath.Path)));
        Assert.False(Directory.Exists(Path.Combine(workspace.RootPath, oversized.WorkspacePath.Path)));

        FileServicePlanRemovalRequest Request(string path) => new()
        {
            Meta = LegacyFileHostHistory.Command(),
            WorkspacePath = LegacyFileHostHistory.FilePath(workspace, path),
        };

        async Task<byte[]> RouteAsync(FileServicePlanRemovalRequest request)
        {
            var answer = await history.RouteAsync(RoutedMethod.PlanNodeRemoval, owner, request, request.Meta.CommandId, ct);
            Assert.NotNull(answer);
            Assert.Equal(RoutedOutcome.Executed, answer.Outcome);
            Assert.NotNull(answer.Response);
            return answer.Response.ToByteArray();
        }
    }

    private static WorkspaceRemovalEntry Entry(string path, WorkspaceEntryType type, RegisteredWorkspaces.RootIdentity root)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(path));
        return new WorkspaceRemovalEntry(path, type, Size: 0, root, default, Mode: 0, Links: 1, digest, digest);
    }

    private static ResponseMeta Reply(FileServicePlanRemovalRequest request) => new() { CorrelationId = request.Meta.CorrelationId };

    private static byte[] Retain(StoreTransaction transaction, FileServicePlanRemovalRequest request, CenterCaller owner, FileServicePlanRemovalResponse response)
    {
        Assert.True(RoutedFileResponseValidation.RemovalPlanOutcome(response, request));
        var id = request.Meta.CommandId.Value.ToByteArray();
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id, "arcforges.node.v1.FileService/PlanRemoval",
            SHA256.HashData(request.ToByteArray()), Origin.Remote).Status);
        transaction.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($id, $caller);",
            ("$id", id), ("$caller", owner.ToByteArray()));
        var bytes = response.ToByteArray();
        CommandDeduplication.Complete(transaction, id, bytes);
        return bytes;
    }

    private static void AssertReceipt(NodeStore store, FileServicePlanRemovalRequest request, byte[] expected)
    {
        store.Read(reader =>
        {
            var id = ("$id", request.Meta.CommandId.Value.ToByteArray());
            Assert.Equal(SHA256.HashData(request.ToByteArray()), (byte[]?)reader.Scalar("SELECT payload_digest FROM command_dedup WHERE command_id = $id;", id));
            Assert.Equal(expected, (byte[]?)reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", id));
            return 0;
        });
    }
}
