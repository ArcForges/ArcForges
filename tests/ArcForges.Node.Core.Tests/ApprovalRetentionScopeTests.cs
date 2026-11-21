// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed class ApprovalRetentionScopeTests
{
    [Fact(Timeout = 30_000)]
    public async Task LiveSettingsHousekeepingLeavesHistoricalApprovalsIntact()
    {
        const string settingsMethod = "NodeService.UpdateNodeSettings";
        const string historicalMethod = "TaskService.CancelTask";
        var ct = TestContext.Current.CancellationToken;
        var clock = new ApprovalClock();
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "approval-scope", Clock = clock });
        await using var processor = new CommandProcessor(store, EventJournal.Open(store), new StreamHub());
        var human = new ActorRef { Origin = Origin.Human };

        var (currentPending, currentTerminal, historicalPending, historicalTerminal) = await processor.ExecuteAsync(context =>
        {
            var current = Raise(context, human, settingsMethod, PermissionMatrix.NodeSettings);
            var currentDenied = Raise(context, human, settingsMethod, PermissionMatrix.NodeSettings);
            var historical = Raise(context, human, historicalMethod, PermissionMatrix.ProcessTerminate);
            var historicalDenied = Raise(context, human, historicalMethod, PermissionMatrix.ProcessTerminate);
            var endedCurrent = Approvals.Decide(context, currentDenied.Id, false, human, "fixture refusal");
            var endedHistorical = Approvals.Decide(context, historicalDenied.Id, false, human, "retained refusal");
            return (current, endedCurrent, historical, endedHistorical);
        }, CommitDurability.Full).WaitAsync(ct);

        clock.Advance(TimeSpan.FromDays(91));
        Assert.Equal(1, await processor.ExecuteAsync(context => Approvals.Expire(context, settingsMethod),
            CommitDurability.Full).WaitAsync(ct));
        Assert.Equal(ApprovalState.Expired, store.Read(reader => Approvals.Get(reader, currentPending.Id))!.State);
        Assert.Equal(ApprovalState.Pending, store.Read(reader => Approvals.Get(reader, historicalPending.Id))!.State);

        Assert.Equal(2, await processor.ExecuteAsync(context => Approvals.Prune(context.Transaction, settingsMethod),
            CommitDurability.Full).WaitAsync(ct));
        Assert.Null(store.Read(reader => Approvals.Get(reader, currentPending.Id)));
        Assert.Null(store.Read(reader => Approvals.Get(reader, currentTerminal.Id)));

        foreach (var recorded in new[] { historicalPending, historicalTerminal })
        {
            var retained = store.Read(reader => Approvals.Get(reader, recorded.Id));
            Assert.NotNull(retained);
            Assert.Equal(recorded.View, retained.View);
            Assert.Equal(recorded.Request, retained.Request);
            Assert.Equal(recorded.RequestDigest, retained.RequestDigest);
        }
    }

    private static StoredApproval Raise(CommandContext context, ActorRef requester, string method, string permission)
    {
        var meta = InProcessNode.Command();
        var request = method == "NodeService.UpdateNodeSettings"
            ? new NodeServiceUpdateNodeSettingsRequest { Meta = meta, TelemetryOptIn = true }.ToByteArray()
            : new TaskServiceCancelTaskRequest { Meta = meta, TaskId = CommandIds.New() }.ToByteArray();
        var raised = Approvals.Raise(context, new ApprovalCapture
        {
            Operation = method,
            MatrixOperation = permission,
            Summary = "approval retention fixture",
            Risk = RiskClass.Medium,
            Requester = requester,
            CommandId = meta.CommandId.Value.ToByteArray(),
            Request = request,
            RequestDigest = SHA256.HashData(request),
        }, TimeSpan.FromHours(1));
        Assert.True(raised.Created);
        return Assert.IsType<StoredApproval>(raised.Approval);
    }

    private sealed class ApprovalClock : TimeProvider
    {
        private DateTimeOffset _utc = DateTimeOffset.UnixEpoch.AddYears(56);

        public override DateTimeOffset GetUtcNow() => _utc;

        internal void Advance(TimeSpan elapsed) => _utc += elapsed;
    }
}
