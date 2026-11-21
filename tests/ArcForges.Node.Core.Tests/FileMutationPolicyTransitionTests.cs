// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Current policy gates metadata reads. Exact retained mutation receipts remain bound to their original caller.</summary>
public sealed class FileMutationPolicyTransitionTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(Origin.Remote, false)]
    [InlineData(Origin.Script, true)]
    public async Task PolicyNarrowingGatesStatusAndKeepsTheExactHistoricalRefusal(Origin origin, bool approvalUnavailable)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = origin == Origin.Remote ? RoutedCalls.Session() : calls.Relay(origin);
        var fixture = new RetainedFileMutationFixture(node, actor, expectedAbsent: !approvalUnavailable, ct);
        fixture.Prepare();
        var status = new FileServiceGetFileOperationRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            OperationCommandId = new Id { Value = ByteString.CopyFrom(fixture.Intent.CommandId) },
        };

        async Task<RoutedAnswer?> ReadStatus(CenterCaller caller) => (await calls.CallAsync(caller, RoutedMethod.GetNodeFileOperation,
            status.ToByteArray(), cancellationToken: ct)).Answer;

        var initial = await ReadStatus(actor);
        Assert.Equal(RoutedOutcome.Executed, initial!.Outcome);
        var prepared = FileServiceGetFileOperationResponse.Parser.ParseFrom(initial.Response);
        Assert.Equal(FileOperationState.Prepared, prepared.Value.Operation.State);
        Assert.True(prepared.Value.Operation.Held);
        Assert.Equal(SHA256.HashData(fixture.Raw), prepared.Value.Operation.RequestSha256.ToByteArray());

        var effectiveOrigin = CenterRouting.CellsOrigin(actor, node.Runtime.NodeId.Span);
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            Assert.Null((await Sched.ChangePolicyAsync(human, policy =>
            {
                policy.Permissions.Add(new PermissionOverride
                {
                    Operation = PermissionMatrix.FileRead,
                    Origin = effectiveOrigin,
                    Decision = PermissionDecision.Deny,
                });
                policy.Permissions.Add(new PermissionOverride
                {
                    Operation = PermissionMatrix.FileWrite,
                    Origin = effectiveOrigin,
                    Decision = PermissionDecision.Deny,
                });
            })).Error);

            var denied = await ReadStatus(actor);
            Assert.Equal(RoutedOutcome.RefusedByPolicy, denied!.Outcome);
            Assert.Equal("permission_denied", denied.Error!.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, denied.Error.Effect);
            Assert.Null(denied.Response);
            Assert.Null(await fixture.InvokeAsync(calls, actor, ct));
            Assert.Equal(prepared.Value.Operation, fixture.ReadJournal());
            fixture.AssertNoEffect();

            // The fixture supplies an original, settled pre-effect refusal through the real SQLite journal.
            // The running service only reconciles its bytes.
            var original = node.Runtime.Store.Write(transaction => FileMutationJournal.CompleteKnownAuthorityRefusal(transaction,
                fixture.Intent.Kind, fixture.Intent.CommandId, actor, fixture.Raw, approvalUnavailable), CommitDurability.Full);
            var saved = FileServiceWriteFileResponse.Parser.ParseFrom(original);
            Assert.Equal(approvalUnavailable ? ErrorCategory.Resource : ErrorCategory.Authorization, saved.Error.Category);
            Assert.Equal(approvalUnavailable ? "enforcement_unavailable" : "permission_denied", saved.Error.Code);
            Assert.Equal(approvalUnavailable ? "file_approval_unavailable" : PermissionMatrix.FileWrite, saved.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, saved.Error.Effect);
            Assert.Equal(original, await fixture.InvokeAsync(calls, actor, ct));

            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Clear())).Error);
            Assert.Equal(original, await fixture.InvokeAsync(calls, actor, ct));
            var complete = await ReadStatus(actor);
            Assert.Equal(RoutedOutcome.Executed, complete!.Outcome);
            var completed = FileServiceGetFileOperationResponse.Parser.ParseFrom(complete.Response).Value.Operation;
            Assert.Equal(FileOperationState.Completed, completed.State);
            Assert.False(completed.Held);
            Assert.Equal(saved.Error, completed.Error);

            var foreign = origin == Origin.Remote ? calls.Relay(Origin.Script) : actor.Clone();
            if (origin != Origin.Remote)
                foreign.LocalSessionId = CommandIds.New();
            var deniedReplay = FileServiceWriteFileResponse.Parser.ParseFrom(await fixture.InvokeAsync(calls, foreign, ct));
            Assert.Equal("command_id_reused", deniedReplay.Error.Code);
            var deniedRead = await ReadStatus(foreign);
            Assert.Equal(RoutedOutcome.Executed, deniedRead!.Outcome);
            Assert.Equal("not_found", FileServiceGetFileOperationResponse.Parser.ParseFrom(deniedRead.Response).Error.Code);

            Assert.Equal(0, await node.StopAsync());
            await node.StartAsync();
            Assert.Equal(original, await fixture.InvokeAsync(new RoutedCalls(node), actor, ct));
            Assert.Equal(completed, fixture.ReadJournal());
        }

        fixture.AssertNoEffect();
    }
}
