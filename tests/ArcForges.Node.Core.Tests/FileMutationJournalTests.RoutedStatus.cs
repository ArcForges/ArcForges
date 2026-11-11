// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

public sealed partial class FileMutationJournalTests
{
    [Fact(Timeout = 120_000)]
    public async Task RoutedStatusBindsOriginalCallerAndExactRawDigestAcrossRestart()
    {
        using var fixture = new Fixture();
        await using var node = await InProcessNode.Create().StartAsync();
        var token = TestContext.Current.CancellationToken;
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(fixture.Workspace, "status-test", cancellationToken: token);
        var marker = Encoding.UTF8.GetBytes("routed-status-no-content-bd6117");
        var (baseIntent, raw) = fixture.WriteIntent(registered.Id, marker);
        var caller = RoutedCalls.Session();
        var intent = baseIntent with { Caller = caller };
        Assert.Equal(FileJournalPreparation.Prepared, node.Runtime.Store.Write(
            transaction => FileMutationJournal.Prepare(transaction, intent, raw), CommitDurability.Full));
        var calls = new RoutedCalls(node);
        var request = new FileServiceGetFileOperationRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            OperationCommandId = new Id { Value = ByteString.CopyFrom(intent.CommandId) },
        };

        async Task<FileServiceGetFileOperationResponse> Get(CenterCaller actor, FileServiceGetFileOperationRequest message)
        {
            var result = await calls.CallAsync(actor, RoutedMethod.GetNodeFileOperation, message.ToByteArray());
            Assert.Equal(RoutedOutcome.Executed, result.Answer!.Outcome);
            var response = FileServiceGetFileOperationResponse.Parser.ParseFrom(result.Answer.Response);
            Assert.True(NodeShapes.IsValid(response));
            return response;
        }

        var prepared = await Get(caller, request);
        Assert.Equal(request.Meta.CorrelationId, prepared.Meta.CorrelationId);
        Assert.Equal(FileOperationState.Prepared, prepared.Value.Operation.State);
        Assert.Equal(SHA256.HashData(raw), prepared.Value.Operation.RequestSha256.ToByteArray());
        Assert.Equal("target.txt", prepared.Value.Operation.WorkspacePath.Path);
        Assert.Equal(registered.Id, prepared.Value.Operation.WorkspacePath.WorkspaceId.Value.ToByteArray());
        Assert.Null(prepared.Value.Operation.Error);
        Assert.True(prepared.Value.Operation.Held);
        Assert.Null(prepared.Audit);

        var otherAccountSession = caller.Clone();
        otherAccountSession.UserId = CommandIds.New();
        otherAccountSession.SessionId = CommandIds.New();
        Assert.Equal(FileOperationState.Prepared, (await Get(otherAccountSession, request)).Value.Operation.State);

        var foreign = calls.Relay(Origin.Human);
        var denied = await Get(foreign, request);
        Assert.Equal("not_found", denied.Error.Code);
        Assert.Equal(request.Meta.CorrelationId, denied.Error.CorrelationId);
        Assert.Null(denied.Value);
        var unknown = request.Clone();
        unknown.OperationCommandId = CommandIds.New();
        Assert.Equal("not_found", (await Get(caller, unknown)).Error.Code);
        var receiptOnlyId = CommandIds.New();
        var receiptDigest = SHA256.HashData("receipt-without-file-journal"u8);
        node.Runtime.Store.Write(transaction => CommandDeduplication.Begin(transaction, receiptOnlyId.Value.Span,
            "arcforges.node.v1.FileService/WriteFile", receiptDigest, Origin.Remote), CommitDurability.Full);
        var receiptOnly = request.Clone();
        receiptOnly.OperationCommandId = receiptOnlyId;
        Assert.Equal("not_found", (await Get(caller, receiptOnly)).Error.Code);
        var malformed = request.Clone();
        malformed.OperationCommandId = new Id();
        var invalid = await Get(caller, malformed);
        Assert.Equal("invalid_argument", invalid.Error.Code);
        Assert.Equal(request.Meta.CorrelationId, invalid.Error.CorrelationId);

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        var recovered = await Get(caller, request);
        var operation = recovered.Value.Operation;
        Assert.Equal(FileOperationState.Unknown, operation.State);
        Assert.True(operation.Held);
        Assert.False(operation.Acknowledged);
        Assert.Equal("file_outcome_unknown", operation.Error.Details.State.Reason);
        Assert.Equal(intent.CorrelationId, operation.Error.CorrelationId.Value.ToByteArray());
        Assert.Equal(SHA256.HashData(raw), operation.RequestSha256.ToByteArray());
        Assert.Equal("original test bytes", File.ReadAllText(fixture.Target));
        Directory.Move(fixture.Workspace, fixture.Workspace + "-moved");
        Assert.Equal(FileOperationState.Unknown, (await Get(caller, request)).Value.Operation.State);
        // Synthetic local HUMAN uses the real local peer/Hello and acknowledgment endpoint.
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            var acknowledged = await human.Files.AcknowledgeFileOperationAsync(new FileServiceAcknowledgeFileOperationRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                OperationCommandId = request.OperationCommandId.Clone(),
                OperationDigest = ByteString.CopyFrom(SHA256.HashData(raw)),
            }, cancellationToken: token);
            Assert.Null(acknowledged.Error);
        }
        new RegisteredWorkspaces(node.Runtime.Store).UnregisterFromVerifiedHuman(registered.Id, token);
        var afterUnregister = await Get(caller, request);
        Assert.Equal(FileOperationState.Unknown, afterUnregister.Value.Operation.State);
        Assert.True(afterUnregister.Value.Operation.Acknowledged);
        Assert.False(afterUnregister.Value.Operation.Held);
        Assert.Equal(SHA256.HashData(raw), afterUnregister.Value.Operation.RequestSha256.ToByteArray());
        AssertNoContent(node.Runtime.Store.DatabasePath, marker);
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a JOIN audit_log l ON l.seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = 'target.txt'
              AND l.operation = 'file.read FileService.GetFileOperation' AND l.decision = 1;
            """, ("$workspace", registered.Id)))! >= 2);
    }

    [Fact(Timeout = 120_000)]
    public async Task RoutedStatusRejectsAnotherRelaySessionWithoutDisclosingTarget()
    {
        using var fixture = new Fixture();
        await using var node = await InProcessNode.Create().StartAsync();
        var token = TestContext.Current.CancellationToken;
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(fixture.Workspace, "relay-status", cancellationToken: token);
        var (baseIntent, raw) = fixture.WriteIntent(registered.Id, Encoding.UTF8.GetBytes("relay-status-test"));
        var calls = new RoutedCalls(node);
        var original = calls.Relay(Origin.Agent);
        Assert.Equal(PermissionDecision.Deny, PermissionMatrix.DecideRouted(PermissionMatrix.FileWrite, Origin.Agent, []).Decision);
        var intent = baseIntent with { Caller = original };
        Assert.Equal(FileJournalPreparation.Prepared, node.Runtime.Store.Write(
            transaction => FileMutationJournal.Prepare(transaction, intent, raw), CommitDurability.Full));
        var request = new FileServiceGetFileOperationRequest
        {
            OperationCommandId = new Id { Value = ByteString.CopyFrom(intent.CommandId) },
        };
        var same = await calls.CallAsync(original, RoutedMethod.GetNodeFileOperation, request.ToByteArray());
        var shown = FileServiceGetFileOperationResponse.Parser.ParseFrom(same.Answer!.Response);
        Assert.Equal(FileOperationState.Prepared, shown.Value.Operation.State);
        Assert.Equal(calls.LastCallId, shown.Meta.CorrelationId);

        var other = original.Clone();
        other.LocalSessionId = CommandIds.New();
        var foreign = await calls.CallAsync(other, RoutedMethod.GetNodeFileOperation, request.ToByteArray());
        var denied = FileServiceGetFileOperationResponse.Parser.ParseFrom(foreign.Answer!.Response);
        Assert.Equal("not_found", denied.Error.Code);
        Assert.Null(denied.Value);
        Assert.True(NodeShapes.IsValid(denied));
        Assert.Equal(calls.LastCallId, denied.Meta.CorrelationId);
        Assert.Equal(denied.Meta.CorrelationId, denied.Error.CorrelationId);

        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.FileRead,
            Origin = Origin.Agent,
            Decision = PermissionDecision.Deny,
        }))).Error);
        var policyDenied = await calls.CallAsync(original, RoutedMethod.GetNodeFileOperation, request.ToByteArray());
        Assert.Equal(RoutedOutcome.RefusedByPolicy, policyDenied.Answer!.Outcome);
        Assert.Equal("permission_denied", policyDenied.Answer.Error!.Code);
    }
}
