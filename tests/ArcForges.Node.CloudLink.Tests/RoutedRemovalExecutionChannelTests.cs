// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real Node, signed WebSocket, SQLite and native files with a mocked Center peer; not real Center acceptance.</summary>
public sealed class RoutedRemovalExecutionChannelTests
{
    [Fact(Timeout = 120_000)]
    public async Task SignedExecutionRefusalPreservesItsCallerAndRawReceiptWithoutMovingFiles()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var connection = await RoutedRemovalPlanFixture.ConnectAsync(center, node);
        var caller = RoutedRemovalPlanFixture.Caller(node, connection, Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "signed-removal-plan-root")).FullName;
        var tree = Directory.CreateDirectory(Path.Combine(root, "tree")).FullName;
        var marker = Path.Combine(tree, "marker");
        var body = "signed-plan-only-private-body"u8.ToArray();
        File.WriteAllBytes(marker, body);

        var request = RoutedRemovalPlanFixture.Request(node, root, "tree", ct);
        var plan = RoutedRemovalPlanFixture.PriorPlan(node, request, requiresApproval: true,
            RoutedRemovalPlanFixture.Item("tree", FileEntryKind.Directory, 0, ownerVerified: false),
            RoutedRemovalPlanFixture.Item("tree/marker", FileEntryKind.File, (ulong)body.Length, ownerVerified: false));
        var planRaw = request.ToByteArray();
        var planReceipt = RoutedRemovalPlanFixture.OriginalBytes(new FileServicePlanRemovalResponse
        {
            Meta = RoutedRemovalPlanFixture.ReplyMeta(request),
            Value = new FileServicePlanRemovalValue { Plan = plan },
        });
        var execute = new FileServiceExecuteRemovalRequest
        {
            Meta = CloudNode.Command(),
            PlanId = plan.PlanId.Clone(),
            PlanDigest = plan.Digest,
            DeleteWithoutQuarantine = true,
        };
        var executionRaw = execute.ToByteArray();
        var executionReceipt = RoutedRemovalPlanFixture.OriginalBytes(new FileServiceExecuteRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = execute.Meta.CorrelationId.Clone() },
            Error = new ArcError
            {
                Category = ErrorCategory.Resource,
                Code = "enforcement_unavailable",
                MessageKey = "error.resource.enforcement_unavailable",
                Effect = EffectCertainty.DidNotHappen,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                CorrelationId = execute.Meta.CorrelationId.Clone(),
                Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "strict_cleanup_guard_unavailable" } },
            },
        });
        var command = execute.Meta.CommandId.Value.ToByteArray();
        var digest = SHA256.HashData(executionRaw);
        // Strict execution refused before custody began, leaving only its exact command receipt and caller record.
        node.Runtime.Store.Write(tx =>
        {
            RoutedRemovalPlanFixture.SeedPlan(tx, request, planRaw, caller, root, plan);
            RoutedRemovalPlanFixture.SeedReceipt(tx, request, planRaw, caller, planReceipt);
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, command, "arcforges.node.v1.FileService/ExecuteRemoval",
                digest, Origin.Remote).Status);
            tx.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($id, $caller);",
                ("$id", command), ("$caller", caller.ToByteArray()));
            CommandDeduplication.Complete(tx, command, executionReceipt);
            return 0;
        }, CommitDurability.Full);

        var planReply = await RoutedRemovalPlanFixture.InvokeAsync(center, connection, request.Meta.CommandId, caller, planRaw, ct);
        Assert.Equal(ByteString.CopyFrom(planReceipt), planReply);
        var first = FileServicePlanRemovalResponse.Parser.ParseFrom(planReply);
        Assert.True(NodeShapes.IsValid(first));
        Assert.Null(first.Error);
        Assert.Equal(2, first.Value.Plan.Items.Count);
        Assert.True(first.Value.Plan.RequiresApproval);
        Assert.True(first.Value.Plan.QuarantineAvailable);

        async Task<ByteString> Execute(CenterCaller source, byte[] payload)
        {
            ct.ThrowIfCancellationRequested();
            var built = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = RoutedMethod.ExecuteNodeRemoval,
                Payload = payload,
                Caller = source,
                CommandId = execute.Meta.CommandId,
                Lifetime = TimeSpan.FromSeconds(30),
            });
            Assert.Equal(execute.Meta.CommandId, built.Header!.CommandId);
            await connection.SendCallAsync(built.Call);
            var frame = await connection.ResultOfAsync(built.Call.CallId);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(built.Call.CallId)),
                "actual signed removal execution refusal");
            var signed = connection.VerifiedResults.Single(x => x.Header.CallId.Equals(built.Call.CallId));
            Assert.Equal(RoutedOutcome.Executed, signed.Header.Outcome);
            return frame.Payload;
        }
        var executionBytes = await Execute(caller, executionRaw);
        Assert.Equal(ByteString.CopyFrom(executionReceipt), executionBytes);
        var response = FileServiceExecuteRemovalResponse.Parser.ParseFrom(executionBytes);
        Assert.NotEqual(executionBytes, response.ToByteString());
        Assert.True(NodeShapes.IsValid(response));
        Assert.Null(response.Value);
        Assert.Equal("enforcement_unavailable", response.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(RetryMode.Never, response.Error.Retry.Mode);
        Assert.Equal(execute.Meta.CorrelationId, response.Meta.CorrelationId);
        Assert.Equal(execute.Meta.CorrelationId, response.Error.CorrelationId);
        var targetId = caller.RelayingNodeId;
        Assert.True(RoutedFileResponseValidation.ExecuteRemoval(new FleetServiceExecuteNodeRemovalResponse
        {
            Value = new FleetServiceExecuteNodeRemovalValue { NodeId = targetId.Clone(), Response = executionBytes },
        }, targetId, execute));
        Assert.Equal(executionBytes, await Execute(caller, executionRaw));
        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        var denied = FileServiceExecuteRemovalResponse.Parser.ParseFrom(await Execute(foreign, executionRaw));
        Assert.Null(denied.Value);
        Assert.Equal(("command_id_reused", EffectCertainty.DidNotHappen), (denied.Error.Code, denied.Error.Effect));

        // Moving the known Meta field changes the signed request bytes without changing the protobuf message.
        using var encoded = new CodedInputStream(executionRaw);
        Assert.Equal(FileServiceExecuteRemovalRequest.MetaFieldNumber, WireFormat.GetTagFieldNumber(encoded.ReadTag()));
        encoded.SkipLastField();
        var metaEnd = checked((int)encoded.Position);
        byte[] reordered = [.. executionRaw[metaEnd..], .. executionRaw[..metaEnd]];
        Assert.NotEqual(executionRaw, reordered);
        Assert.Equal(execute, FileServiceExecuteRemovalRequest.Parser.ParseFrom(reordered));
        var conflict = FileServiceExecuteRemovalResponse.Parser.ParseFrom(await Execute(caller, reordered));
        Assert.Null(conflict.Value);
        Assert.Equal(("command_id_reused", EffectCertainty.DidNotHappen), (conflict.Error.Code, conflict.Error.Effect));
        Assert.Equal(body, File.ReadAllBytes(marker));
        Assert.Equal(new[] { marker }, Directory.GetFileSystemEntries(tree));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT state FROM cleanup_plan;")));
        Assert.Empty(connection.UnverifiedResults);
    }

    [Fact(Timeout = 30_000)]
    public async Task RemovalRelayAssertionSignsTheExactCommandAndRefusesItsAbsence()
    {
        var ct = TestContext.Current.CancellationToken;
        var (link, connection) = await ChannelTests.ConnectedAsync();
        await using (link)
        {
            var raw = "owned-removal-metadata-fixture"u8.ToArray();
            var command = CommandIds.New();
            var target = new Id { Value = ByteString.CopyFrom(link.NodeId) };
            var assertion = await link.Service.SignRelayAssertionAsync(Origin.Human, CommandIds.New(),
                RoutedMethod.ExecuteNodeRemoval, SHA256.HashData(raw), target, command, ct);
            Assert.NotNull(assertion);
            Assert.Equal(command, assertion.CommandId);
            Assert.Equal(RoutedMethod.ExecuteNodeRemoval, assertion.Method);
            Assert.Equal(SHA256.HashData(raw), assertion.RequestSha256.ToByteArray());
            Assert.Equal(1, connection.Received.Count(frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest));
            var input = RelaySignatures.AssertionInput(assertion, link.Center.Endpoint);
            Assert.NotNull(input);
            Assert.True(FakeChannelPeer.Verify(link.NodePublicKey, input, assertion.Signature.ToByteArray()));
            assertion.CommandId = null;
            Assert.Null(RelaySignatures.AssertionInput(assertion, link.Center.Endpoint));
        }
    }
}
