// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Store;
using Google.Protobuf;
using RelayShapes = ArcForges.Contracts.Relay.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// Results and refusals (AF-CTR-05 CTR5-NODE-06/07; relay.proto rule routedRefusal; Plan PN-6) and the retention of
/// <c>routed_call_log</c> (node-store.md section 2a): REAL signing with a file-backed node key, REAL node store.
/// </summary>
public sealed class RoutedResultTests
{
    private static readonly TimeProvider Clock = TimeProvider.System;

    [Fact]
    public void TheResultIsSignedWithTheNodeKeyAndVerifiesAgainstTheRegisteredKey()
    {
        // N1-14 (Linux file key; the Windows CNG key signs through the same INodeKey seam, exercised only by the OS secret-store tier).
        var root = Directory.CreateTempSubdirectory("arcforges-result-").FullName;
        try
        {
            var keys = NodeKeyStores.ForTestDataRoot(root);
            var node = RandomNumberGenerator.GetBytes(16);
            using var key = keys.Create(node, "https://center.example.test", Clock);
            var call = CallHeader();
            var signer = new ResultSigner(key, node, Clock);
            var response = new ArcForges.Contracts.Node.V1.TaskServiceGetTaskResponse { Meta = new ResponseMeta() }.ToByteString();
            var executed = signer.Executed(call, response);
            Assert.True(RelayShapes.IsValid(executed));
            var input = RelaySignatures.ResultInput(executed.Header.Header.Span);
            Assert.True(FakeChannelPeer.Verify(key.PublicKey, input, executed.Header.Signature.ToByteArray()));
            Assert.True(RelaySignatures.Verify(key.PublicKey, input, executed.Header.Signature.Span));
            Assert.True(CloudIdentity.IsLowS(executed.Header.Signature.Span));
            Assert.False(executed.Header.HasKid);
            var header = ArcForges.Contracts.Relay.V1.ResultHeader.Parser.ParseFrom(executed.Header.Header);
            Assert.Equal(SHA256.HashData(response.Span), header.ResponseSha256.ToByteArray());
            Assert.Equal((uint)response.Length, header.ResponseSize);
            Assert.Equal(call.RequestSha256, header.RequestSha256);
            Assert.Equal(call.CommandId, header.CommandId);

            // A signature over the bare header, or under the call's domain string, is not this signature.
            Assert.False(RelaySignatures.Verify(key.PublicKey, executed.Header.Header.Span, executed.Header.Signature.Span));
            Assert.False(RelaySignatures.Verify(key.PublicKey, RelaySignatures.CallInput(executed.Header.Header.Span), executed.Header.Signature.Span));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ARefusalCarriesClosedFieldsOnly()
    {
        // routedRefusal: no free text; a reason or state outside the identifier pattern, a resource, a message key that is not the code's
        // and other details are refused before signing, and the node's builders never produce one.
        var correlation = CommandIds.New();
        var policy = RoutedRefusals.Policy("task.submit", RoutedRefusals.DispatchUnavailable, correlation);
        Assert.True(RoutedRefusals.Closed(policy));
        Assert.Equal("error.authorization.permission_denied", policy.MessageKey);
        Assert.Throws<InvalidOperationException>(() => RoutedRefusals.Policy("task.submit", "/home/u/.ssh/id_ed25519: permission denied", correlation));
        Assert.Throws<InvalidOperationException>(() => RoutedRefusals.Policy("task submit", "denied", correlation));
        Assert.False(RoutedRefusals.Closed(Change(policy, error => error.MessageKey = "error.authorization.something_else")));
        Assert.False(RoutedRefusals.Closed(Change(policy, error => error.Details.Limit = new LimitFailure { LimitName = "x" })));
        Assert.False(RoutedRefusals.Closed(Change(policy, error => error.Details.State.Resource = new AggregateRef { Kind = "task", Id = correlation })));
        Assert.False(RoutedRefusals.Closed(Change(policy, error => error.Code = "Permission denied")));
        Assert.False(RoutedRefusals.Closed(Change(policy, error => error.Retry.ReconciliationOperation = "arcforges.node.v1.TaskService/GetTask")));
        foreach (var step in CallVerifier.Steps)
        {
            var refusal = RoutedRefusals.Verification(new CallRefusal(step, step == "expired" ? RoutedRefusals.Expired : RoutedRefusals.SignatureInvalid, correlation), correlation);
            Assert.True(RoutedRefusals.Closed(refusal), step);
        }

        // The signed result header of every refusal passes the contract's own validator.
        var root = Directory.CreateTempSubdirectory("arcforges-refusal-").FullName;
        try
        {
            using var key = NodeKeyStores.ForTestDataRoot(root).Create(RandomNumberGenerator.GetBytes(16), "https://center.example.test", Clock);
            var signer = new ResultSigner(key, RandomNumberGenerator.GetBytes(16), Clock);
            var verification = signer.RefusedVerification(new CallRefusal("signature", RoutedRefusals.SignatureInvalid, CommandIds.New()));
            Assert.True(RelayShapes.IsValid(verification));
            var refused = signer.Refused(CallHeader(), RoutedOutcome.RefusedByPolicy, policy);
            Assert.True(RelayShapes.IsValid(refused));
            var withText = Change(policy, error => error.Details.State.Reason = "C:\\Users\\someone\\build");
            Assert.Throws<InvalidOperationException>(() => signer.Refused(CallHeader(), RoutedOutcome.RefusedByPolicy, withText));
            Assert.Throws<InvalidOperationException>(() => signer.RefusedVerification(new CallRefusal("signature", RoutedRefusals.SignatureInvalid, null)));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// AF-CTR-05 N2b decisions Q11 (relay.proto routedRefusal): <c>AUTHORIZATION/approval_required</c> alone carries a resource, exactly
    /// <c>{kind "approval", id}</c>, and the RECONCILE advice through <c>ApprovalService/GetApproval</c>; its signed result passes the contract.
    /// </summary>
    [Fact]
    public void OnlyAnApprovalRequiredRefusalCarriesItsApprovalAndItsReconciliation()
    {
        var correlation = CommandIds.New();
        var approval = RoutedRefusals.ApprovalRequired("task.cancel_others", CommandIds.New(), correlation);
        Assert.True(RoutedRefusals.Closed(approval));
        Assert.Equal((RetryMode.Reconcile, RoutedRefusals.ApprovalReconciliation, "approval"),
            (approval.Retry.Mode, approval.Retry.ReconciliationOperation, approval.Details.State.Resource.Kind));
        Assert.False(RoutedRefusals.Closed(Change(approval, error => error.Details.State.Resource.Kind = "task")));
        Assert.False(RoutedRefusals.Closed(Change(approval, error => error.Details.State.Resource.Id = null)));
        Assert.False(RoutedRefusals.Closed(Change(approval, error => error.Retry.ReconciliationOperation = "arcforges.node.v1.TaskService/GetTask")));
        Assert.False(RoutedRefusals.Closed(Change(approval, error => error.Retry.Mode = RetryMode.Never)));
        Assert.False(RoutedRefusals.Closed(Change(approval, error => error.Retry.ClearReconciliationOperation())));
        Assert.False(RoutedRefusals.Closed(Change(approval, error => error.Details.State.Resource = null)));

        // Another code never carries either.
        var policy = RoutedRefusals.Policy("task.submit", "denied", correlation);
        Assert.False(RoutedRefusals.Closed(Change(policy, error => error.Details.State.Resource = new AggregateRef { Kind = "approval", Id = correlation })));
        Assert.False(RoutedRefusals.Closed(Change(policy, error =>
        {
            error.Retry.Mode = RetryMode.Reconcile;
            error.Retry.ReconciliationOperation = RoutedRefusals.ApprovalReconciliation;
        })));
        Assert.True(RoutedRefusals.Closed(RoutedRefusals.Authorization("command_pattern_denied", "task.submit", "agents.allowed_command_patterns", correlation)));
        Assert.Equal("task.cancel_others", RoutedRefusals.Operation(RoutedMethod.CancelNodeTask));

        var root = Directory.CreateTempSubdirectory("arcforges-refusal-").FullName;
        try
        {
            using var key = NodeKeyStores.ForTestDataRoot(root).Create(RandomNumberGenerator.GetBytes(16), "https://center.example.test", Clock);
            var signer = new ResultSigner(key, RandomNumberGenerator.GetBytes(16), Clock);
            Assert.True(RelayShapes.IsValid(signer.Refused(CallHeader(), RoutedOutcome.RefusedByPolicy, approval)));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task TheRoutedCallLogKeepsReadsSevenDaysAndAtMostTenThousandRefusals()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-routedlog-").FullName;
        try
        {
            var clock = new ManualClock();
            using (var store = NodeStore.Open(new NodeStoreOptions { DataRoot = root, BootIdentity = "boot-1", Clock = clock }))
            {
                var log = new RoutedCallLog(new DirectRoutedCallStore(store), clock);
                var read = await log.RecordVerifiedAsync(Row(2));
                await log.CompleteAsync(read!.Value, RoutedCallDecision.Executed, null, responseSha256: new byte[32], responseSize: 10);
                var submit = await log.RecordVerifiedAsync(Row(1));
                await log.CompleteAsync(submit!.Value, RoutedCallDecision.RefusedByPolicy, "AUTHORIZATION/permission_denied");
                store.Write(transaction =>
                {
                    for (var index = 0; index < RoutedCallLog.RefusalsKept + 5; index++)
                    {
                        transaction.Execute("INSERT INTO routed_call_log (received_at, frame_sha256, decision, refusal_step, refusal_code) VALUES ($at, $frame, 3, 'signature', 'AUTHENTICATION/signature_invalid');",
                            ("$at", StoreTime.NowMicroseconds(clock)), ("$frame", new byte[32]));
                    }
                });

                clock.Advance(TimeSpan.FromDays(8));
                var removed = store.Write(RoutedCallLog.Prune);
                Assert.Equal(6, removed);
                Assert.Equal((long)RoutedCallLog.RefusalsKept, store.Read(reader => reader.Scalar("SELECT count(*) FROM routed_call_log WHERE decision = 3;")));
                Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM routed_call_log WHERE decision = 2;")));

                clock.Advance(TimeSpan.FromDays(366));
                store.Write(RoutedCallLog.Prune);
                Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM routed_call_log;")));
            }
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    private static VerifiedCallRow Row(int method) => new()
    {
        FrameSha256 = RandomNumberGenerator.GetBytes(32),
        CallId = RandomNumberGenerator.GetBytes(16),
        Kid = "cmd-test-0001",
        Method = method,
        Caller = [0x08, 0x01],
        CommandId = method is 1 or 6 ? RandomNumberGenerator.GetBytes(16) : null,
        RequestSha256 = RandomNumberGenerator.GetBytes(32),
        RequestSize = 10,
    };

    private static CallHeader CallHeader() => new()
    {
        CallId = CommandIds.New(),
        CommandId = CommandIds.New(),
        Method = RoutedMethod.SubmitNodeTask,
        RequestSha256 = ByteString.CopyFrom(new byte[32]),
    };

    private static ArcError Change(ArcError error, Action<ArcError> change)
    {
        var copy = error.Clone();
        change(copy);
        return copy;
    }
}
