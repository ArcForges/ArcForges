// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Store;
using Microsoft.Data.Sqlite;
using static ArcForges.ClosedLoop.Tests.CloudLinkCenterControlTests;

namespace ArcForges.ClosedLoop.Tests;

[Trait("loop", "cloud")]
public sealed class CloudLinkCenterControlDeviceTests
{
    [Fact(Timeout = 150_000, DisableParallelization = true)]
    public async Task InstalledDeviceCodeApprovalUsesThePublishedTransientFingerprint()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        var (origin, coordination) = RequireNativeFixture();
        await using var fixture = TestNode.Create();
        ConfigureNativeFixture(fixture, origin);
        var process = await fixture.StartNodeAsync();
        await using var local = OpenChannel(fixture);
        var node = new NodeService.NodeServiceClient(local.CallInvoker);
        var control = new CenterControlService.CenterControlServiceClient(local.CallInvoker);
        var hello = await node.HandshakeAsync(new() { Meta = Meta() }, deadline: Deadline, cancellationToken: ct);
        var identity = Value(hello.Value, hello.Error);
        var owner = identity.OwnerEpoch;
        Assert.NotNull(owner);
        await using var cleanup = new OwnedNodeCleanup(fixture, process, control, owner);

        var begun = await CliAsync(fixture, 0, "center", "connect", origin, "--mode", "self_hosted", "--flow", "device_code");
        var flowId = ReadCliId(begun, "flowId");
        var commandId = ReadCliId(begun, "commandId");
        Assert.Equal(owner, ReadCliId(begun, "ownerEpoch"));
        var pending = await WaitForFlowAsync(control, flowId,
            flow => flow.State == "pending" && flow.HasVerificationUri && flow.HasUserCode && flow.HasNodeKeyFingerprint);
        var displayed = (await CliAsync(fixture, 0, "center", "flow", IdText.Format(flowId))).GetProperty("flow");
        Assert.Equal("pending", displayed.GetProperty("state").GetString());
        var verificationUri = displayed.GetProperty("verificationUri").GetString();
        var userCode = displayed.GetProperty("userCode").GetString();
        var nodeKeyFingerprint = displayed.GetProperty("nodeKeyFingerprint").GetString();
        Assert.True(!string.IsNullOrEmpty(nodeKeyFingerprint) && nodeKeyFingerprint == pending.NodeKeyFingerprint,
            "The installed CLI must display the exact pending owner-local fingerprint.");
        Assert.True(verificationUri == pending.VerificationUri && userCode == pending.UserCode,
            "The installed CLI must display the admitted activation URL and code.");
        var human = await fixture.ProductCliBytesAsync(NativeBound, "center", "flow", IdText.Format(flowId));
        Assert.True(human.ExitCode == 0 && Encoding.UTF8.GetString(human.Stdout).Contains(pending.NodeKeyFingerprint, StringComparison.Ordinal),
            "The installed human-facing CLI must display the pending Node fingerprint.");

        var replayed = await CliAsync(fixture, 0, "center", "connect", origin, "--mode", "self_hosted", "--flow", "device_code",
            "--owner-epoch", IdText.Format(owner), "--command-id", IdText.Format(commandId));
        Assert.Equal(flowId, ReadCliId(replayed, "flowId"));
        Assert.Equal(commandId, ReadCliId(replayed, "commandId"));
        Assert.Equal(owner, ReadCliId(replayed, "ownerEpoch"));
        Assert.False(replayed.TryGetProperty("flow", out _), "A mutation replay must omit the transient flow view.");
        RequireNoDisplayValues(replayed.GetRawText(), pending);
        var originalReceipt = ReadReceiptBody(fixture, owner, commandId);
        RequireNoDisplayValues(originalReceipt, pending);

        await WriteObservationAsync(coordination, "approval.json", new { verificationUri, userCode, nodeKeyFingerprint });
        var terminal = await WaitForFlowAsync(control, flowId, flow => flow.State == "succeeded");
        Assert.False(terminal.HasNodeKeyFingerprint || terminal.HasUserCode || terminal.HasVerificationUri,
            "Terminal owner-local flow responses must omit transient sign-in display values.");
        var terminalCli = await CliAsync(fixture, 0, "center", "flow", IdText.Format(flowId));
        var terminalFlow = terminalCli.GetProperty("flow");
        Assert.False(terminalFlow.TryGetProperty("nodeKeyFingerprint", out _) || terminalFlow.TryGetProperty("userCode", out _) ||
            terminalFlow.TryGetProperty("verificationUri", out _), "Terminal CLI flow output must omit transient sign-in display fields.");
        RequireNoDisplayValues(terminalCli.GetRawText(), pending);

        var original = await node.GetOperationAsync(new() { Meta = Meta(), OwnerEpoch = owner, CommandId = commandId },
            deadline: Deadline, cancellationToken: ct);
        var receipt = Value(original.Value, original.Error).Operation;
        Assert.Equal(commandId, receipt.CommandId);
        Assert.Equal(owner, receipt.OwnerEpoch);
        Assert.Equal(OperationState.Succeeded, receipt.State);
        RequireNoDisplayValues(receipt.ToString(), pending);
        var retainedReceipt = ReadReceiptBody(fixture, owner, commandId);
        RequireNoDisplayValues(retainedReceipt, pending);
        Assert.True(retainedReceipt == originalReceipt, "The same committed BeginConnect receipt must survive device approval unchanged.");

        var linked = await WaitForStatusAsync(control, state => state.ChannelState == "online");
        Assert.Equal("linked", linked.State);
        Assert.NotNull(linked.EnrollmentId);
        await WriteObservationAsync(coordination, "connected.json", new
        {
            ownerEpoch = Convert.ToHexStringLower(owner.Value.Span),
            nodeEpoch = identity.NodeEpoch,
        });
        await WaitForFixtureAsync(coordination, "connected-confirmed", NativeBound, "the real Center's exact V2 connection observation");

        var signedOut = await CliAsync(fixture, 0, "center", "signout");
        Assert.Equal(owner, ReadCliId(signedOut, "ownerEpoch"));
        var signedOutProjection = signedOut.GetProperty("connection");
        Assert.Equal("signed_out", signedOutProjection.GetProperty("state").GetString());
        Assert.Equal("confirmed", signedOutProjection.GetProperty("remoteRevocation").GetString());
        var ended = await WaitForStatusAsync(control, state => state.State == "signed_out");
        Assert.False(ended.ConnectionEnabled);
        Assert.Null(ended.EnrollmentId);
        Assert.Equal("confirmed", ended.RemoteRevocation);
    }

    private static string ReadReceiptBody(TestNode fixture, Id owner, Id commandId)
    {
        using var database = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(fixture.DataRoot),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
            DefaultTimeout = 2,
        }.ToString());
        database.Open();
        using var query = database.CreateCommand();
        query.CommandText = "SELECT response_json FROM command_receipt WHERE owner_epoch=$owner AND command_id=$command;";
        query.Parameters.AddWithValue("$owner", owner.Value.ToByteArray());
        query.Parameters.AddWithValue("$command", Convert.ToHexStringLower(commandId.Value.Span));
        return Assert.IsType<string>(query.ExecuteScalar());
    }

    private static void RequireNoDisplayValues(string observed, CenterConnectFlow pending)
    {
        Assert.False(observed.Contains(pending.NodeKeyFingerprint, StringComparison.Ordinal) ||
            observed.Contains(pending.UserCode, StringComparison.Ordinal) || observed.Contains(pending.VerificationUri, StringComparison.Ordinal),
            "Transient device sign-in display values must stay out of receipts and final projections.");
    }
}
