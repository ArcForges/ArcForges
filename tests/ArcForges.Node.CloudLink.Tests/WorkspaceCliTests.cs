// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// Real CLI process, local RPC and signed proxy. The center replies below are scripted, so these tests do not claim
/// center authorization, target execution or a real-center end-to-end result.
/// </summary>
public sealed class WorkspaceCliTests
{
    [Fact(Timeout = 60_000)]
    public async Task RegisterListShowAndUnregisterUseBoundFleetEnvelopes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.ScriptedFleet = true;
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var nodeId = new Id { Value = ByteString.CopyFrom(node.Runtime.NodeId.Span) };
        var credentials = center.Issue(node.Runtime.NodeId.ToArray());
        byte[] publicKey;
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(node.Runtime.NodeId.Span, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(node.Runtime.NodeId.Span, center.Endpoint.Origin, TimeProvider.System))
        {
            publicKey = key.PublicKey;
            center.CommandKeys.Add(center.Channel.CommandPublicKey);
            center.Channel.RegisterNodeKey(credentials.AccessToken, publicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        await center.Channel.ProvedAsync();
        await Eventually.TrueAsync(() => node.Cloud.Status().Relay == RelayState.Connected, "the node channel is connected");
        var workspaceId = CommandIds.New();
        const string path = "/synthetic/cli-workspace";
        var workspace = new Workspace
        {
            WorkspaceId = workspaceId,
            Kind = WorkspaceKind.Registered,
            State = WorkspaceState.Active,
            Name = "demo",
            RootPath = path,
        };
        center.Script("RegisterNodeWorkspace", Reply(new FleetServiceRegisterNodeWorkspaceResponse
        {
            Meta = new ResponseMeta { CorrelationId = CommandIds.New() },
            Value = new FleetServiceRegisterNodeWorkspaceValue
            {
                NodeId = nodeId,
                Response = new WorkspaceServiceRegisterWorkspaceResponse
                {
                    Meta = new ResponseMeta { CorrelationId = CommandIds.New() },
                    Value = new WorkspaceServiceRegisterWorkspaceValue { Workspace = workspace },
                }.ToByteString(),
            },
        }));
        var registered = await RunCliAsync(node, ct, "workspace", "register", path, "--name", "demo");
        Assert.True(registered.Exit == 0, "registration exit=" + registered.Exit + "; stderr=" + registered.Error);
        Assert.Contains(IdText.Format(workspaceId), registered.Output, StringComparison.Ordinal);
        var sent = FleetServiceRegisterNodeWorkspaceRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("RegisterNodeWorkspace")).Body));
        var inner = WorkspaceServiceRegisterWorkspaceRequest.Parser.ParseFrom(sent.Request);
        var assertion = RelayAssertion.Parser.ParseFrom(sent.RelayAssertion);
        Assert.Equal(path, inner.Path);
        Assert.Equal("demo", inner.Name);
        Assert.Equal(inner.Meta.CommandId, sent.Meta.CommandId);
        Assert.Equal(inner.Meta.CommandId, assertion.CommandId);
        Assert.Equal(RoutedMethod.RegisterNodeWorkspace, assertion.Method);
        Assert.Equal(Origin.Script, sent.Caller.LocalOrigin); // this test process is noninteractive, not a HUMAN claim.
        Assert.True(FakeChannelPeer.Verify(publicKey, RelaySignatures.AssertionInput(assertion, center.Endpoint)!, assertion.Signature.ToByteArray()));

        // Script the same declared metadata transcript as the producer, bound to each actual CLI request.
        // These bytes describe synthetic records only, not an observed workspace or a real Center audit.
        async Task<(int Exit, string Output, string Error)> ReadReply(string method, string[] arguments,
            Func<ByteString, IMessage> response)
        {
            var before = center.CallsOf(method).Count;
            var releaseRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            center.Script(method, new FakeFault.Hold(releaseRead));
            var pending = RunCliAsync(node, ct, arguments);
            await Eventually.TrueAsync(() => center.CallsOf(method).Count == before + 1, "the scripted read request arrived");
            var body = ByteString.CopyFrom(FakeCenter.Payload(center.CallsOf(method)[before].Body));
            center.Script(method, Reply(response(body)));
            releaseRead.TrySetResult();
            return await pending;
        }
        var page = new WorkspaceServiceListWorkspacesResponse
        {
            Value = new WorkspaceServiceListWorkspacesValue { Workspaces = { workspace }, Page = new PageState { HasMore = false } },
            Audit = WorkspaceAuditMetadata.ForRecords([workspace]),
        };
        FleetServiceListNodeWorkspacesResponse ListResponse(ByteString body)
        {
            var request = WorkspaceServiceListWorkspacesRequest.Parser.ParseFrom(
                FleetServiceListNodeWorkspacesRequest.Parser.ParseFrom(body).Request);
            var meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() };
            page.Meta = meta.Clone();
            return new FleetServiceListNodeWorkspacesResponse
            {
                Meta = meta,
                Value = new FleetServiceListNodeWorkspacesValue { NodeId = nodeId, Response = page.ToByteString() },
            };
        }
        var listed = await ReadReply("ListNodeWorkspaces", ["workspace", "list"], ListResponse);
        Assert.True(listed.Exit == 0, "list exit=" + listed.Exit + "; stderr=" + listed.Error);
        Assert.Contains(path, listed.Output, StringComparison.Ordinal);
        var sentList = FleetServiceListNodeWorkspacesRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("ListNodeWorkspaces")).Body));
        Assert.Null(sentList.Meta.CommandId);
        Assert.Null(WorkspaceServiceListWorkspacesRequest.Parser.ParseFrom(sentList.Request).Meta.CommandId);

        FleetServiceGetNodeWorkspaceResponse GetResponse(ByteString body, Workspace declared)
        {
            var request = WorkspaceServiceGetWorkspaceRequest.Parser.ParseFrom(
                FleetServiceGetNodeWorkspaceRequest.Parser.ParseFrom(body).Request);
            var meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() };
            return new FleetServiceGetNodeWorkspaceResponse
            {
                Meta = meta,
                Value = new FleetServiceGetNodeWorkspaceValue
                {
                    NodeId = nodeId,
                    Response = new WorkspaceServiceGetWorkspaceResponse
                    {
                        Meta = meta.Clone(),
                        Value = new WorkspaceServiceGetWorkspaceValue { Workspace = declared },
                        Audit = WorkspaceAuditMetadata.ForRecords([declared]),
                    }.ToByteString(),
                },
            };
        }
        var shown = await ReadReply("GetNodeWorkspace", ["workspace", "show", IdText.Format(workspaceId)],
            body => GetResponse(body, workspace));
        Assert.True(shown.Exit == 0, "show exit=" + shown.Exit + "; stderr=" + shown.Error);
        Assert.Contains(path, shown.Output, StringComparison.Ordinal);
        var sentGet = FleetServiceGetNodeWorkspaceRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("GetNodeWorkspace")).Body));
        Assert.Null(sentGet.Meta.CommandId);
        Assert.Equal(workspaceId, WorkspaceServiceGetWorkspaceRequest.Parser.ParseFrom(sentGet.Request).WorkspaceId);

        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        center.Script("UnregisterNodeWorkspace", new FakeFault.Hold(release));
        var removing = RunCliAsync(node, ct, "workspace", "unregister", IdText.Format(workspaceId));
        await Eventually.TrueAsync(() => center.CallsOf("UnregisterNodeWorkspace").Count == 1, "the unregister request arrived");
        var sentRemove = FleetServiceUnregisterNodeWorkspaceRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("UnregisterNodeWorkspace")).Body));
        var remove = WorkspaceServiceUnregisterWorkspaceRequest.Parser.ParseFrom(sentRemove.Request);
        Assert.Equal(workspaceId, remove.WorkspaceId);
        Assert.Equal(remove.Meta.CommandId, sentRemove.Meta.CommandId);
        Assert.Equal(remove.Meta.CommandId, RelayAssertion.Parser.ParseFrom(sentRemove.RelayAssertion).CommandId);
        center.Script("UnregisterNodeWorkspace", Reply(new FleetServiceUnregisterNodeWorkspaceResponse
        {
            Meta = new ResponseMeta { CorrelationId = CommandIds.New() },
            Value = new FleetServiceUnregisterNodeWorkspaceValue
            {
                NodeId = nodeId,
                Response = new WorkspaceServiceUnregisterWorkspaceResponse
                {
                    Meta = new ResponseMeta { CorrelationId = CommandIds.New() },
                    Value = new WorkspaceServiceUnregisterWorkspaceValue { Receipt = new Receipt { CommandId = remove.Meta.CommandId, Effect = EffectCertainty.Happened } },
                }.ToByteString(),
            },
        }));
        release.TrySetResult();
        var removed = await removing;
        Assert.True(removed.Exit == 0, "unregister exit=" + removed.Exit + "; stderr=" + removed.Error);

        var holdWrong = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        center.Script("UnregisterNodeWorkspace", new FakeFault.Hold(holdWrong));
        var badReceiptCall = RunCliAsync(node, ct, "workspace", "unregister", IdText.Format(workspaceId));
        await Eventually.TrueAsync(() => center.CallsOf("UnregisterNodeWorkspace").Count == 2, "the second unregister request arrived");
        center.Script("UnregisterNodeWorkspace", Reply(new FleetServiceUnregisterNodeWorkspaceResponse
        {
            Meta = new ResponseMeta { CorrelationId = CommandIds.New() },
            Value = new FleetServiceUnregisterNodeWorkspaceValue
            {
                NodeId = nodeId,
                Response = new WorkspaceServiceUnregisterWorkspaceResponse
                {
                    Meta = new ResponseMeta { CorrelationId = CommandIds.New() },
                    Value = new WorkspaceServiceUnregisterWorkspaceValue
                    {
                        Receipt = new Receipt { CommandId = CommandIds.New(), Effect = EffectCertainty.Happened },
                    },
                }.ToByteString(),
            },
        }));
        holdWrong.TrySetResult();
        var badReceipt = await badReceiptCall;
        Assert.NotEqual(0, badReceipt.Exit);
        Assert.DoesNotContain("Unregistered", badReceipt.Output, StringComparison.Ordinal);

        var local = await RunCliAsync(node, ct, "workspace", "register", path, "--local");
        Assert.NotEqual(0, local.Exit);
        Assert.Single(center.CallsOf("RegisterNodeWorkspace"));

        var wrongWorkspace = workspace.Clone();
        wrongWorkspace.WorkspaceId = CommandIds.New();
        var wrongGet = await ReadReply("GetNodeWorkspace", ["workspace", "show", IdText.Format(workspaceId)],
            body => GetResponse(body, wrongWorkspace));
        Assert.NotEqual(0, wrongGet.Exit);
        Assert.DoesNotContain(IdText.Format(wrongWorkspace.WorkspaceId), wrongGet.Output, StringComparison.Ordinal);

        var missingId = workspace.Clone();
        missingId.WorkspaceId = null;
        page.Value.Workspaces.Clear();
        page.Value.Workspaces.Add(missingId);
        var wrongList = await ReadReply("ListNodeWorkspaces", ["workspace", "list"], ListResponse);
        Assert.NotEqual(0, wrongList.Exit);

        page.Value.Workspaces.Clear();
        page.Value.Workspaces.Add(workspace);
        page.Audit = null;
        var missingTranscript = await ReadReply("ListNodeWorkspaces", ["workspace", "list"], ListResponse);
        Assert.NotEqual(0, missingTranscript.Exit);
        Assert.DoesNotContain(path, missingTranscript.Output, StringComparison.Ordinal);
        page.Audit = WorkspaceAuditMetadata.ForRecords([workspace]);
        page.Audit.Observations[0].Sha256 = ByteString.CopyFrom(new byte[32]);
        var forgedTranscript = await ReadReply("ListNodeWorkspaces", ["workspace", "list"], ListResponse);
        Assert.NotEqual(0, forgedTranscript.Exit);
        Assert.DoesNotContain(path, forgedTranscript.Output, StringComparison.Ordinal);
    }

    private static FakeFault.Raw Reply(IMessage response) => new([.. FakeCenter.DataFrame(response), .. FakeCenter.TrailerFrame(0, null)]);

    private static async Task<(int Exit, string Output, string Error)> RunCliAsync(CloudNode node, CancellationToken token, params string[] args)
    {
        var start = new ProcessStartInfo(CloudNode.HelperExecutable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add(NodeLocations.TestModeOption);
        foreach (var arg in args) start.ArgumentList.Add(arg);
        start.Environment[NodeLocations.EndpointVariable] = node.Endpoint.Address;
        start.Environment[NodeLocations.ConfigDirectoryVariable] = Path.GetDirectoryName(node.ConfigPath)!;
        start.Environment.Remove("ARCFORGES_OS_SECRET_STORE_TESTS");
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the test CLI.");
        var output = process.StandardOutput.ReadToEndAsync(token);
        var error = process.StandardError.ReadToEndAsync(token);
        try
        {
            await process.WaitForExitAsync(token).WaitAsync(TimeSpan.FromSeconds(25), token);
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None);
            }

            throw;
        }

        return (process.ExitCode, await output, await error);
    }
}
