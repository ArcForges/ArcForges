// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>REAL local endpoint, proxy, node signing and guarded HTTP transport; scripted center responses are MOCKED.</summary>
public sealed class FleetProxyTests
{
    [Fact(Timeout = 60000)]
    public async Task TheProxyUsesTheConnectionOriginAndSignsTheExactRequestWithFreshNonces()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var center = await FakeCenter.StartAsync();
        center.ScriptedFleet = true;
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        var credentials = center.Issue(nodeId);
        byte[] publicKey;
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            publicKey = key.PublicKey;
            center.CommandKeys.Add(center.Channel.CommandPublicKey);
            center.Channel.RegisterNodeKey(credentials.AccessToken, publicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        var connection = await center.Channel.ProvedAsync();
        await Eventually.TrueAsync(() => node.Cloud.Status().Relay == RelayState.Connected, "the node channel is connected");
        await using var script = await node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        var listValue = new FleetServiceListNodesResponse { Meta = new ResponseMeta(), Value = new FleetServiceListNodesValue() };
        center.Script("ListNodes", Reply(listValue));
        center.Script("ListNodes", Reply(listValue));
        var forged = new RoutedCaller { Kind = CallerKind.NodeRelay, RelayingNodeId = CommandIds.New(), LocalOrigin = Origin.Human };
        var list = new FleetServiceListNodesRequest { Meta = CloudNode.Command(), Caller = forged, RelayAssertion = ByteString.CopyFrom([1, 2, 3]) };
        Assert.NotNull((await fleet.ListNodesAsync(list, deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: TestContext.Current.CancellationToken)).Value);
        Assert.NotNull((await fleet.ListNodesAsync(list, deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: TestContext.Current.CancellationToken)).Value);
        var captures = center.CallsOf("ListNodes");
        Assert.Equal(2, captures.Count);
        var first = FleetServiceListNodesRequest.Parser.ParseFrom(FakeCenter.Payload(captures[0].Body));
        var second = FleetServiceListNodesRequest.Parser.ParseFrom(FakeCenter.Payload(captures[1].Body));
        var firstAssertion = RelayAssertion.Parser.ParseFrom(first.RelayAssertion);
        var secondAssertion = RelayAssertion.Parser.ParseFrom(second.RelayAssertion);
        Assert.Equal(Origin.Script, first.Caller.LocalOrigin);
        Assert.Equal(nodeId, first.Caller.RelayingNodeId.Value.ToByteArray());
        Assert.Equal(Origin.Script, firstAssertion.LocalOrigin);
        Assert.Equal(nodeId, firstAssertion.RelayingNodeId.Value.ToByteArray());
        Assert.Equal(connection.Installation, firstAssertion.RelayingInstallationId.Value.ToByteArray());
        Assert.Equal(firstAssertion.LocalSessionId, secondAssertion.LocalSessionId);
        Assert.NotEqual(firstAssertion.RelayNonce, secondAssertion.RelayNonce);
        Assert.Null(firstAssertion.TargetNodeId);
        Assert.Null(firstAssertion.CommandId);
        var withoutAssertion = first.Clone();
        withoutAssertion.ClearRelayAssertion();
        Assert.Equal(SHA256.HashData(withoutAssertion.ToByteArray()), firstAssertion.RequestSha256.ToByteArray());
        Assert.True(FakeChannelPeer.Verify(publicKey, RelaySignatures.AssertionInput(firstAssertion, center.Endpoint)!, firstAssertion.Signature.ToByteArray()));

        // A signed request can outlive a center switch. Never send its payload to the new center even if node/installation IDs match.
        Assert.True(CenterEndpoint.TryParse("http://localhost:9", out var differentCenter, out _));
        var sentToDifferentCenter = false;
        var mismatch = await node.Cloud.ForwardRelayAsync(new BoundRelayAssertion(firstAssertion, differentCenter),
            (client, options) =>
            {
                sentToDifferentCenter = true;
                return Task.FromResult(new FleetServiceListNodesResponse());
            }, TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal(CenterOutcome.Unreachable, mismatch.Outcome);
        Assert.False(sentToDifferentCenter);

        var target = new Id { Value = ByteString.CopyFrom(nodeId) };
        center.Script("GetNode", Reply(new FleetServiceGetNodeResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceGetNodeValue { Node = new FleetNode { NodeId = target, Name = "own-node" } },
        }));
        var found = await fleet.GetNodeAsync(new FleetServiceGetNodeRequest { Meta = CloudNode.Command(), NodeId = target, Caller = forged },
            deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(target, found.Value.Node.NodeId);
        var getNode = FleetServiceGetNodeRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("GetNode")).Body));
        var getAssertion = RelayAssertion.Parser.ParseFrom(getNode.RelayAssertion);
        Assert.Equal(Origin.Script, getNode.Caller.LocalOrigin);
        Assert.Equal(RoutedMethod.GetNode, getAssertion.Method);
        Assert.Equal(target, getAssertion.TargetNodeId);
        Assert.Null(getAssertion.CommandId);
        getNode.ClearRelayAssertion();
        Assert.Equal(SHA256.HashData(getNode.ToByteArray()), getAssertion.RequestSha256.ToByteArray());
        Assert.True(FakeChannelPeer.Verify(publicKey, RelaySignatures.AssertionInput(getAssertion, center.Endpoint)!, getAssertion.Signature.ToByteArray()));

        var inner = new TaskServiceGetTaskRequest { Meta = CloudNode.Command(), TaskId = CommandIds.New() }.ToByteString();
        var nested = new TaskServiceGetTaskResponse { Meta = new ResponseMeta(), Value = new TaskServiceGetTaskValue() }.ToByteString();
        center.Script("GetNodeTask", Reply(new FleetServiceGetNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceGetNodeTaskValue { NodeId = target, Response = nested },
        }));
        var result = await fleet.GetNodeTaskAsync(new FleetServiceGetNodeTaskRequest
        {
            Meta = CloudNode.Command(),
            NodeId = target,
            Caller = forged,
            Request = inner,
        }, deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(nested, result.Value.Response);
        var sent = FleetServiceGetNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("GetNodeTask")).Body));
        var assertion = RelayAssertion.Parser.ParseFrom(sent.RelayAssertion);
        Assert.Equal(inner, sent.Request);
        Assert.Equal(SHA256.HashData(inner.Span), assertion.RequestSha256.ToByteArray());
        Assert.Equal(target, assertion.TargetNodeId);
        Assert.Null(assertion.CommandId);
        Assert.Equal(firstAssertion.LocalSessionId, assertion.LocalSessionId);
        Assert.True(FakeChannelPeer.Verify(publicKey, RelaySignatures.AssertionInput(assertion, center.Endpoint)!, assertion.Signature.ToByteArray()));

        await using var agent = await node.ChannelAsync(Origin.Agent);
        var agentFleet = new FleetService.FleetServiceClient(agent.CallInvoker);
        var other = new Id { Value = ByteString.CopyFrom(RandomNumberGenerator.GetBytes(16)) };
        var refused = await agentFleet.GetNodeTaskAsync(new FleetServiceGetNodeTaskRequest { Meta = CloudNode.Command(), NodeId = other, Request = inner }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("permission_denied", refused.Error.Code);
        Assert.Equal("relayed_agent_own_node_only", refused.Error.Details.State.Reason);
        Assert.Single(center.CallsOf("GetNodeTask"));

        var unsupported = await Assert.ThrowsAsync<RpcException>(async () =>
            await fleet.RenameNodeAsync(new FleetServiceRenameNodeRequest(), deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(StatusCode.Unimplemented, unsupported.StatusCode);
    }

    [Fact(Timeout = 60000)]
    public async Task ExpiredAssertionIsResignedWithTheSameMutationBytesAndCommand()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var center = await FakeCenter.StartAsync();
        center.ScriptedFleet = true;
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.CommandKeys.Add(center.Channel.CommandPublicKey);
            center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        await center.Channel.ProvedAsync();
        await Eventually.TrueAsync(() => node.Cloud.Status().Relay == RelayState.Connected, "the node channel is connected");
        await using var script = await node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        var target = new Id { Value = ByteString.CopyFrom(nodeId) };
        var meta = CloudNode.Command();
        var inner = new TaskServiceCancelTaskRequest { Meta = meta.Clone(), TaskId = CommandIds.New() }.ToByteString();
        var expired = new ArcError
        {
            Category = ErrorCategory.Authentication,
            Code = "unauthenticated",
            MessageKey = "error.authentication.unauthenticated",
            Effect = EffectCertainty.DidNotHappen,
            Retry = new RetryAdvice { Mode = RetryMode.SameCommand },
            Details = new ErrorDetails { State = new StateFailure { State = "relay_assertion", Reason = "expired" } },
        };
        center.Script("CancelNodeTask", Reply(new FleetServiceCancelNodeTaskResponse { Meta = new ResponseMeta(), Error = expired }));
        center.Script("CancelNodeTask", Reply(new FleetServiceCancelNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceCancelNodeTaskValue { NodeId = target, Response = ByteString.CopyFrom([1]) },
        }));
        var answer = await fleet.CancelNodeTaskAsync(new FleetServiceCancelNodeTaskRequest { Meta = meta, NodeId = target, Request = inner },
            deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: TestContext.Current.CancellationToken);
        Assert.NotNull(answer.Value);
        var calls = center.CallsOf("CancelNodeTask").Select(call => FleetServiceCancelNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(2, calls.Count);
        var first = RelayAssertion.Parser.ParseFrom(calls[0].RelayAssertion);
        var second = RelayAssertion.Parser.ParseFrom(calls[1].RelayAssertion);
        Assert.Equal(inner, calls[0].Request);
        Assert.Equal(inner, calls[1].Request);
        Assert.Equal(meta.CommandId, calls[0].Meta.CommandId);
        Assert.Equal(meta.CommandId, calls[1].Meta.CommandId);
        Assert.Equal(meta.CommandId, first.CommandId);
        Assert.Equal(meta.CommandId, second.CommandId);
        Assert.Equal(first.RequestSha256, second.RequestSha256);
        Assert.NotEqual(first.RelayNonce, second.RelayNonce);
    }

    [Fact(Timeout = 60000)]
    public async Task UnsignedNodeRefusesWithoutContactingTheCenter()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var center = await FakeCenter.StartAsync();
        center.ScriptedFleet = true;
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        await using var local = await node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(local.CallInvoker);
        var response = await fleet.ListNodesAsync(new FleetServiceListNodesRequest { Meta = CloudNode.Command() }, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("not_signed_in", response.Error.Code);
        Assert.Empty(center.CallsOf("ListNodes"));
    }

    [Fact(Timeout = 60000)]
    public async Task WorkspaceProxyBindsEachMethodAndRejectsMismatchedCommandIdsBeforeSending()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var ct = TestContext.Current.CancellationToken;
        // The local RPC, caller classification, nonce and signatures are real; replies below are a scripted center,
        // so this test does not establish center authorization or target workspace behavior.
        await using var center = await FakeCenter.StartAsync();
        center.ScriptedFleet = true;
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        var credentials = center.Issue(nodeId);
        byte[] publicKey;
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            publicKey = key.PublicKey;
            center.CommandKeys.Add(center.Channel.CommandPublicKey);
            center.Channel.RegisterNodeKey(credentials.AccessToken, publicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        await center.Channel.ProvedAsync();
        await Eventually.TrueAsync(() => node.Cloud.Status().Relay == RelayState.Connected, "the node channel is connected");
        await using var human = await node.ChannelAsync(Origin.Human);
        var fleet = new FleetService.FleetServiceClient(human.CallInvoker);
        var target = new Id { Value = ByteString.CopyFrom(nodeId) };
        var forged = new RoutedCaller { Kind = CallerKind.NodeRelay, RelayingNodeId = CommandIds.New(), LocalOrigin = Origin.Agent };
        var meta = CloudNode.Command();
        var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = meta.Clone(), Path = "/test/workspace" }.ToByteString();
        center.Script("RegisterNodeWorkspace", Reply(new FleetServiceRegisterNodeWorkspaceResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceRegisterNodeWorkspaceValue { NodeId = target, Response = ByteString.CopyFrom([1]) },
        }));
        var registered = await fleet.RegisterNodeWorkspaceAsync(new FleetServiceRegisterNodeWorkspaceRequest
        {
            Meta = meta,
            NodeId = target,
            Caller = forged,
            Request = register,
        }, cancellationToken: ct);
        Assert.NotNull(registered.Value);

        var removeMeta = CloudNode.Command();
        var unregister = new WorkspaceServiceUnregisterWorkspaceRequest { Meta = removeMeta.Clone(), WorkspaceId = CommandIds.New() }.ToByteString();
        center.Script("UnregisterNodeWorkspace", Reply(new FleetServiceUnregisterNodeWorkspaceResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceUnregisterNodeWorkspaceValue { NodeId = target, Response = ByteString.CopyFrom([1]) },
        }));
        Assert.NotNull((await fleet.UnregisterNodeWorkspaceAsync(new FleetServiceUnregisterNodeWorkspaceRequest
        {
            Meta = removeMeta,
            NodeId = target,
            Caller = forged,
            Request = unregister,
        }, cancellationToken: ct)).Value);

        var readMeta = new RequestMeta { CorrelationId = CommandIds.New() };
        var list = new WorkspaceServiceListWorkspacesRequest { Meta = readMeta.Clone() }.ToByteString();
        center.Script("ListNodeWorkspaces", Reply(new FleetServiceListNodeWorkspacesResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceListNodeWorkspacesValue { NodeId = target, Response = ByteString.CopyFrom([1]) },
        }));
        Assert.NotNull((await fleet.ListNodeWorkspacesAsync(new FleetServiceListNodeWorkspacesRequest
        {
            Meta = readMeta,
            NodeId = target,
            Caller = forged,
            Request = list,
        }, cancellationToken: ct)).Value);

        var get = new WorkspaceServiceGetWorkspaceRequest { Meta = readMeta.Clone(), WorkspaceId = CommandIds.New() }.ToByteString();
        center.Script("GetNodeWorkspace", Reply(new FleetServiceGetNodeWorkspaceResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceGetNodeWorkspaceValue { NodeId = target, Response = ByteString.CopyFrom([1]) },
        }));
        Assert.NotNull((await fleet.GetNodeWorkspaceAsync(new FleetServiceGetNodeWorkspaceRequest
        {
            Meta = readMeta,
            NodeId = target,
            Caller = forged,
            Request = get,
        }, cancellationToken: ct)).Value);

        var fileRequest = new FileServiceReadFileRequest
        {
            Meta = readMeta.Clone(),
            Path = new FilePath { WorkspaceId = CommandIds.New(), Path = "file.bin" },
            Offset = 0,
            Length = 3,
        }.ToByteString();
        var content = ByteString.CopyFrom([1, 2, 3]);
        var digest = ByteString.CopyFrom(SHA256.HashData(content.Span));
        var nodeResponse = new FileServiceReadFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = readMeta.CorrelationId.Clone() },
            Value = new FileServiceReadFileValue
            {
                Data = content,
                Offset = 0,
                NextOffset = 3,
                Eof = true,
                Sha256 = digest,
                FileSize = 3,
            },
            Audit = new FileAuditMetadata
            {
                Observations = { new FileAuditObservation { Kind = FileAuditKind.ReadBytes, SizeBytes = 3, DigestInputBytes = 3, Sha256 = digest } },
            },
        };
        center.Script("ReadNodeFile", Reply(new FleetServiceReadNodeFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = readMeta.CorrelationId.Clone() },
            Value = new FleetServiceReadNodeFileValue { NodeId = target, Response = nodeResponse.ToByteString() },
        }));
        var read = await fleet.ReadNodeFileAsync(new FleetServiceReadNodeFileRequest
        {
            Meta = readMeta,
            NodeId = target,
            Caller = forged,
            Request = fileRequest,
        }, cancellationToken: ct);
        Assert.NotNull(read.Value);
        Assert.Equal(nodeResponse.ToByteString(), read.Value.Response);

        var directoryRequest = new FileServiceListDirectoryRequest
        {
            Meta = readMeta.Clone(),
            Path = new FilePath { WorkspaceId = CommandIds.New(), Path = "" },
            PageSize = 1,
        }.ToByteString();
        var directoryDigest = ByteString.CopyFrom(SHA256.HashData("ArcForges directory-list v1\0"u8));
        var directoryBytes = (ulong)"ArcForges directory-list v1\0"u8.Length;
        var directoryInner = new FileServiceListDirectoryResponse
        {
            Meta = new ResponseMeta { CorrelationId = readMeta.CorrelationId.Clone() },
            Value = new FileServiceListDirectoryValue
            {
                Truncated = false,
                SnapshotEntries = 0,
                MetadataDigest = directoryDigest,
                MetadataBytes = directoryBytes,
            },
            Audit = new FileAuditMetadata
            {
                Observations = { new FileAuditObservation { Kind = FileAuditKind.DirectoryMetadata, SizeBytes = directoryBytes,
                    DigestInputBytes = directoryBytes, ItemCount = 0, Sha256 = directoryDigest } },
            },
        };
        center.Script("ListNodeDirectory", Reply(new FleetServiceListNodeDirectoryResponse
        {
            Meta = new ResponseMeta { CorrelationId = readMeta.CorrelationId.Clone() },
            Value = new FleetServiceListNodeDirectoryValue { NodeId = target, Response = directoryInner.ToByteString() },
        }));
        var directory = await fleet.ListNodeDirectoryAsync(new FleetServiceListNodeDirectoryRequest
        {
            Meta = readMeta,
            NodeId = target,
            Caller = forged,
            Request = directoryRequest,
        }, cancellationToken: ct);
        Assert.NotNull(directory.Value);
        Assert.Equal(directoryInner.ToByteString(), directory.Value.Response);

        var sentDirectory = FleetServiceListNodeDirectoryRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("ListNodeDirectory")).Body));
        var searchRequest = new FileServiceSearchFilesRequest
        {
            Meta = readMeta.Clone(),
            Path = new FilePath { WorkspaceId = CommandIds.New(), Path = "" },
            Pattern = "not-present",
            Mode = FileSearchMode.Literal,
        }.ToByteString();
        var scanDigest = ByteString.CopyFrom(SHA256.HashData("ArcForges search-scan v1\0"u8));
        var searchInner = new FileServiceSearchFilesResponse
        {
            Meta = new ResponseMeta { CorrelationId = readMeta.CorrelationId.Clone() },
            Value = new FileServiceSearchFilesValue
            {
                VisitedEntries = 1,
                ScannedBytes = 0,
                SkippedFiles = 0,
                Truncated = false,
                ScanDigest = scanDigest,
                ScanTranscriptBytes = 25,
                ScanFileCount = 0,
            },
            Audit = new FileAuditMetadata
            {
                Observations = { new FileAuditObservation { Kind = FileAuditKind.SearchTranscript, SizeBytes = 0,
                    DigestInputBytes = 25, ItemCount = 0, Sha256 = scanDigest } },
            },
        };
        center.Script("SearchNodeFiles", Reply(new FleetServiceSearchNodeFilesResponse
        {
            Meta = new ResponseMeta { CorrelationId = readMeta.CorrelationId.Clone() },
            Value = new FleetServiceSearchNodeFilesValue { NodeId = target, Response = searchInner.ToByteString() },
        }));
        var searchResult = await fleet.SearchNodeFilesAsync(new FleetServiceSearchNodeFilesRequest
        {
            Meta = readMeta,
            NodeId = target,
            Caller = forged,
            Request = searchRequest,
        }, cancellationToken: ct);
        Assert.NotNull(searchResult.Value);
        Assert.Equal(searchInner.ToByteString(), searchResult.Value.Response);
        var sentSearch = FleetServiceSearchNodeFilesRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("SearchNodeFiles")).Body));

        var sentRegister = FleetServiceRegisterNodeWorkspaceRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("RegisterNodeWorkspace")).Body));
        var sentUnregister = FleetServiceUnregisterNodeWorkspaceRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("UnregisterNodeWorkspace")).Body));
        var sentList = FleetServiceListNodeWorkspacesRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("ListNodeWorkspaces")).Body));
        var sentGet = FleetServiceGetNodeWorkspaceRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("GetNodeWorkspace")).Body));
        var sentRead = FleetServiceReadNodeFileRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("ReadNodeFile")).Body));
        var checks = new[]
        {
            (sentRegister.Caller, sentRegister.RelayAssertion, register, RoutedMethod.RegisterNodeWorkspace, meta.CommandId),
            (sentUnregister.Caller, sentUnregister.RelayAssertion, unregister, RoutedMethod.UnregisterNodeWorkspace, removeMeta.CommandId),
            (sentList.Caller, sentList.RelayAssertion, list, RoutedMethod.ListNodeWorkspaces, (Id?)null),
            (sentGet.Caller, sentGet.RelayAssertion, get, RoutedMethod.GetNodeWorkspace, (Id?)null),
            (sentRead.Caller, sentRead.RelayAssertion, fileRequest, RoutedMethod.ReadNodeFile, (Id?)null),
            (sentDirectory.Caller, sentDirectory.RelayAssertion, directoryRequest, RoutedMethod.ListNodeDirectory, (Id?)null),
            (sentSearch.Caller, sentSearch.RelayAssertion, searchRequest, RoutedMethod.SearchNodeFiles, (Id?)null),
        };
        foreach (var (caller, signedBytes, payload, method, command) in checks)
        {
            var signed = RelayAssertion.Parser.ParseFrom(signedBytes);
            Assert.Equal(Origin.Human, caller.LocalOrigin);
            Assert.Equal(target, caller.RelayingNodeId);
            Assert.Equal(method, signed.Method);
            Assert.Equal(target, signed.TargetNodeId);
            Assert.Equal(command, signed.CommandId);
            Assert.Equal(SHA256.HashData(payload.Span), signed.RequestSha256.ToByteArray());
            Assert.True(FakeChannelPeer.Verify(publicKey, RelaySignatures.AssertionInput(signed, center.Endpoint)!, signed.Signature.ToByteArray()));
        }

        var mismatch = await fleet.RegisterNodeWorkspaceAsync(new FleetServiceRegisterNodeWorkspaceRequest
        {
            Meta = CloudNode.Command(),
            NodeId = target,
            Request = register,
        }, cancellationToken: ct);
        Assert.Equal("invalid_argument", mismatch.Error.Code);
        var unexpectedReadCommand = await fleet.GetNodeWorkspaceAsync(new FleetServiceGetNodeWorkspaceRequest
        {
            Meta = CloudNode.Command(),
            NodeId = target,
            Request = get,
        }, cancellationToken: ct);
        Assert.Equal("invalid_argument", unexpectedReadCommand.Error.Code);
        var invalidFileRead = await fleet.ReadNodeFileAsync(new FleetServiceReadNodeFileRequest
        {
            Meta = CloudNode.Command(),
            NodeId = target,
            Request = fileRequest,
        }, cancellationToken: ct);
        Assert.Equal("invalid_argument", invalidFileRead.Error.Code);
        var invalidDirectory = await fleet.ListNodeDirectoryAsync(new FleetServiceListNodeDirectoryRequest
        {
            Meta = CloudNode.Command(),
            NodeId = target,
            Request = directoryRequest,
        }, cancellationToken: ct);
        Assert.Equal("invalid_argument", invalidDirectory.Error.Code);
        var invalidSearch = await fleet.SearchNodeFilesAsync(new FleetServiceSearchNodeFilesRequest
        {
            Meta = CloudNode.Command(),
            NodeId = target,
            Request = searchRequest,
        }, cancellationToken: ct);
        Assert.Equal("invalid_argument", invalidSearch.Error.Code);
        Assert.Single(center.CallsOf("SearchNodeFiles"));
        Assert.Single(center.CallsOf("ListNodeDirectory"));
        Assert.Single(center.CallsOf("ReadNodeFile"));
        Assert.Single(center.CallsOf("RegisterNodeWorkspace"));
        Assert.Single(center.CallsOf("GetNodeWorkspace"));

        // A scripted center can send an SDK-accepted noncanonical Decimal. The local consumer must reject it.
        var tooLong = new FileServiceReadFileRequest
        {
            Meta = readMeta.Clone(),
            Path = new FilePath { WorkspaceId = CommandIds.New(), Path = new string('x', 4097) },
            Offset = 0,
            Length = 1,
        }.ToByteString();
        var invalidDecimal = new ArcError
        {
            Category = ErrorCategory.Resource,
            Code = "too_large",
            MessageKey = "error.resource.too_large",
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Effect = EffectCertainty.DidNotHappen,
            CorrelationId = readMeta.CorrelationId.Clone(),
            Details = new ErrorDetails
            {
                Limit = new LimitFailure
                {
                    LimitName = "path_bytes",
                    Maximum = new ArcForges.Contracts.Foundation.V1.Decimal { Value = "4096.00" },
                }
            },
        };
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(invalidDecimal));
        center.Script("ReadNodeFile", Reply(new FleetServiceReadNodeFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = readMeta.CorrelationId.Clone() },
            Error = invalidDecimal,
        }));
        var invalidReply = await fleet.ReadNodeFileAsync(new FleetServiceReadNodeFileRequest
        {
            Meta = readMeta,
            NodeId = target,
            Request = tooLong,
        }, cancellationToken: ct);
        Assert.Equal("internal", invalidReply.Error.Code);
        Assert.Equal(EffectCertainty.Unknown, invalidReply.Error.Effect);
        Assert.Equal(RetryMode.Never, invalidReply.Error.Retry.Mode);
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(invalidReply.Error));
        Assert.Equal(2, center.CallsOf("ReadNodeFile").Count);
    }

    private static FakeFault.Raw Reply(IMessage response) => new([.. FakeCenter.DataFrame(response), .. FakeCenter.TrailerFrame(0, null)]);
}
