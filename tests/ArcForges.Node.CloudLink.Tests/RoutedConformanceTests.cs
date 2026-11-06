// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// AF-CTR-05 part N2b against the routed captures of Cloud E2b (<c>center/internal/hub/testdata/routed</c>, vendored byte for byte with a
/// drift check; re-vendored at the E2b merge): every captured routed request carries, in its <c>request</c> field, exact node.v1 TaskService
/// request bytes of its method that this node parses, and every captured value carries the method's TaskService response; the node's own
/// dispatcher answers each captured inner request with a response of that type (the shapes the center forwards unchanged). The FleetService
/// side of these exchanges (the local proxy) is part N3's.
/// </summary>
public sealed class RoutedConformanceTests
{
    /// <summary>The Cloud commit the captures were vendored from (the E2b branch head until its merge; re-vendored then).</summary>
    private const string SourceCommit = "571fa8576a36f94a12190692553d9d38fe78466b";

    private static readonly string Directory = Path.Combine(AppContext.BaseDirectory, "Fixtures", "routed-exchanges");

    private static readonly Dictionary<string, RoutedMethod> Methods = new(StringComparer.Ordinal)
    {
        ["SubmitNodeTask"] = RoutedMethod.SubmitNodeTask,
        ["GetNodeTask"] = RoutedMethod.GetNodeTask,
        ["ListNodeTasks"] = RoutedMethod.ListNodeTasks,
        ["WaitNodeTask"] = RoutedMethod.WaitNodeTask,
        ["ReadNodeTaskOutput"] = RoutedMethod.ReadNodeTaskOutput,
        ["CancelNodeTask"] = RoutedMethod.CancelNodeTask,
    };

    public static TheoryData<string> Captures() =>
        [.. System.IO.Directory.EnumerateFiles(Directory, "*.json").Select(path => Path.GetFileNameWithoutExtension(path)).Order(StringComparer.Ordinal)];

    [Fact]
    public void TheVendoredRoutedCapturesAreTheManifestsBytes()
    {
        var root = FakeCenterConformanceTests.VendoredManifest("routed-exchanges", 35, SourceCommit);
        Assert.Equal("1.0.0-ci.437.1", root.GetProperty("contractsCohort").GetString());
        Assert.All(Methods.Keys, method => Assert.Contains(root.GetProperty("files").EnumerateArray(),
            file => file.GetProperty("file").GetString() == method + "-ok.json"));
    }

    [Theory]
    [MemberData(nameof(Captures))]
    public void EveryCapturedRoutedRequestCarriesTheMethodsExactNodeRequest(string name)
    {
        var (method, request, response) = Load(name);
        Assert.NotNull(Parse(method, request));
        if (response is { } bytes)
        {
            Assert.NotNull(ParseResponse(method, bytes));
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task TheNodeAnswersEveryCapturedInnerRequestWithItsMethodsResponse()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await CloudNode.Create(null).StartAsync();
        var dispatcher = (RoutedDispatcher)node.Runtime.RoutedDispatcher!;
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.AccountSession,
            AccountId = CommandIds.New(),
            UserId = CommandIds.New(),
            SessionId = CommandIds.New(),
        };
        foreach (var name in Methods.Keys.Select(method => method + "-ok"))
        {
            var (method, request, _) = Load(name);
            var parsed = Parse(method, request);
            var now = DateTimeOffset.UtcNow;
            var header = new CallHeader
            {
                CallId = CommandIds.New(),
                Kid = "conformance-key",
                CenterUrlSha256 = ByteString.CopyFrom(new byte[32]),
                AccountId = caller.AccountId,
                TargetNodeId = new Id { Value = ByteString.CopyFrom(node.Runtime.NodeId.Span) },
                Caller = caller,
                Method = method,
                RequestSha256 = ByteString.CopyFrom(SHA256.HashData(request)),
                RequestSize = (uint)request.Length,
                IssuedAt = ProtoTime.ToInstant(now),
                ExpiresAt = ProtoTime.ToInstant(now.AddSeconds(30)),
                Deadline = ProtoTime.ToInstant(now.AddSeconds(5)),
            };
            if (method is RoutedMethod.SubmitNodeTask or RoutedMethod.CancelNodeTask)
            {
                header.CommandId = parsed switch
                {
                    TaskServiceSubmitTaskRequest submit => submit.Meta.CommandId,
                    TaskServiceCancelTaskRequest cancel => cancel.Meta.CommandId,
                    _ => null,
                };
            }

            var answer = await dispatcher.DispatchAsync(new VerifiedCall(header, ByteString.CopyFrom(request), 0), new Link(), TestContext.Current.CancellationToken);
            Assert.NotNull(answer);
            if (answer.Outcome == RoutedOutcome.Executed)
            {
                Assert.NotNull(ParseResponse(method, answer.Response!.ToByteArray()));
            }
            else
            {
                Assert.True(RoutedRefusals.Closed(answer.Error!), name);
            }
        }
    }

    private static (RoutedMethod Method, byte[] Request, byte[]? Response) Load(string name)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Directory, name + ".json")));
        var root = document.RootElement;
        var fleetMethod = root.GetProperty("method").GetString()!.Split('/')[^1];
        var method = Methods[fleetMethod];
        var outer = Message(root.GetProperty("request").GetProperty("frames")[0].GetString()!);
        var request = method switch
        {
            RoutedMethod.SubmitNodeTask => FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(outer).Request,
            RoutedMethod.GetNodeTask => FleetServiceGetNodeTaskRequest.Parser.ParseFrom(outer).Request,
            RoutedMethod.ListNodeTasks => FleetServiceListNodeTasksRequest.Parser.ParseFrom(outer).Request,
            RoutedMethod.WaitNodeTask => FleetServiceWaitNodeTaskRequest.Parser.ParseFrom(outer).Request,
            RoutedMethod.ReadNodeTaskOutput => FleetServiceReadNodeTaskOutputRequest.Parser.ParseFrom(outer).Request,
            _ => FleetServiceCancelNodeTaskRequest.Parser.ParseFrom(outer).Request,
        };
        byte[]? response = null;
        if (root.GetProperty("outcome").GetString() == "value")
        {
            var reply = Message(root.GetProperty("reply").GetProperty("frames")[0].GetString()!);
            response = (method switch
            {
                RoutedMethod.SubmitNodeTask => FleetServiceSubmitNodeTaskResponse.Parser.ParseFrom(reply).Value.Response,
                RoutedMethod.GetNodeTask => FleetServiceGetNodeTaskResponse.Parser.ParseFrom(reply).Value.Response,
                RoutedMethod.ListNodeTasks => FleetServiceListNodeTasksResponse.Parser.ParseFrom(reply).Value.Response,
                RoutedMethod.WaitNodeTask => FleetServiceWaitNodeTaskResponse.Parser.ParseFrom(reply).Value.Response,
                RoutedMethod.ReadNodeTaskOutput => FleetServiceReadNodeTaskOutputResponse.Parser.ParseFrom(reply).Value.Response,
                _ => FleetServiceCancelNodeTaskResponse.Parser.ParseFrom(reply).Value.Response,
            }).ToByteArray();
        }

        return (method, request.ToByteArray(), response);
    }

    /// <summary>The message of a gRPC-web data frame (a flag byte, a big-endian length, the message), given in hex.</summary>
    private static byte[] Message(string frame)
    {
        var bytes = Convert.FromHexString(frame);
        if (bytes.Length >= 5 && bytes[0] == 0 && bytes.Length == 5 + ((bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4]))
        {
            return bytes[5..];
        }

        return bytes;
    }

    private static IMessage Parse(RoutedMethod method, byte[] bytes) => method switch
    {
        RoutedMethod.SubmitNodeTask => TaskServiceSubmitTaskRequest.Parser.ParseFrom(bytes),
        RoutedMethod.GetNodeTask => TaskServiceGetTaskRequest.Parser.ParseFrom(bytes),
        RoutedMethod.ListNodeTasks => TaskServiceListTasksRequest.Parser.ParseFrom(bytes),
        RoutedMethod.WaitNodeTask => TaskServiceWaitTaskRequest.Parser.ParseFrom(bytes),
        RoutedMethod.ReadNodeTaskOutput => TaskServiceReadTaskOutputRequest.Parser.ParseFrom(bytes),
        _ => TaskServiceCancelTaskRequest.Parser.ParseFrom(bytes),
    };

    private static IMessage ParseResponse(RoutedMethod method, byte[] bytes) => method switch
    {
        RoutedMethod.SubmitNodeTask => TaskServiceSubmitTaskResponse.Parser.ParseFrom(bytes),
        RoutedMethod.GetNodeTask => TaskServiceGetTaskResponse.Parser.ParseFrom(bytes),
        RoutedMethod.ListNodeTasks => TaskServiceListTasksResponse.Parser.ParseFrom(bytes),
        RoutedMethod.WaitNodeTask => TaskServiceWaitTaskResponse.Parser.ParseFrom(bytes),
        RoutedMethod.ReadNodeTaskOutput => TaskServiceReadTaskOutputResponse.Parser.ParseFrom(bytes),
        _ => TaskServiceCancelTaskResponse.Parser.ParseFrom(bytes),
    };

    private sealed class Link : IRoutedLink
    {
        public bool Usable => true;

        public bool Stopping => false;
    }
}
