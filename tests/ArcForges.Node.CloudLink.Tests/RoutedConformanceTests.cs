// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// Verifies the immutable Cloud E2b captures and the published V1 request and response shapes used in their historical bodies.
/// </summary>
public sealed class RoutedConformanceTests
{
    /// <summary>The merged Cloud E2b commit whose captures were verified byte for byte.</summary>
    private const string SourceCommit = "b7743b931aba21465aceb12861502c5fe27699e4";

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
}
