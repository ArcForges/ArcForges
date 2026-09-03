// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using ArcForges.Contracts.Foundation;
using ArcForges.Contracts.LocalRpc;
using ArcForges.Contracts.LocalRpc.Notes;
using ArcForges.Contracts.LocalRpc.Scope;
using ArcForges.Contracts.LocalRpc.Slate;

namespace ArcForges.Tests.ContractCompatibilityTests;

internal static class LocalRpcGolden
{
    private static readonly Lazy<string> Root = new(Locate);

    internal static IEnumerable<(string Name, object Value, JsonTypeInfo TypeInfo)> All()
    {
        yield return ("register-instance-request", LocalRpcFixtures.RegisterRequest(), Strict<RegisterInstanceRequest>());
        yield return ("register-instance-result", LocalRpcFixtures.RegisterResult(), Strict<RegisterInstanceResult>());
        yield return ("heartbeat-request", LocalRpcFixtures.HeartbeatReq(), Strict<HeartbeatRequest>());
        yield return ("heartbeat-result", LocalRpcFixtures.HeartbeatRes(), Strict<HeartbeatResult>());
        yield return ("route-request", LocalRpcFixtures.RouteReq(), Strict<RouteRequest>());
        yield return ("route-result", LocalRpcFixtures.RouteRes(), Strict<RouteResult>());
        yield return ("request-approval-request", LocalRpcFixtures.RequestApprovalReq(), Strict<RequestApprovalRequest>());
        yield return ("request-approval-result", LocalRpcFixtures.RequestApprovalRes(), Strict<RequestApprovalResult>());
        yield return ("resolve-approval-request", LocalRpcFixtures.ResolveApprovalReq(), Strict<ResolveApprovalRequest>());
        yield return ("resolve-approval-result", LocalRpcFixtures.ResolveApprovalRes(), Strict<ResolveApprovalResult>());
        yield return ("connection-established-notice", LocalRpcFixtures.ConnectionNotice(), Strict<ConnectionEstablishedNotice>());
        yield return ("insert-blocks-request", LocalRpcFixtures.InsertBlocksReq(), Strict<InsertBlocksRequest>());
        yield return ("insert-blocks-response", LocalRpcFixtures.InsertBlocksRes(), Strict<InsertBlocksResponse>());
        yield return ("arc-result-insert-blocks", LocalRpcFixtures.ArcResultInsertBlocks(), Strict<ArcResult<InsertBlocksResponse>>());
        yield return ("scope-search-resources-request", LocalRpcFixtures.ScopeSearchReq(), Strict<ArcForges.Contracts.LocalRpc.Scope.SearchResourcesRequest>());
        yield return ("scope-search-resources-response", LocalRpcFixtures.ScopeSearchRes(), Strict<ArcForges.Contracts.LocalRpc.Scope.SearchResourcesResponse>());
        yield return ("slate-get-project-snapshot-request", LocalRpcFixtures.SlateProjectReq(), Strict<GetProjectSnapshotRequest>());
        yield return ("slate-get-project-snapshot-response", LocalRpcFixtures.SlateProjectRes(), Strict<GetProjectSnapshotResponse>());
    }

    internal static JsonTypeInfo<T> Strict<T>() =>
        (JsonTypeInfo<T>)LocalRpcJsonContext.Default.GetTypeInfo(typeof(T))!;

    internal static JsonTypeInfo<T> Inbound<T>() =>
        (JsonTypeInfo<T>)LocalRpcInboundJsonContext.Default.GetTypeInfo(typeof(T))!;

    internal static string Path(string name) =>
        System.IO.Path.Combine(Root.Value, name + ".json");

    internal static string Read(string name) =>
        File.ReadAllText(Path(name), Encoding.UTF8).TrimEnd('\r', '\n');

    internal static void Write(string name, string json) =>
        File.WriteAllText(Path(name), json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

    internal static bool Exists(string name) => File.Exists(Path(name));

    internal static string Serialize(object value, JsonTypeInfo typeInfo) =>
        JsonSerializer.Serialize(value, typeInfo);

    private static string Locate()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(System.IO.Path.Combine(directory.FullName, "ArcForges.slnx")))
        {
            directory = directory.Parent;
        }

        var root = directory?.FullName ?? throw new InvalidOperationException("Repository root was not found.");
        return System.IO.Path.Combine(root, "tests", "ContractCompatibilityTests", "golden", "localrpc", "v1");
    }
}
