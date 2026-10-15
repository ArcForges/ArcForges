// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using Grpc.Core;
using Microsoft.AspNetCore.Connections.Features;

namespace ArcForges.Node.Api;

/// <summary>What the node knows about one client connection: its verified peer and the origin assigned at its hello.</summary>
/// <param name="Peer">The operating-system peer of the connection (same user, resolved by LocalRpc before HTTP/2).</param>
/// <param name="Kind">The client kind from the hello.</param>
/// <param name="Origin">The origin assigned at the hello.</param>
public sealed record ClientSession(LocalRpcPeer Peer, ClientKind Kind, Origin Origin);

/// <summary>
/// The interim permission model until AF-SEC-01 (Plan): every connection is a same-user peer (the LocalRpc service mode refuses
/// other users and unidentifiable peers before HTTP/2), and the origin is assigned at <c>NodeService.Hello</c> from the client kind
/// and the reported terminal (11 section 1: HUMAN for the Desktop and an interactive CLI, SCRIPT for a CLI without a terminal or in a
/// CI job, AGENT for the MCP adapter and hooks) and recorded with every mutation (<c>command_dedup.origin</c>). The permission matrix,
/// agent ancestry and approvals are AF-SEC-01's; origins are guardrails, not a security boundary.
/// </summary>
public sealed class ClientSessions
{
    private readonly ConcurrentDictionary<string, ClientSession> _sessions = new(StringComparer.Ordinal);

    /// <summary>Open sessions.</summary>
    public int Count => _sessions.Count;

    /// <summary>The interim origin of a client.</summary>
    public static Origin AssignOrigin(ClientHello hello)
    {
        ArgumentNullException.ThrowIfNull(hello);
        return hello.ClientKind switch
        {
            ClientKind.Desktop => Origin.Human,
            ClientKind.Cli => hello.InteractiveTerminal && hello.CiMarkers.Count == 0 ? Origin.Human : Origin.Script,
            ClientKind.McpAdapter or ClientKind.Hook => Origin.Agent,
            _ => Origin.Script,
        };
    }

    /// <summary>Records the session of the call's connection; it ends with the connection.</summary>
    public void Register(ServerCallContext context, ClientSession session)
    {
        ArgumentNullException.ThrowIfNull(context);
        var http = context.GetHttpContext();
        var id = http.Connection.Id;
        if (_sessions.TryAdd(id, session))
        {
            var lifetime = http.Features.Get<IConnectionLifetimeFeature>();
            lifetime?.ConnectionClosed.Register(() => _sessions.TryRemove(id, out _));
        }
        else
        {
            _sessions[id] = session;
        }
    }

    /// <summary>The origin of the call's connection: assigned at its hello, or SCRIPT for a connection that sent none.</summary>
    public Origin OriginOf(ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return _sessions.TryGetValue(context.GetHttpContext().Connection.Id, out var session) ? session.Origin : Origin.Script;
    }
}
