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
/// The connections' sessions and their origins (11 section 1). Every connection is a same-user peer (the LocalRpc service mode refuses other
/// users and unidentifiable peers before HTTP/2), and its origin is assigned at <c>NodeService.Hello</c> from the client kind verified against
/// the peer's executable (<see cref="ClientImages"/>), the reported terminal and CI markers, and the agent roots (<see cref="AgentRoots"/>):
/// HUMAN for a verified Desktop and a verified interactive CLI outside every agent root; AGENT for the MCP adapter and hooks, and a CLI under an
/// agent root; SCRIPT otherwise (a CLI without a terminal or in a CI job, and any kind the peer does not verify). The origin is recorded with
/// every mutation (<c>command_dedup.origin</c>) and decides the permission matrix. Origins are guardrails, not a security boundary: the
/// documented bypasses of 11 section 1 apply (a same-user process can allocate a terminal, leave an agent's ancestry, or run the product's
/// own executables). REMOTE and PEER origins come from the relay and LAN layers (AF-CLD-05, AF-LAN-01), never from a local hello.
/// </summary>
public sealed class ClientSessions
{
    private readonly ConcurrentDictionary<string, ClientSession> _sessions = new(StringComparer.Ordinal);

    /// <summary>Open sessions.</summary>
    public int Count => _sessions.Count;

    /// <summary>Called when a connection said hello (once per connection).</summary>
    public Action<ClientSession>? Opened { get; init; }

    /// <summary>Called when a connection that said hello closed.</summary>
    public Action<ClientSession>? Closed { get; init; }

    /// <summary>The registered agent roots (08 section 3: registered by sessions, AF-AI-01); a CLI under one is AGENT.</summary>
    public AgentRoots Agents { get; } = new();

    /// <summary>
    /// The origin of a client whose hello passed validation (its process is the connection's peer). A kind that claims more than SCRIPT is
    /// honoured only when the peer's executable verifies it; a kind that claims AGENT is honoured as it is, since it never widens anything.
    /// </summary>
    public Origin AssignOrigin(ClientHello hello, LocalRpcPeer peer, ClientImages images)
    {
        ArgumentNullException.ThrowIfNull(hello);
        ArgumentNullException.ThrowIfNull(peer);
        ArgumentNullException.ThrowIfNull(images);
        var verified = images.Verifies(hello.ClientKind, peer.ExecutablePath);
        return hello.ClientKind switch
        {
            ClientKind.Desktop => verified ? Origin.Human : Origin.Script,
            ClientKind.Cli when Agents.Contains(peer.ProcessId) => Origin.Agent,
            ClientKind.Cli => verified && hello.InteractiveTerminal && hello.CiMarkers.Count == 0 ? Origin.Human : Origin.Script,
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
            Opened?.Invoke(session);
            var lifetime = http.Features.Get<IConnectionLifetimeFeature>();
            lifetime?.ConnectionClosed.Register(() =>
            {
                if (_sessions.TryRemove(id, out var closed))
                {
                    Closed?.Invoke(closed);
                }
            });
        }
        else
        {
            _sessions[id] = session;
        }
    }

    /// <summary>The session of the call's connection, or <see langword="null"/> when it sent no hello.</summary>
    public ClientSession? SessionOf(ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return _sessions.TryGetValue(context.GetHttpContext().Connection.Id, out var session) ? session : null;
    }

    /// <summary>The origin of the call's connection: assigned at its hello, or SCRIPT for a connection that sent none.</summary>
    public Origin OriginOf(ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return _sessions.TryGetValue(context.GetHttpContext().Connection.Id, out var session) ? session.Origin : Origin.Script;
    }
}
