// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Api;

namespace ArcForges.Node.Core.Tests;

/// <summary>Verifies attribution to the local session and approval requester.</summary>
public sealed class CallerTests
{
    /// <summary>The sessions a hello can open: each kind with the origins the node can assign it.</summary>
    public static TheoryData<ClientKind, Origin> Sessions => new()
    {
        { ClientKind.Cli, Origin.Human },
        { ClientKind.Cli, Origin.Script },
        { ClientKind.Cli, Origin.Agent },
        { ClientKind.Desktop, Origin.Human },
        { ClientKind.Desktop, Origin.Script },
        { ClientKind.McpAdapter, Origin.Agent },
        { ClientKind.Hook, Origin.Agent },
        { ClientKind.Supervisor, Origin.Script },
    };

    [Theory]
    [MemberData(nameof(Sessions))]
    public void AConnectionsCallerHasItsSessionsOriginKindAndSession(ClientKind kind, Origin origin)
    {
        var session = new ClientSession(Peer(), kind, origin);
        var caller = Caller.OfConnection(session);
        Assert.Equal(origin, caller.Origin);
        Assert.Equal(kind, caller.Kind);
        Assert.Same(session, caller.Session);
        Assert.Null(caller.ApprovalId);
        Assert.False(caller.Approved);
        Assert.Equal(new ActorRef { Origin = origin, ClientKind = kind }, caller.Actor);
    }

    [Fact]
    public void AConnectionWithoutAHelloIsAScriptCallerWithoutAKindOrSession()
    {
        var caller = Caller.OfConnection(null);
        Assert.Equal(Origin.Script, caller.Origin);
        Assert.Equal(ClientKind.Unspecified, caller.Kind);
        Assert.Null(caller.Session);
        Assert.False(caller.Approved);
        Assert.Equal(new ActorRef { Origin = Origin.Script, ClientKind = ClientKind.Unspecified }, caller.Actor);

        // A local approval keeps the original requester when it executes without a connection.
        var approved = Caller.OfApproval(new ActorRef { Origin = Origin.Agent, ClientKind = ClientKind.McpAdapter }, [1, 2, 3]);
        Assert.Equal((Origin.Agent, ClientKind.McpAdapter), (approved.Origin, approved.Kind));
        Assert.Null(approved.Session);
        Assert.True(approved.Approved);
    }

    private static LocalRpcPeer Peer() => new(Environment.ProcessId, DateTimeOffset.UtcNow, null, null, null);
}
