// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Security;

/// <summary>
/// The node's center-routed policy at the caller level (AF-CTR-05 CTR5-NODE-09; Design 11 section 1, "Center-routed callers"; Plan decisions
/// Q7 as amended by PB-2, D0-B1 and N-9; policy.proto <c>CenterRoutedPolicy</c>). A center-routed call reaches the node with origin REMOTE and
/// the <see cref="CenterCaller"/> the center verified and signed into the call header. This class decides what the node can decide from the
/// caller alone, before the request is read:
/// <list type="bullet">
/// <item>the policy's <c>enabled</c> switch (absent = true): off, every routed call is refused <c>center_routed_disabled</c>;</item>
/// <item>a caller missing the fields of its kind is refused <c>center_caller_incomplete</c> (verifier N-4: fail closed before policy);</item>
/// <item>a node-relayed caller from another node is refused <c>relay_own_node_only</c> unless <c>relayed_from</c> is ACCOUNT on this, the
/// target, node; after that opt-in a claimed AGENT origin is refused <c>relayed_agent_own_node_only</c> (until AF-CTR-07) and a claimed HUMAN
/// or SCRIPT origin gets the SCRIPT cells, never more (the claimed origin is advisory cross-node).</item>
/// </list>
/// The relaying node checked is the one the center states in the signed header (D0-B1). Which HUMAN, SCRIPT or AGENT cells apply on top of
/// the routed column is <see cref="CellsOrigin"/>; the matrix takes the narrower of the two (<see cref="PermissionMatrix.DecideRouted"/>).
/// </summary>
public static class CenterRouting
{
    /// <summary>The policy is off.</summary>
    public const string Disabled = "center_routed_disabled";

    /// <summary>A relayed call from another node without the target's opt-in.</summary>
    public const string OwnNodeOnly = "relay_own_node_only";

    /// <summary>A relayed AGENT caller from another node.</summary>
    public const string AgentOwnNodeOnly = "relayed_agent_own_node_only";

    /// <summary>A caller missing the fields its kind requires, or carrying another kind's.</summary>
    public const string Incomplete = "center_caller_incomplete";

    /// <summary>A caller kind the node does not serve (AGENT_GRANT before AF-CTR-07, or unknown).</summary>
    public const string Unsupported = "center_caller_unsupported";

    /// <summary>
    /// Why <paramref name="caller"/> lacks the fields of its kind (verifier N-4), or <see langword="null"/>: NODE_RELAY needs the relaying node,
    /// a local origin of HUMAN, SCRIPT or AGENT and the local session, and no account-session fields; ACCOUNT_SESSION needs the user and the
    /// center session, and no relay fields; both need the account.
    /// </summary>
    public static string? Shape(CenterCaller caller)
    {
        ArgumentNullException.ThrowIfNull(caller);
        if (!caller.HasKind || caller.Kind is not (CenterCallerKind.AccountSession or CenterCallerKind.NodeRelay))
        {
            return Unsupported;
        }

        if (!Valid(caller.AccountId))
        {
            return Incomplete;
        }

        return caller.Kind == CenterCallerKind.NodeRelay
            ? Valid(caller.RelayingNodeId) && caller.HasLocalOrigin && caller.LocalOrigin is Origin.Human or Origin.Script or Origin.Agent
                && Valid(caller.LocalSessionId) && caller.UserId is null && caller.SessionId is null ? null : Incomplete
            : Valid(caller.UserId) && Valid(caller.SessionId) && caller.RelayingNodeId is null && !caller.HasLocalOrigin
                && caller.LocalSessionId is null ? null : Incomplete;
    }

    /// <summary>
    /// The caller-level refusal reason for <paramref name="caller"/> at the node <paramref name="nodeId"/> under <paramref name="policy"/>, or
    /// <see langword="null"/> when the call goes on to the operation's cells. <see cref="Shape"/> is checked first.
    /// </summary>
    public static string? Refusal(CenterCaller caller, ReadOnlySpan<byte> nodeId, CenterRoutedPolicy? policy)
    {
        ArgumentNullException.ThrowIfNull(caller);
        if (Shape(caller) is { } shape)
        {
            return shape;
        }

        if (policy is { HasEnabled: true, Enabled: false })
        {
            return Disabled;
        }

        if (caller.Kind != CenterCallerKind.NodeRelay || OwnNode(caller, nodeId))
        {
            return null;
        }

        // Plan PB-2: cross-node relay is an opt-in on the target only (UNSPECIFIED is read as OWN_NODE).
        if (policy is not { HasRelayedFrom: true, RelayedFrom: RelayedFrom.Account })
        {
            return OwnNodeOnly;
        }

        return caller.LocalOrigin == Origin.Agent ? AgentOwnNodeOnly : null;
    }

    /// <summary>True for a node-relayed caller whose relaying node, as the signed header states it, is <paramref name="nodeId"/>.</summary>
    public static bool OwnNode(CenterCaller caller, ReadOnlySpan<byte> nodeId)
    {
        ArgumentNullException.ThrowIfNull(caller);
        return caller.Kind == CenterCallerKind.NodeRelay && caller.RelayingNodeId is { } relaying && relaying.Value.Span.SequenceEqual(nodeId);
    }

    /// <summary>
    /// The origin whose HUMAN, SCRIPT or AGENT cells (and AGENT-only rules) apply to <paramref name="caller"/> on top of the routed column:
    /// the local origin of a relay from this node, SCRIPT for a relay from another node (after the opt-in; never more), and REMOTE (the routed
    /// column alone) for an account session.
    /// </summary>
    public static Origin CellsOrigin(CenterCaller caller, ReadOnlySpan<byte> nodeId)
    {
        ArgumentNullException.ThrowIfNull(caller);
        if (caller.Kind != CenterCallerKind.NodeRelay)
        {
            return Origin.Remote;
        }

        return OwnNode(caller, nodeId) ? caller.LocalOrigin : Origin.Script;
    }

    /// <summary>
    /// True when <paramref name="a"/> and <paramref name="b"/> are the same center caller for ownership (Design 11 section 1, "Command lines":
    /// "the same account session, or the same relaying node and local origin"): the same account and center session for an account session,
    /// the same account, relaying node and local origin for a relay (the local session is not compared). A user's other session is another
    /// owner (verifier N-11), while its resend is the same caller class (<see cref="SameClass"/>).
    /// </summary>
    public static bool Same(CenterCaller? a, CenterCaller? b)
    {
        if (a is null || b is null || a.Kind != b.Kind || !Equal(a.AccountId, b.AccountId))
        {
            return false;
        }

        return a.Kind switch
        {
            CenterCallerKind.AccountSession => Equal(a.SessionId, b.SessionId),
            CenterCallerKind.NodeRelay => Equal(a.RelayingNodeId, b.RelayingNodeId) && a.LocalOrigin == b.LocalOrigin,
            _ => false,
        };
    }

    /// <summary>
    /// True when <paramref name="a"/> and <paramref name="b"/> are the same caller class for the replay of a recorded outcome and the in-progress
    /// answer (N2b decisions B-2 as refined by E2b review C2-N3): the class the center's routing record digests, so the node answers exactly the
    /// resends the center routes to one record. An account session compares the account and the user, never the session; a relay compares the
    /// account, the relaying node and the local origin, never the local session.
    /// </summary>
    public static bool SameClass(CenterCaller? a, CenterCaller? b)
    {
        if (a is null || b is null || a.Kind != b.Kind || !Equal(a.AccountId, b.AccountId))
        {
            return false;
        }

        return a.Kind switch
        {
            CenterCallerKind.AccountSession => Equal(a.UserId, b.UserId),
            CenterCallerKind.NodeRelay => Equal(a.RelayingNodeId, b.RelayingNodeId) && a.LocalOrigin == b.LocalOrigin,
            _ => false,
        };
    }

    private static bool Valid(ArcForges.Contracts.Foundation.V1.Id? id) =>
        id is { Value.Length: 16 } && id.Value.Span.IndexOfAnyExcept((byte)0) >= 0;

    private static bool Equal(ArcForges.Contracts.Foundation.V1.Id? a, ArcForges.Contracts.Foundation.V1.Id? b) =>
        a is not null && b is not null && a.Value.Span.SequenceEqual(b.Value.Span);
}
