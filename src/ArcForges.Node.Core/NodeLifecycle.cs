// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core;

/// <summary>A transition that SM-NODE does not allow.</summary>
public sealed class InvalidLifecycleTransitionException : InvalidOperationException
{
    /// <summary>Creates the exception.</summary>
    public InvalidLifecycleTransitionException(NodeLifecycleState from, NodeLifecycleState to)
        : base($"SM-NODE does not allow {from} -> {to}.")
    {
        From = from;
        To = to;
    }

    /// <summary>Creates the exception.</summary>
    public InvalidLifecycleTransitionException()
    {
    }

    /// <summary>Creates the exception.</summary>
    public InvalidLifecycleTransitionException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public InvalidLifecycleTransitionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>The current state.</summary>
    public NodeLifecycleState From { get; }

    /// <summary>The refused target.</summary>
    public NodeLifecycleState To { get; }
}

/// <summary>
/// The node lifecycle (state machine SM-NODE, ArcForges-Design <c>state-machines/machines.json</c>): STARTING, RECOVERING, READY,
/// DEGRADED, STOPPING, UPDATING, and the pseudo-state STOPPED (process exit). The state lives in memory and every transition is
/// journaled as a <see cref="NodeStatusChanged"/> event on topic NODE.
/// </summary>
public sealed class NodeLifecycle
{
    private static readonly Dictionary<NodeLifecycleState, NodeLifecycleState[]> Allowed = new()
    {
        [NodeLifecycleState.Starting] = [NodeLifecycleState.Recovering],
        [NodeLifecycleState.Recovering] = [NodeLifecycleState.Ready, NodeLifecycleState.Degraded],
        [NodeLifecycleState.Ready] = [NodeLifecycleState.Degraded, NodeLifecycleState.Stopping, NodeLifecycleState.Updating],
        [NodeLifecycleState.Degraded] = [NodeLifecycleState.Ready, NodeLifecycleState.Stopping, NodeLifecycleState.Updating],
        [NodeLifecycleState.Stopping] = [],
        [NodeLifecycleState.Updating] = [],
    };

    private readonly Lock _gate = new();
    private NodeLifecycleState _state = NodeLifecycleState.Starting;
    private string _reason = string.Empty;

    /// <summary>The current state.</summary>
    public NodeLifecycleState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    /// <summary>Why the node is in its state (for example the missing capabilities of DEGRADED).</summary>
    public string Reason
    {
        get
        {
            lock (_gate)
            {
                return _reason;
            }
        }
    }

    /// <summary>True in STOPPING or UPDATING: new API calls answer <c>STATE/node_stopping</c>.</summary>
    public bool IsStopping => State is NodeLifecycleState.Stopping or NodeLifecycleState.Updating;

    /// <summary>True when SM-NODE allows <paramref name="from"/> -> <paramref name="to"/>.</summary>
    public static bool IsAllowed(NodeLifecycleState from, NodeLifecycleState to) => Allowed.TryGetValue(from, out var targets) && targets.Contains(to);

    /// <summary>Moves to <paramref name="to"/> (called by the command that journals the change).</summary>
    /// <exception cref="InvalidLifecycleTransitionException">SM-NODE does not allow the transition.</exception>
    public void MoveTo(NodeLifecycleState to, string reason)
    {
        lock (_gate)
        {
            if (!IsAllowed(_state, to))
            {
                throw new InvalidLifecycleTransitionException(_state, to);
            }

            _state = to;
            _reason = reason ?? string.Empty;
        }
    }
}
