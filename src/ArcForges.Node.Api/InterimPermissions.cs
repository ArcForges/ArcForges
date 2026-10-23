// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;

namespace ArcForges.Node.Api;

/// <summary>The operations of the scheduler's services that the default permission matrix (11 section 1) gates by origin.</summary>
internal enum GatedOperation
{
    /// <summary>Cancel (or pause, resume) a task another owner submitted: HUMAN A, SCRIPT P, AGENT P.</summary>
    CancelOthersTask,

    /// <summary>Change a task's priority (<c>SetTaskPriority</c>): HUMAN A, SCRIPT A, AGENT P.</summary>
    ChangeTaskPriority,

    /// <summary>Pause or resume a pool: HUMAN A, SCRIPT A, AGENT P.</summary>
    PauseOrResumePool,

    /// <summary>Change parallelism (<c>SetParallelism</c>): HUMAN A, SCRIPT P, AGENT P.</summary>
    ChangeParallelism,

    /// <summary>Lower the limit of the caller's own agent session: HUMAN A, SCRIPT P, AGENT A.</summary>
    LowerOwnSessionParallelism,

    /// <summary>Change other policy, create, update or delete pools: HUMAN A, SCRIPT P, AGENT P.</summary>
    ChangePolicy,

    /// <summary>Change <c>retry_safety</c> (AD-0006 section 4: HUMAN-edited): HUMAN A, everyone else D.</summary>
    ChangeRetrySafety,
}

/// <summary>
/// The interim permission gate of the scheduler's services until AF-SEC-01 (11 section 1, the default matrix): <c>A</c> runs; <c>D</c> is
/// refused; <c>P</c> (approval required) is refused for every origin, SCRIPT included, because approvals do not exist yet; no approval
/// object is created. Every origin the matrix does not grant (REMOTE, PEER, an unknown one) is refused: the gate fails closed. This is the
/// single point AF-SEC-01 replaces with the policy's <c>permissions</c> and approval requests.
/// </summary>
internal static class InterimPermissions
{
    private enum Cell
    {
        Allow,
        Approval,
        Deny,
    }

    /// <summary>The refusal of <paramref name="operation"/> for <paramref name="origin"/>, or <see langword="null"/> when it is allowed.</summary>
    public static ArcError? Check(Origin origin, GatedOperation operation, string method) => CellOf(origin, operation) switch
    {
        Cell.Allow => null,
        Cell.Approval => NodeErrors.PermissionDenied(
            $"{method}: an approval is required for {Name(origin)} callers; approvals arrive with AF-SEC-01, so the call is refused (no approval was created)"),
        _ => NodeErrors.PermissionDenied($"{method}: denied for {Name(origin)} callers"),
    };

    /// <summary>True when <paramref name="operation"/> is allowed for <paramref name="origin"/> without an approval.</summary>
    public static bool Allowed(Origin origin, GatedOperation operation) => CellOf(origin, operation) == Cell.Allow;

    private static Cell CellOf(Origin origin, GatedOperation operation) => (origin, operation) switch
    {
        (Origin.Human, _) => Cell.Allow,
        (Origin.Script or Origin.Agent, GatedOperation.ChangeRetrySafety) => Cell.Deny,
        (Origin.Script, GatedOperation.ChangeTaskPriority or GatedOperation.PauseOrResumePool) => Cell.Allow,
        (Origin.Agent, GatedOperation.LowerOwnSessionParallelism) => Cell.Allow,
        (Origin.Script or Origin.Agent, _) => Cell.Approval,
        _ => Cell.Deny,
    };

    private static string Name(Origin origin) => origin switch
    {
        Origin.Script => "SCRIPT",
        Origin.Agent => "AGENT",
        Origin.Remote => "REMOTE",
        Origin.Human => "HUMAN",
        _ => origin.ToString().ToUpperInvariant(),
    };
}
