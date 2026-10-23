// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Security;

/// <summary>
/// One operation of the permission matrix (11 section 1): its name (the <c>PermissionOverride.operation</c> and
/// <c>ExplainPermission.operation</c> value, for example <c>task.cancel_others</c>), the default decision per origin and, for the REMOTE
/// column, the <c>fleet.v1.NodeCommandBody</c> kind with its risk class.
/// </summary>
/// <param name="Name">The operation name.</param>
/// <param name="Description">What the operation is (the matrix row).</param>
/// <param name="Human">The HUMAN cell (fixed: overrides never change it).</param>
/// <param name="Script">The SCRIPT cell.</param>
/// <param name="Agent">The AGENT cell.</param>
/// <param name="RemoteKind">The remote command kind, or <see langword="null"/> when nothing reaches the operation remotely (REMOTE D).</param>
/// <param name="RemoteRisk">The remote command kind's risk class.</param>
/// <param name="Peer">The PEER cell.</param>
/// <param name="Fixed">True for rows no override may change (approvers, retry-safety and permission edits, integrations, rollback).</param>
/// <param name="Risk">The risk class an approval request for the operation carries.</param>
public sealed record PermissionRow(string Name, string Description, PermissionDecision Human, PermissionDecision Script, PermissionDecision Agent,
    string? RemoteKind, RiskClass RemoteRisk, PermissionDecision Peer, bool Fixed, RiskClass Risk);

/// <summary>A decision with where it came from (<c>ExplainPermission</c>).</summary>
/// <param name="Decision">ALLOW, APPROVAL, DENY, or REMOTE_POLICY (a REMOTE command kind: the cloud's step-up and the node's remote-control policy decide).</param>
/// <param name="Source">The matrix default or the override that decided it.</param>
/// <param name="RemoteRisk">The remote command kind's risk class (REMOTE only).</param>
public sealed record PermissionVerdict(PermissionDecision Decision, string Source, RiskClass RemoteRisk);

/// <summary>
/// The default permission matrix of 11 section 1 and its overrides (policy <c>permissions</c>, edited only by HUMAN callers). The matrix is a
/// guardrail, not a security boundary: every local client runs as the node's user, and the documented bypasses of 11 section 1 apply (a
/// same-user process can look interactive, leave an agent's ancestry, or edit the store directly). Operation names follow the example of
/// policy.proto (<c>task.cancel_others</c>): <c>&lt;object&gt;.&lt;action&gt;</c>. The rows the matrix gives per remedy class ("Apply remedy") and
/// the application rows of the Direction table are not part of release 1 and are not listed.
/// </summary>
public static class PermissionMatrix
{
    private const PermissionDecision A = PermissionDecision.Allow;
    private const PermissionDecision P = PermissionDecision.Approval;
    private const PermissionDecision D = PermissionDecision.Deny;

    /// <summary>The source text of a matrix default.</summary>
    public const string DefaultSource = "default permission matrix (11 section 1)";

    /// <summary>Submit a task (own).</summary>
    public const string TaskSubmit = "task.submit";

    /// <summary>Read tasks, records and resources.</summary>
    public const string TaskRead = "task.read";

    /// <summary>Read an output tail.</summary>
    public const string TaskReadOutput = "task.read_output";

    /// <summary>Cancel the caller's own task.</summary>
    public const string TaskCancelOwn = "task.cancel_own";

    /// <summary>Cancel, pause, resume or re-prioritise another owner's task.</summary>
    public const string TaskCancelOthers = "task.cancel_others";

    /// <summary>Change a task's priority (<c>SetTaskPriority</c>).</summary>
    public const string TaskSetPriority = "task.set_priority";

    /// <summary>Freeze a running task (<c>PauseTask</c>; tasks.proto: HUMAN A, SCRIPT A, AGENT P).</summary>
    public const string TaskPause = "task.pause";

    /// <summary>Purge a task record (<c>PurgeTaskRecord</c>; HUMAN only).</summary>
    public const string TaskPurge = "task.purge";

    /// <summary>Pause or resume a pool.</summary>
    public const string PoolPause = "pool.pause";

    /// <summary>Change parallelism (<c>SetParallelism</c>).</summary>
    public const string ParallelismChange = "parallelism.change";

    /// <summary>Lower the limit of the caller's own agent session (the AGENT exception of the parallelism row).</summary>
    public const string ParallelismLowerOwnSession = "parallelism.lower_own_session";

    /// <summary>Change other policy, create, update or delete pools.</summary>
    public const string PolicyChange = "policy.change";

    /// <summary>Change <c>retry_safety</c> (AD-0006 section 4: HUMAN-edited).</summary>
    public const string PolicyRetrySafety = "policy.retry_safety";

    /// <summary>Change <c>permissions</c> (11 section 1: editable only by HUMAN).</summary>
    public const string PolicyPermissions = "policy.permissions";

    /// <summary>Decide an approval.</summary>
    public const string ApprovalDecide = "approval.decide";

    /// <summary>Plan a cleanup.</summary>
    public const string CleanupPlan = "cleanup.plan";

    /// <summary>Execute a cleanup.</summary>
    public const string CleanupExecute = "cleanup.execute";

    /// <summary>Adopt a process (<c>AdoptProcess</c>).</summary>
    public const string ProcessAdopt = "process.adopt";

    /// <summary>Terminate a process (<c>TerminateProcess</c>, and cancelling an ADOPTED task).</summary>
    public const string ProcessTerminate = "process.terminate";

    /// <summary>Integrations, pairing, account sign-in.</summary>
    public const string Integrations = "integration.change";

    /// <summary>Stop the node (<c>StopNode</c>).</summary>
    public const string NodeStop = "node.stop";

    /// <summary>Apply an update.</summary>
    public const string NodeUpdate = "node.update";

    /// <summary>Roll back an update.</summary>
    public const string NodeRollback = "node.rollback";

    /// <summary>Change node settings (<c>UpdateNodeSettings</c>; node.proto: HUMAN A, SCRIPT P, AGENT D).</summary>
    public const string NodeSettings = "node.settings";

    /// <summary>Rename the node (<c>RenameNode</c>; node.proto: HUMAN A, SCRIPT A, AGENT D).</summary>
    public const string NodeRename = "node.rename";

    /// <summary>Mark notifications read (<c>MarkNotificationsRead</c>; node.proto: HUMAN only).</summary>
    public const string NotificationsMarkRead = "notifications.mark_read";

    /// <summary>The rows, in matrix order.</summary>
    public static IReadOnlyList<PermissionRow> Rows { get; } =
    [
        new(TaskSubmit, "Submit task (own)", A, A, A, "run_task", RiskClass.High, A, false, RiskClass.Medium),
        new(TaskRead, "Read tasks, records, resources", A, A, A, "refresh", RiskClass.Low, A, false, RiskClass.Low),
        new(TaskReadOutput, "Read an output tail", A, A, A, "read_output_tail", RiskClass.Low, D, false, RiskClass.Low),
        new(TaskCancelOwn, "Cancel own task", A, A, A, "cancel_task", RiskClass.Medium, A, false, RiskClass.Medium),
        new(TaskCancelOthers, "Cancel others' tasks", A, P, P, "cancel_task", RiskClass.Medium, D, false, RiskClass.Medium),
        new(TaskSetPriority, "Change a task's priority", A, A, P, "set_priority", RiskClass.Medium, D, false, RiskClass.Medium),
        new(TaskPause, "Pause a running task", A, A, P, null, RiskClass.Unspecified, D, false, RiskClass.Medium),
        new(TaskPurge, "Purge a task record", A, D, D, null, RiskClass.Unspecified, D, false, RiskClass.High),
        new(PoolPause, "Pause or resume a pool", A, A, P, "pause_queue", RiskClass.Low, D, false, RiskClass.Low),
        new(ParallelismChange, "Change parallelism", A, P, P, "set_parallelism", RiskClass.High, D, false, RiskClass.Medium),
        new(ParallelismLowerOwnSession, "Lower the caller's own session's parallelism limit", A, P, A, "set_parallelism", RiskClass.High, D, false, RiskClass.Low),
        new(PolicyChange, "Change other policy, create or delete pools", A, P, P, null, RiskClass.Unspecified, D, false, RiskClass.High),
        new(PolicyRetrySafety, "Change retry_safety rules (HUMAN-edited)", A, D, D, null, RiskClass.Unspecified, D, true, RiskClass.High),
        new(PolicyPermissions, "Change the permission overrides (HUMAN-edited)", A, D, D, null, RiskClass.Unspecified, D, true, RiskClass.High),
        new(ApprovalDecide, "Decide an approval", A, D, D, "decide_approval", RiskClass.High, D, true, RiskClass.High),
        new(CleanupPlan, "Plan cleanup", A, A, A, null, RiskClass.Unspecified, D, false, RiskClass.Low),
        new(CleanupExecute, "Execute cleanup", A, P, P, null, RiskClass.Unspecified, D, false, RiskClass.High),
        new(ProcessAdopt, "Adopt a process", A, D, D, null, RiskClass.Unspecified, D, false, RiskClass.High),
        new(ProcessTerminate, "Terminate a process", A, P, P, null, RiskClass.Unspecified, D, false, RiskClass.High),
        new(Integrations, "Integrations, pairing, account sign-in", A, D, D, null, RiskClass.Unspecified, D, true, RiskClass.High),
        new(NodeStop, "Stop the node", A, A, D, "stop_node", RiskClass.High, D, false, RiskClass.High),
        new(NodeUpdate, "Apply an update", A, A, D, "apply_update", RiskClass.High, D, false, RiskClass.High),
        new(NodeRollback, "Roll back an update", A, D, D, null, RiskClass.Unspecified, D, true, RiskClass.High),
        new(NodeSettings, "Change node settings", A, P, D, null, RiskClass.Unspecified, D, false, RiskClass.Medium),
        new(NodeRename, "Rename the node", A, A, D, null, RiskClass.Unspecified, D, false, RiskClass.Low),
        new(NotificationsMarkRead, "Mark notifications read", A, D, D, null, RiskClass.Unspecified, D, false, RiskClass.Low),
    ];

    private static readonly Dictionary<string, PermissionRow> ByName = Rows.ToDictionary(row => row.Name, StringComparer.Ordinal);

    /// <summary>The row of <paramref name="operation"/>, or <see langword="null"/> for an unknown name.</summary>
    public static PermissionRow? Find(string? operation) => operation is not null && ByName.TryGetValue(operation, out var row) ? row : null;

    /// <summary>
    /// The decision for <paramref name="origin"/> on <paramref name="operation"/> under the policy's <paramref name="overrides"/>. HUMAN rows
    /// and <see cref="PermissionRow.Fixed"/> rows ignore overrides; the last matching override wins. REMOTE answers REMOTE_POLICY for an
    /// operation with a command kind (the cloud's step-up and the node's remote-control policy decide, AD-0009 section 5) and DENY otherwise,
    /// unless an override denies it. Any other origin is denied: the matrix fails closed.
    /// </summary>
    public static PermissionVerdict Decide(Origin origin, string operation, IReadOnlyList<PermissionOverride> overrides)
    {
        ArgumentNullException.ThrowIfNull(overrides);
        var row = Find(operation) ?? throw new ArgumentException($"Unknown operation '{operation}'.", nameof(operation));
        var defaults = origin switch
        {
            Origin.Human => row.Human,
            Origin.Script => row.Script,
            Origin.Agent => row.Agent,
            Origin.Remote => row.RemoteKind is null ? D : PermissionDecision.RemotePolicy,
            Origin.Peer => row.Peer,
            _ => D,
        };
        var verdict = new PermissionVerdict(defaults, DefaultSource, origin == Origin.Remote ? row.RemoteRisk : RiskClass.Unspecified);
        if (row.Fixed || origin is not (Origin.Script or Origin.Agent or Origin.Remote))
        {
            return verdict;
        }

        for (var index = overrides.Count - 1; index >= 0; index--)
        {
            var rule = overrides[index];
            if (rule.Origin == origin && string.Equals(rule.Operation, operation, StringComparison.Ordinal) && Valid(rule) is null)
            {
                return verdict with { Decision = rule.Decision, Source = string.Create(CultureInfo.InvariantCulture, $"policy permissions[{index}]") };
            }
        }

        return verdict;
    }

    /// <summary>
    /// Why an override is not valid, or <see langword="null"/>: the operation must be a matrix row that is not fixed; the origin SCRIPT, AGENT
    /// or REMOTE (HUMAN rows are fixed; policy.proto); SCRIPT and AGENT take ALLOW, APPROVAL or DENY; a REMOTE override may only deny, because
    /// remote commands are decided by the remote-control policy (AF-CLD-05).
    /// </summary>
    public static string? Valid(PermissionOverride rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (Find(rule.HasOperation ? rule.Operation : null) is not { } row)
        {
            return "operation: a permission matrix operation (" + string.Join(", ", Rows.Where(candidate => !candidate.Fixed).Select(candidate => candidate.Name)) + ")";
        }

        if (row.Fixed)
        {
            return $"operation: '{row.Name}' is fixed (11 section 1) and cannot be overridden";
        }

        return rule.Origin switch
        {
            Origin.Script or Origin.Agent when rule.Decision is A or P or D => null,
            Origin.Script or Origin.Agent => "decision: ALLOW, APPROVAL or DENY",
            Origin.Remote when rule.Decision == D => null,
            Origin.Remote => "decision: a REMOTE override may only DENY (remote commands follow the remote-control policy)",
            _ => "origin: SCRIPT, AGENT or REMOTE (HUMAN rows are fixed)",
        };
    }

    /// <summary>The upper-case name of an origin, as messages and audit summaries show it.</summary>
    public static string Name(Origin origin) => origin switch
    {
        Origin.Human => "HUMAN",
        Origin.Script => "SCRIPT",
        Origin.Agent => "AGENT",
        Origin.Remote => "REMOTE",
        Origin.Peer => "PEER",
        Origin.Node => "NODE",
        _ => origin.ToString().ToUpperInvariant(),
    };
}
