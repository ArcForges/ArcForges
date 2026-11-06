// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core;

/// <summary>
/// The bound of the local <c>TaskService.SubmitTask</c> (AD-0021 section 5; AF-CTR-05 Plan decision Q8, CTR5-NODE-13/14; tasks.proto): a
/// local submission is admitted from a HUMAN caller only, and recorded <c>local_diagnostic</c>. The node's own tests may admit a local SCRIPT
/// caller, never an AGENT, and only on a <c>--test-mode</c> node with <see cref="Variable"/> set to <c>1</c>; production ignores the variable.
/// </summary>
public static class LocalSubmission
{
    /// <summary>The test-mode-only allowance.</summary>
    public const string Variable = "ARCFORGES_TEST_ALLOW_LOCAL_SCRIPT_SUBMIT";

    /// <summary>True when a local SCRIPT submission is admitted: <paramref name="testMode"/> and <paramref name="value"/> exactly <c>1</c>.</summary>
    public static bool ScriptAllowed(bool testMode, string? value) => testMode && string.Equals(value, "1", StringComparison.Ordinal);
}
