// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core.Platform;

/// <summary>
/// The Linux execution test hooks (02 section 4: <c>ARCFORGES_*</c> variables, honoured only with <c>--test-mode</c>), so each test node
/// gets its own slice and a test can withhold the user manager or a controller's delegation (16 section 4; R-RES-008):
/// <list type="bullet">
/// <item><see cref="Slice"/>: the root slice instead of <c>arcforges.slice</c>, for example <c>arcforges-test-&lt;id&gt;.slice</c>.</item>
/// <item><see cref="ManagerAddress"/>: the user manager's D-Bus address; an address where nothing listens makes the node run as it does
/// without a user manager (observe only).</item>
/// <item><see cref="Controllers"/>: the controllers treated as delegated (space-separated), for example <c>cpu pids</c> to run as with a
/// manager that has no memory delegation.</item>
/// <item><see cref="GuardUnit"/>: the guard unit the node starts when it is installed, instead of <c>arcforges-guard.service</c>.</item>
/// </list>
/// </summary>
public static class LinuxTestHooks
{
    /// <summary>The root slice.</summary>
    public const string Slice = "ARCFORGES_SLICE";

    /// <summary>The user manager's D-Bus address.</summary>
    public const string ManagerAddress = "ARCFORGES_SYSTEMD_ADDRESS";

    /// <summary>The controllers treated as delegated.</summary>
    public const string Controllers = "ARCFORGES_TEST_CONTROLLERS";

    /// <summary>The guard unit.</summary>
    public const string GuardUnit = "ARCFORGES_GUARD_UNIT";

    /// <summary>The production guard unit (13 section 3.4).</summary>
    public const string DefaultGuardUnit = "arcforges-guard.service";

    /// <summary>The value of a hook in test mode, or null.</summary>
    public static string? Value(bool testMode, string variable) =>
        testMode && Environment.GetEnvironmentVariable(variable) is { Length: > 0 } value ? value : null;
}
