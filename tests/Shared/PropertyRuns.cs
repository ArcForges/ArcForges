// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Tests;

/// <summary>
/// How much work a property test does (CsCheck; AD-0016 testing techniques). Every routine run does the same fixed number of iterations,
/// chosen per test for its cost; random inputs differ between runs, and a failure prints the seed that reproduces it
/// (<c>CsCheck_Seed=&lt;seed&gt;</c>). The deep tier raises the work with <c>CsCheck_Iter=&lt;n&gt;</c> or <c>CsCheck_Time=&lt;seconds&gt;</c>.
/// Linked into the test projects that have property tests.
/// </summary>
internal static class PropertyRuns
{
    /// <summary>The <c>iter</c> argument: <paramref name="routine"/>, or -1 (CsCheck's environment defaults) when the deep tier set them.</summary>
    public static long Iter(long routine) => IsSet("CsCheck_Iter") || IsSet("CsCheck_Time") ? -1 : routine;

    private static bool IsSet(string name) => !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name));
}
