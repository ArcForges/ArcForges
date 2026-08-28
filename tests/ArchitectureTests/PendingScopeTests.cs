// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.ArchitectureTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 01.04. Unlock when the 13 rules run on NetArchTest.Rules over the loaded src assemblies and the 26 fixtures are compiled with Roslyn, replacing the current source-text scan.")]
    [Xunit.Trait("Category", "Architecture")]
    public void RulesRunOnLoadedAssembliesInsteadOfSourceText() =>
        Xunit.Assert.Fail("Step 01.04 must replace this placeholder with real assertions before removing the skip.");
}
