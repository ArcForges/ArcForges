// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.ReleaseArtifactTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 30/31. Unlock when signed install, update and rollback artifacts exist.")]
    [Xunit.Trait("Category", "Contract")]
    public void SignedArtifactsInstallUpgradeAndRollBack() =>
        Xunit.Assert.Fail("Step 30/31 must replace this placeholder with real assertions before removing the skip.");
}
