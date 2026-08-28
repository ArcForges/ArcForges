// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.MobileContractTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 18-20. Unlock when the MAUI shared layer owns real contracts and validators.")]
    [Xunit.Trait("Category", "Contract")]
    public void SharedMobileLayerLeaksNoPlatformTypes() =>
        Xunit.Assert.Fail("Step 18-20 must replace this placeholder with real assertions before removing the skip.");
}
