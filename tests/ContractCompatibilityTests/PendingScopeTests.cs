// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.ContractCompatibilityTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 02. Unlock when current and previous contract versions exist and the compatibility diff runs.")]
    [Xunit.Trait("Category", "Contract")]
    public void PreviousAndCurrentContractsStayCompatible() =>
        Xunit.Assert.Fail("Step 02 must replace this placeholder with real assertions before removing the skip.");
}
