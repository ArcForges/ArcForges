// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.VirtualizationTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 06/10/16/22. Unlock when ArcVirtualGridControl and the large-document path exist.")]
    [Xunit.Trait("Category", "Contract")]
    public void RowAndColumnVirtualizationHoldTheFrozenFrameBudget() =>
        Xunit.Assert.Fail("Step 06/10/16/22 must replace this placeholder with real assertions before removing the skip.");
}
