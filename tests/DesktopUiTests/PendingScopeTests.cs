// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.DesktopUiTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 06/09/10/21/23. Unlock when the desktop shells expose real pages and accessibility identifiers.")]
    [Xunit.Trait("Category", "Ui")]
    public void DesktopJourneysRunThroughAccessibleUiSeams() =>
        Xunit.Assert.Fail("Step 06/09/10/21/23 must replace this placeholder with real assertions before removing the skip.");
}
