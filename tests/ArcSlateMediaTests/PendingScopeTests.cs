// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.ArcSlateMediaTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 23-25. Unlock when the media, timeline and export pipeline exists behind ArcMediaNative.")]
    [Xunit.Trait("Category", "Integration")]
    public void MediaGoldensAndAvDriftStayInsideBudget() =>
        Xunit.Assert.Fail("Step 23-25 must replace this placeholder with real assertions before removing the skip.");
}
