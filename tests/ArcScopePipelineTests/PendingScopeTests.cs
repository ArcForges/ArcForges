// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.ArcScopePipelineTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 21/22. Unlock when the acquisition, decode and recording pipeline exists.")]
    [Xunit.Trait("Category", "Integration")]
    public void IngestProfileHoldsWithNoUnrecordedLoss() =>
        Xunit.Assert.Fail("Step 21/22 must replace this placeholder with real assertions before removing the skip.");
}
