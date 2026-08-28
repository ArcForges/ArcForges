// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.EndToEndTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 08+. Unlock when two products and the Cloud slice can complete one cross-process user journey.")]
    [Xunit.Trait("Category", "Integration")]
    public void CrossProductJourneyCompletesAcrossProcesses() =>
        Xunit.Assert.Fail("Step 08+ must replace this placeholder with real assertions before removing the skip.");
}
