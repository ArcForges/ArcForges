// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.CloudIntegrationTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 12/13/26. Unlock when PostgreSQL, object storage and the Cloud modules exist behind Testcontainers.")]
    [Xunit.Trait("Category", "Integration")]
    public void CloudVerticalSliceRunsAgainstRealPostgres() =>
        Xunit.Assert.Fail("Step 12/13/26 must replace this placeholder with real assertions before removing the skip.");
}
