// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.NativeContentTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 06/07/09/10. Unlock when the native preview pipeline and ContentSandbox parse real malicious fixtures under budget.")]
    [Xunit.Trait("Category", "Contract")]
    public void MaliciousFixturesFailClosedInsideTheSandbox() =>
        Xunit.Assert.Fail("Step 06/07/09/10 must replace this placeholder with real assertions before removing the skip.");
}
