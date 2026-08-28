// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.NativeAbiTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 07/22/24. Unlock when every owned C ABI shim has a real implementation on all five RIDs.")]
    [Xunit.Trait("Category", "NativeAbi")]
    public void OwnedShimsExportOneStableAbiOnEveryRid() =>
        Xunit.Assert.Fail("Step 07/22/24 must replace this placeholder with real assertions before removing the skip.");
}
