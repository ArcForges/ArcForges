// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.GraphicsInteropTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 07/22/24/25. Unlock when a real GPU adapter is probed and external-surface copy levels are observable.")]
    [Xunit.Trait("Category", "Contract")]
    public void CopyLevelsAndDeviceLossAreObservedOnRealAdapters() =>
        Xunit.Assert.Fail("Step 07/22/24/25 must replace this placeholder with real assertions before removing the skip.");
}
