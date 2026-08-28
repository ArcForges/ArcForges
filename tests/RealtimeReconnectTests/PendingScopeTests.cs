// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.RealtimeReconnectTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 12/18/19. Unlock when SignalR events and the HTTP snapshot recovery path exist.")]
    [Xunit.Trait("Category", "Integration")]
    public void SequenceGapRecoversThroughHttpSnapshot() =>
        Xunit.Assert.Fail("Step 12/18/19 must replace this placeholder with real assertions before removing the skip.");
}
