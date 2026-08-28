// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.SyncConflictTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 12/26. Unlock when sync objects, revisions and explicit conflict records exist.")]
    [Xunit.Trait("Category", "Contract")]
    public void ExactBaseWritesProduceConflictRecordsNotLastWriteWins() =>
        Xunit.Assert.Fail("Step 12/26 must replace this placeholder with real assertions before removing the skip.");
}
