// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.PersistenceRecoveryTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 04. Unlock when the SQLite journal, snapshot and migration framework exists.")]
    [Xunit.Trait("Category", "Integration")]
    public void CrashDuringWriteRecoversTheLastDurableGeneration() =>
        Xunit.Assert.Fail("Step 04 must replace this placeholder with real assertions before removing the skip.");
}
