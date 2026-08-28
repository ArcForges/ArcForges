// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.McpAotTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 07/14. Unlock when the MCP client runs inside a real Native AOT publish.")]
    [Xunit.Trait("Category", "Contract")]
    public void McpClientRunsInsideNativeAotPublish() =>
        Xunit.Assert.Fail("Step 07/14 must replace this placeholder with real assertions before removing the skip.");
}
