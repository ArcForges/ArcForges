// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.LocalRpcAotTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 03. Unlock when StreamJsonRpc proxies are generated and exercised over a real Named Pipe/UDS transport in a Native AOT publish.")]
    [Xunit.Trait("Category", "Contract")]
    public void GeneratedProxiesSurviveNativeAotPublish() =>
        Xunit.Assert.Fail("Step 03 must replace this placeholder with real assertions before removing the skip.");
}
