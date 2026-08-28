// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.PublicApiContractTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 02/12. Unlock when endpoint metadata, generated OpenAPI and the Refit surface exist and their sets are compared.")]
    [Xunit.Trait("Category", "Contract")]
    public void EndpointMetadataAndRefitSurfacesAreEqual() =>
        Xunit.Assert.Fail("Step 02/12 must replace this placeholder with real assertions before removing the skip.");
}
