// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.DesktopExperienceTests;

public sealed class SkeletonTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void ReferencedProductionModulesExecuteTheirDeclaredContract()
    {
        IReadOnlyList<string> modules = ArcForges.Testing.ReferencedModuleContract.Verify(typeof(SkeletonTests).Assembly);
        Xunit.Assert.NotEmpty(modules);
    }
}
