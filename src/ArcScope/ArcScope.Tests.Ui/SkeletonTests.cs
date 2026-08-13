// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcScope.Tests.Ui;

public sealed class SkeletonTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Ui")]
    public void ReferencedProductionModulesExecuteTheirDeclaredContract()
    {
        IReadOnlyList<string> modules = ArcForges.Testing.ReferencedModuleContract.Verify(typeof(SkeletonTests).Assembly);
        Xunit.Assert.NotEmpty(modules);
    }
}
