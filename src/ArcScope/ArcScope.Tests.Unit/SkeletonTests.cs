// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcScope.Tests.Unit;

public sealed class SkeletonTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Unit")]
    public void ProjectIsDiscoverable()
    {
        Xunit.Assert.NotEmpty(typeof(SkeletonTests).Assembly.GetName().Name!);
    }
}
