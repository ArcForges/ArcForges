// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.DesktopExperienceTests;

public sealed class SkeletonTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void ProjectIsDiscoverable()
    {
        Xunit.Assert.NotEmpty(typeof(SkeletonTests).Assembly.GetName().Name!);
    }
}
