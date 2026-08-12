// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Web.BrowserTests;

public sealed class SkeletonTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Browser")]
    public void ProjectIsDiscoverable()
    {
        Xunit.Assert.NotEmpty(typeof(SkeletonTests).Assembly.GetName().Name!);
    }
}
