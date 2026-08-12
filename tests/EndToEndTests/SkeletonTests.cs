// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.EndToEndTests;

public sealed class SkeletonTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Integration")]
    public void ProjectIsDiscoverable()
    {
        Xunit.Assert.NotEmpty(typeof(SkeletonTests).Assembly.GetName().Name!);
    }
}
