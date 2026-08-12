// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcSlate.Tests.Ui;

public sealed class SkeletonTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Ui")]
    public void ProjectIsDiscoverable()
    {
        Xunit.Assert.NotEmpty(typeof(SkeletonTests).Assembly.GetName().Name!);
    }
}
