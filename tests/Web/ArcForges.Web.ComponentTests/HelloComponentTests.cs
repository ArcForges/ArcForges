// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Web.Components;
using Bunit;

namespace ArcForges.Web.Tests.Components;

public sealed class HelloComponentTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Ui")]
    public void HelloRendersOneLabelledLandmarkHeading()
    {
        using BunitContext context = new();

        IRenderedComponent<Hello> rendered = context.Render<Hello>();

        Xunit.Assert.Equal("Hello from ArcForges Web Components", rendered.Find("h1").TextContent);
        Xunit.Assert.Equal("arc-hello-title", rendered.Find("section").GetAttribute("aria-labelledby"));
        Xunit.Assert.Equal("arc-hello-title", rendered.Find("h1").GetAttribute("id"));
    }
}
