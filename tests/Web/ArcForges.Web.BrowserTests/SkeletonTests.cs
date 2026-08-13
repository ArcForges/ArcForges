// SPDX-License-Identifier: AGPL-3.0-only

using Microsoft.Playwright;

namespace ArcForges.Web.BrowserTests;

public sealed class SkeletonTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Browser")]
    public async Task PublishedWasmBootsInARealBrowser()
    {
        string baseUrl = Environment.GetEnvironmentVariable("ARCFORGES_WEB_BASE_URL") ??
            throw new InvalidOperationException("ARCFORGES_WEB_BASE_URL must identify the published site.");

        using IPlaywright playwright = await Playwright.CreateAsync().ConfigureAwait(true);
        IBrowser browser = await playwright.Chromium
            .LaunchAsync(new BrowserTypeLaunchOptions { Headless = true })
            .ConfigureAwait(true);
        try
        {
            IPage page = await browser.NewPageAsync().ConfigureAwait(true);
            IResponse? response = await page
                .GotoAsync(baseUrl, new PageGotoOptions { WaitUntil = WaitUntilState.NetworkIdle })
                .ConfigureAwait(true);

            Xunit.Assert.NotNull(response);
            Xunit.Assert.True(response.Ok, $"Browser navigation failed with HTTP {response.Status}.");
            Xunit.Assert.Equal("ArcForges", await page.Locator("h1").InnerTextAsync().ConfigureAwait(true));
            Xunit.Assert.Contains(
                "Hello from the ArcForges Web companion",
                await page.Locator("main").InnerTextAsync().ConfigureAwait(true),
                StringComparison.Ordinal);
        }
        finally
        {
            await browser.DisposeAsync().ConfigureAwait(true);
        }
    }
}
