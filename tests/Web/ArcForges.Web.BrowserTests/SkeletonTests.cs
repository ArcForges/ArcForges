// SPDX-License-Identifier: AGPL-3.0-only

using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Support.UI;

namespace ArcForges.Web.BrowserTests;

public sealed class SkeletonTests
{
    private static readonly TimeSpan BootBudget = TimeSpan.FromSeconds(60);

    [Xunit.Fact]
    [Xunit.Trait("Category", "Browser")]
    public void PublishedWasmBootsInARealBrowser()
    {
        string configured = Environment.GetEnvironmentVariable("ARCFORGES_WEB_BASE_URL") ??
            throw new InvalidOperationException("ARCFORGES_WEB_BASE_URL must identify the published site.");
        Uri baseUrl = new(configured, UriKind.Absolute);

        ChromeOptions options = new();
        options.AddArgument("--headless=new");
        options.AddArgument("--no-sandbox");
        options.AddArgument("--disable-dev-shm-usage");

        using ChromeDriver driver = new(options);
        try
        {
            driver.Navigate().GoToUrl(baseUrl);

            WebDriverWait wait = new(driver, BootBudget);
            IWebElement heading = wait.Until(candidate => candidate.FindElement(By.CssSelector("h1")));

            Xunit.Assert.Equal("ArcForges", heading.Text);
            Xunit.Assert.Contains(
                "Hello from the ArcForges Web companion",
                driver.FindElement(By.CssSelector("main")).Text,
                StringComparison.Ordinal);
        }
        finally
        {
            driver.Quit();
        }
    }
}
