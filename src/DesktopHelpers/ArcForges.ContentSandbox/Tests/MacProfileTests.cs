// SPDX-License-Identifier: AGPL-3.0-only
using System.Xml.Linq;
using ArcForges.ContentSandbox.Broker;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>The macOS profile is declarative data and a refusal: no launcher exists, so nothing is ever started on that platform.</summary>
public sealed class MacProfileTests
{
    private static string EntitlementsPath()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "DesktopPlatform.slnx")))
        {
            directory = directory.Parent;
        }

        return Path.Combine(directory?.FullName ?? throw new InvalidOperationException("The repository root was not found."),
            "src", "DesktopHelpers", "ArcForges.ContentSandbox", "macos", "ArcForges.ContentSandbox.entitlements");
    }

    [Fact]
    public void TheEntitlementsEnableTheAppSandboxAndNothingElse()
    {
        var document = XDocument.Load(EntitlementsPath());
        var keys = document.Descendants("key").Select(key => key.Value).ToArray();
        Assert.Equal(["com.apple.security.app-sandbox"], keys);
        Assert.Equal("true", document.Descendants("dict").Single().Elements().ElementAt(1).Name.LocalName);
        Assert.DoesNotContain(keys, key => key.Contains("network", StringComparison.Ordinal)
            || key.Contains("files", StringComparison.Ordinal) || key.Contains("inherit", StringComparison.Ordinal)
            || key.Contains("application-groups", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ALaunchOnMacOsIsRefusedWithoutStartingAnything()
    {
        await using var launcher = new ContentSandboxLauncher(Fixtures.Options(), ContentSandboxProfile.MacOsAppSandboxXpc, launcherOverride: null);
        var result = await launcher.LaunchAsync("data"u8.ToArray(), TestContext.Current.CancellationToken);
        Assert.Equal("security.isolation_unavailable", result.Failure!.Code);
    }
}
