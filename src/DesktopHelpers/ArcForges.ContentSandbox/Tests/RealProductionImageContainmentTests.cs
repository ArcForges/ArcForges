// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using Xunit;
using static ArcForges.ContentSandbox.Tests.ProductionImageScenarios;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>Local-only scenarios over the real broker/child/codec. No scripted reader participates.</summary>
[SupportedOSPlatform("windows")]
public sealed class RealProductionImageContainmentTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void RequireComponent() => Assert.SkipUnless(OperatingSystem.IsWindows()
        && Environment.GetEnvironmentVariable("ARCFORGES_CONTENTSANDBOX_OS") == "1"
        && Directory.Exists(Environment.GetEnvironmentVariable("ARCFORGES_CONTENTSANDBOX_PRODUCTION")),
        "Local actual-codec component opt-in requires the composed Native AOT helper. Unsigned fixture mode does not close release acceptance.");

    private static ContentSandboxLaunchOptions ComponentOptions(OsHarness os) => os.Options() with { ParserProfile = ProductionParserProfile.ProfileId };

    [Theory]
    [InlineData("png", 1u)]
    [InlineData("tiff", 1u)]
    [InlineData("exr", 1u)]
    [InlineData("png", 2u)]
    [InlineData("tiff", 2u)]
    [InlineData("exr", 2u)]
    public async Task ActualCodecTilesBoundsAndClosedHandleCrossTheRestrictedChild(string codec, uint format)
    {
        RequireComponent();
        using var os = OsHarness.Create(production: true);
        await using var launcher = new ContentSandboxLauncher(ComponentOptions(os));
        await ImageScenarioAsync(launcher, codec, Ct, format);
        OsHarness.Evidence("actual " + codec + " component helper", ["real OIIO/PDFium preloaded", "tile/hash/bounds/closed-handle", "local unsigned fixture; not authenticated release acceptance"]);
    }

    [Theory]
    [InlineData("png")]
    [InlineData("tiff")]
    [InlineData("exr")]
    public async Task TruncatedActualFormatsRefuseAndFreshInvocationRecovers(string codec)
    {
        RequireComponent();
        using var os = OsHarness.Create(production: true);
        await using var launcher = new ContentSandboxLauncher(ComponentOptions(os));
        await RefusedInputAsync(launcher, FirstPartyImageFixtures.Create(codec)[..8], Ct);
        await ImageScenarioAsync(launcher, codec, Ct);
    }

    [Fact]
    public async Task ActualImageDimensionLimitRefusesBeforeOutputAndFreshBudgetRecovers()
    {
        RequireComponent();
        using var os = OsHarness.Create(production: true);
        await using (var limited = new ContentSandboxLauncher(ComponentOptions(os) with
        {
            Limits = new ContentSandboxLimits { MaxWidth = 1, MaxHeight = 1, TimeoutMs = 10000 },
        }))
        {
            await RefusedInputAsync(limited, FirstPartyImageFixtures.Create("png"), Ct);
        }

        await using var fresh = new ContentSandboxLauncher(ComponentOptions(os));
        await ImageScenarioAsync(fresh, "png", Ct);
    }

    [Fact]
    public async Task CancellationAndAbruptLossEndActualParserProcessAndAllowFreshInvocation()
    {
        RequireComponent();
        using var os = OsHarness.Create(production: true);
        await using var launcher = new ContentSandboxLauncher(ComponentOptions(os));
        await using (var invocation = await LaunchAsync(launcher, FirstPartyImageFixtures.Create("exr"), Ct))
        {
            var image = await invocation.OpenImageAsync(0, 0, 1, Ct);
            Assert.True(image.IsSuccess, image.Failure?.Code + " " + image.Detail);
            Assert.True(await invocation.CancelAsync());
            Assert.False((await invocation.ReadImageTileAsync(image.Value, 0, 0, 1, 1, Ct)).IsSuccess);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(15));
            _ = await invocation.WaitForExitAsync(deadline.Token);
        }

        await using (var invocation = await LaunchAsync(launcher, FirstPartyImageFixtures.Create("tiff"), Ct))
        {
            var image = await invocation.OpenImageAsync(0, 0, 1, Ct);
            Assert.True(image.IsSuccess, image.Failure?.Code + " " + image.Detail);
            using var process = Process.GetProcessById(invocation.HelperProcess.ProcessId);
            process.Kill(entireProcessTree: false);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(15));
            await process.WaitForExitAsync(deadline.Token);
            Assert.False((await invocation.ReadImageTileAsync(image.Value, 0, 0, 1, 1, Ct)).IsSuccess);
            Assert.NotEqual(ContentSandboxContract.ExitClean, await invocation.WaitForExitAsync(deadline.Token));
        }

        await ImageScenarioAsync(launcher, "png", Ct);
        OsHarness.Evidence("actual combined parser lifecycle component", ["cancellation", "parent-induced abrupt loss, not a malicious-codec crash", "fresh invocation recovered", "unsigned fixture evidence"]);
    }

}

/// <summary>Explicit local acceptance entry points consuming a separately approved installed cohort.</summary>
public sealed class AuthenticatedProductionContainmentTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static ProductionContainmentHarness RequireInstallation()
    {
        var configuration = Environment.GetEnvironmentVariable("ARCFORGES_CONTENTSANDBOX_RELEASE_CONFIG");
        Assert.SkipUnless(Environment.GetEnvironmentVariable("ARCFORGES_CONTENTSANDBOX_OS") == "1" && File.Exists(configuration),
            "Requires an operator-selected installed signed helper and externally approved exact Image/Pdf release cohort; never enabled in CI.");
        return ProductionContainmentHarness.ReadOperatorConfiguration(configuration!);
    }

    [Theory]
    [InlineData("png")]
    [InlineData("tiff")]
    [InlineData("exr")]
    public async Task AuthenticatedInstalledProductionCohortServesTheActualFormat(string codec)
    {
        var harness = RequireInstallation();
        await using var launcher = new ContentSandboxLauncher(harness.Options);
        await using var invocation = await LaunchAsync(launcher, FirstPartyImageFixtures.Create(codec), Ct);
        await AssertImageAsync(invocation, Ct);
        await invocation.CloseAsync();
        Assert.Equal(ContentSandboxContract.ExitClean, await invocation.WaitForExitAsync(Ct));
        harness.Evidence("actual " + codec + " tile/bounds/closed-handle/clean-exit", invocation);
        await RefusedInputAsync(launcher, FirstPartyImageFixtures.Create(codec)[..8], Ct);
        await ImageScenarioAsync(launcher, codec, Ct);
    }

    [Fact]
    public async Task AuthenticatedSameCohortServesPdfPageTextPixelsAndFreshImage()
    {
        var harness = RequireInstallation();
        await using var launcher = new ContentSandboxLauncher(harness.Options);
        await using (var invocation = await LaunchAsync(launcher, FirstPartyPdfFixture.Bytes(), Ct))
        {
            Assert.NotEqual(Environment.ProcessId, invocation.HelperProcess.ProcessId);
            var opened = await invocation.OpenPdfAsync(Ct);
            Assert.True(opened.IsSuccess, opened.Failure?.Code + " " + opened.Detail);
            var page = await invocation.GetPdfPageAsync(opened.Value, 0, Ct);
            Assert.True(page.IsSuccess, page.Failure?.Code + " " + page.Detail);
            Assert.Equal((144d, 72d), (page.Value.WidthPoints, page.Value.HeightPoints));
            var text = await invocation.ExtractPdfTextAsync(opened.Value, 0, 0, Ct);
            Assert.True(text.IsSuccess, text.Failure?.Code + " " + text.Detail);
            Assert.Contains("ArcScope PDF", text.Value.Text, StringComparison.Ordinal);
            var rendered = await invocation.RenderPdfTileAsync(opened.Value, page.Value, 144, 72, 0, 0, 16, 16, Ct);
            Assert.True(rendered.IsSuccess, rendered.Failure?.Code + " " + rendered.Detail);
            using var tile = rendered.Value;
            Assert.Equal(new byte[] { 255, 0, 0, 255 }, tile.Bytes.Span[..4].ToArray());
            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(tile.Bytes.Span)), tile.Sha256);
            Assert.True((await invocation.ClosePdfAsync(opened.Value, Ct)).IsSuccess);
            Assert.False((await invocation.GetPdfPageAsync(opened.Value, 0, Ct)).IsSuccess);
            await invocation.CloseAsync();
            Assert.Equal(ContentSandboxContract.ExitClean, await invocation.WaitForExitAsync(Ct));
            harness.Evidence("actual PDF page/text/tile/closed-handle/clean-exit", invocation);
        }

        await ImageScenarioAsync(launcher, "png", Ct);
    }
}

/// <summary>Reusable scenarios use the actual broker and no substituted codec or launcher.</summary>
internal static class ProductionImageScenarios
{
    internal static async Task ImageScenarioAsync(ContentSandboxLauncher launcher, string codec, CancellationToken cancellation, uint format = 1)
    {
        await using var invocation = await LaunchAsync(launcher, FirstPartyImageFixtures.Create(codec), cancellation);
        await AssertImageAsync(invocation, cancellation, format);
        await invocation.CloseAsync();
        Assert.Equal(ContentSandboxContract.ExitClean, await invocation.WaitForExitAsync(cancellation));
    }

    internal static async Task AssertImageAsync(ContentSandboxInvocation invocation, CancellationToken cancellation, uint format = 1)
    {
        Assert.NotEqual(Environment.ProcessId, invocation.HelperProcess.ProcessId);
        var opened = await invocation.OpenImageAsync(0, 0, format, cancellation);
        Assert.True(opened.IsSuccess, opened.Failure?.Code + " " + opened.Detail);
        var info = await invocation.GetImageInfoAsync(opened.Value, cancellation);
        Assert.True(info.IsSuccess, info.Failure?.Code + " " + info.Detail);
        Assert.Equal((2u, 2u), (info.Value.Width, info.Value.Height));
        Assert.False((await invocation.ReadImageTileAsync(opened.Value, 1, 1, 2, 2, cancellation)).IsSuccess);
        Assert.False((await invocation.ReadImageTileAsync(Guid.NewGuid(), 0, 0, 1, 1, cancellation)).IsSuccess);
        var read = await invocation.ReadImageTileAsync(opened.Value, 0, 0, 2, 2, cancellation);
        Assert.True(read.IsSuccess, read.Failure?.Code + " " + read.Detail);
        using var tile = read.Value;
        Assert.Equal(format == 1 ? 16 : 64, tile.Bytes.Length);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(tile.Bytes.Span)), tile.Sha256);
        for (var offset = 0; offset < tile.Bytes.Length; offset += format == 1 ? 4 : 16)
        {
            if (format == 1) { Assert.Equal(new byte[] { 255, 0, 0, 255 }, tile.Bytes.Span.Slice(offset, 4).ToArray()); }
            else
            {
                Assert.Equal(1f, BitConverter.ToSingle(tile.Bytes.Span.Slice(offset, 4)));
                Assert.Equal(0f, BitConverter.ToSingle(tile.Bytes.Span.Slice(offset + 4, 4)));
                Assert.Equal(0f, BitConverter.ToSingle(tile.Bytes.Span.Slice(offset + 8, 4)));
                Assert.Equal(1f, BitConverter.ToSingle(tile.Bytes.Span.Slice(offset + 12, 4)));
            }
        }
        Assert.True((await invocation.CloseImageAsync(opened.Value, cancellation)).IsSuccess);
        Assert.False((await invocation.GetImageInfoAsync(opened.Value, cancellation)).IsSuccess);
    }

    internal static async Task RefusedInputAsync(ContentSandboxLauncher launcher, byte[] input, CancellationToken cancellation)
    {
        await using var invocation = await LaunchAsync(launcher, input, cancellation);
        var result = await invocation.OpenImageAsync(0, 0, 1, cancellation);
        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Failure);
        await invocation.CloseAsync();
        Assert.Equal(ContentSandboxContract.ExitClean, await invocation.WaitForExitAsync(cancellation));
    }

    internal static async Task<ContentSandboxInvocation> LaunchAsync(ContentSandboxLauncher launcher, byte[] input, CancellationToken cancellation)
    {
        var launched = await launcher.LaunchAsync(input, cancellation);
        Assert.True(launched.IsSuccess, launched.Failure?.Code + " " + launched.Detail);
        return launched.Value;
    }
}
