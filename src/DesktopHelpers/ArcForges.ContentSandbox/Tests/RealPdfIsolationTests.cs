// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.Versioning;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>A first-party PDF with a valid xref, text, a red rectangle, and an action the no-V8 parser never executes.</summary>
internal static class FirstPartyPdfFixture
{
    internal static byte[] Bytes()
    {
        const string stream = "1 0 0 rg 0 0 72 72 re f\nBT /F1 14 Tf 8 40 Td (ArcScope PDF) Tj ET\n";
        string[] objects =
        [
            "<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 144 72] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            "<< /Length " + stream.Length.ToString(CultureInfo.InvariantCulture) + " >>\nstream\n" + stream + "endstream",
            "<< /S /JavaScript /JS (app.alert('must never run')) >>",
        ];
        var pdf = new StringBuilder("%PDF-1.7\n");
        var offsets = new List<int>();
        for (var i = 0; i < objects.Length; i++)
        {
            offsets.Add(pdf.Length);
            pdf.Append((i + 1).ToString(CultureInfo.InvariantCulture)).Append(" 0 obj\n").Append(objects[i]).Append("\nendobj\n");
        }

        var xref = pdf.Length;
        pdf.Append("xref\n0 7\n0000000000 65535 f \n");
        foreach (var offset in offsets)
        {
            pdf.Append(offset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n");
        }

        pdf.Append("trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n").Append(xref.ToString(CultureInfo.InvariantCulture)).Append("\n%%EOF\n");
        return Encoding.ASCII.GetBytes(pdf.ToString());
    }
}

/// <summary>Local opt-in evidence against the actual Native AOT production helper and real PDFium. Never enabled in CI.</summary>
[SupportedOSPlatform("windows")]
public sealed class RealPdfIsolationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void RequireOptIn() => Assert.SkipUnless(OperatingSystem.IsWindows()
        && Environment.GetEnvironmentVariable("ARCFORGES_CONTENTSANDBOX_OS") == "1"
        && Directory.Exists(Environment.GetEnvironmentVariable("ARCFORGES_CONTENTSANDBOX_PRODUCTION")),
        "Set ARCFORGES_CONTENTSANDBOX_OS=1 and ARCFORGES_CONTENTSANDBOX_PRODUCTION to the composed Native AOT helper; local opt-in only.");

    private static ContentSandboxLaunchOptions Options(OsHarness os) => os.Options() with { ParserProfile = ProductionParserProfile.ProfileId };

    [Fact]
    public async Task ActualPdfPageTextAndTileCrossTheRestrictedProductionHelper()
    {
        RequireOptIn();
        using var os = OsHarness.Create(production: true);
        await using var launcher = new ContentSandboxLauncher(Options(os));
        var launched = await launcher.LaunchAsync(FirstPartyPdfFixture.Bytes(), Ct);
        Assert.True(launched.IsSuccess, launched.Failure?.Code + " " + launched.Detail);
        await using var invocation = launched.Value!;
        Assert.NotEqual(Environment.ProcessId, invocation.HelperProcess.ProcessId);
        var opened = await invocation.OpenPdfAsync(Ct);
        Assert.True(opened.IsSuccess, opened.Failure?.Code + " " + opened.Detail);
        var geometry = await invocation.GetPdfPageAsync(opened.Value, 0, Ct);
        Assert.True(geometry.IsSuccess, geometry.Failure?.Code + " " + geometry.Detail);
        Assert.Equal(144, geometry.Value!.WidthPoints);
        Assert.Equal(72, geometry.Value.HeightPoints);
        var extracted = await invocation.ExtractPdfTextAsync(opened.Value, 0, 0, Ct);
        Assert.True(extracted.IsSuccess, extracted.Failure?.Code + " " + extracted.Detail);
        Assert.Contains("ArcScope PDF", extracted.Value!.Text, StringComparison.Ordinal);
        using var tile = (await invocation.RenderPdfTileAsync(opened.Value, geometry.Value, 144, 72, 0, 0, 16, 16, Ct)).Value!;
        Assert.NotNull(tile);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(tile.Bytes.Span)), tile.Sha256);
        Assert.Equal(new byte[] { 255, 0, 0, 255 }, tile.Bytes.Span[..4].ToArray());
        await invocation.CloseAsync();
        Assert.Equal(ContentSandboxContract.ExitClean, await invocation.WaitForExitAsync(Ct));
        OsHarness.Evidence("actual PDFium production helper", ["AppContainer/Job Object", "page/text/RGBA tile passed", "clean exit"]);
    }

    [Fact]
    public async Task MalformedActualPdfFailsAndANewProductionHelperStillWorks()
    {
        RequireOptIn();
        using var os = OsHarness.Create(production: true);
        await using var launcher = new ContentSandboxLauncher(Options(os));
        var malformed = await launcher.LaunchAsync("%PDF-1.7\n1 0 obj\n"u8.ToArray(), Ct);
        Assert.True(malformed.IsSuccess, malformed.Failure?.Code + " " + malformed.Detail);
        await using (var invocation = malformed.Value!)
        {
            Assert.False((await invocation.OpenPdfAsync(Ct)).IsSuccess);
        }

        var fresh = await launcher.LaunchAsync(FirstPartyPdfFixture.Bytes(), Ct);
        Assert.True(fresh.IsSuccess, fresh.Failure?.Code + " " + fresh.Detail);
        await using var again = fresh.Value!;
        Assert.True((await again.OpenPdfAsync(Ct)).IsSuccess);
    }

    [Fact]
    public async Task AbruptlyEndingARealParserHelperFailsClosedAndANewInvocationWorks()
    {
        RequireOptIn();
        using var os = OsHarness.Create(production: true);
        await using var launcher = new ContentSandboxLauncher(Options(os));
        var launched = await launcher.LaunchAsync(FirstPartyPdfFixture.Bytes(), Ct);
        Assert.True(launched.IsSuccess, launched.Failure?.Code + " " + launched.Detail);
        await using (var invocation = launched.Value!)
        {
            var opened = await invocation.OpenPdfAsync(Ct);
            Assert.True(opened.IsSuccess, opened.Failure?.Code + " " + opened.Detail);
            // End the actual parser process after PDFium has loaded. This observes OS/broker handling
            // of abrupt process loss, not evidence that a particular hostile PDF caused a native crash.
            using var process = Process.GetProcessById(invocation.HelperProcess.ProcessId);
            process.Kill(entireProcessTree: false);
            await process.WaitForExitAsync(Ct);
            Assert.False((await invocation.GetPdfPageAsync(opened.Value, 0, Ct)).IsSuccess);
            Assert.NotEqual(ContentSandboxContract.ExitClean, await invocation.WaitForExitAsync(Ct));
        }

        var fresh = await launcher.LaunchAsync(FirstPartyPdfFixture.Bytes(), Ct);
        Assert.True(fresh.IsSuccess, fresh.Failure?.Code + " " + fresh.Detail);
        await using var recovered = fresh.Value!;
        Assert.True((await recovered.OpenPdfAsync(Ct)).IsSuccess);
        OsHarness.Evidence("production parser abrupt process loss", ["failed closed", "fresh invocation recovered", "parent-induced termination; no hostile-PDF crash claim"]);
    }

    [Fact]
    public async Task TheRealParserProcessEndsWhenItsLaunchingParentDies()
    {
        RequireOptIn();
        using var os = OsHarness.Create(production: true);
        var info = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, RedirectStandardOutput = true };
        info.Environment["ARCFORGES_CS_PARENT_MODE"] = "1";
        info.Environment["ARCFORGES_CS_PARENT_PRODUCTION"] = "1";
        info.Environment["ARCFORGES_CS_HELPER"] = os.ExecutablePath;
        info.Environment["ARCFORGES_CS_ROOT"] = Fixtures.NewRoot();
        using var parent = Process.Start(info)!;
        var line = await parent.StandardOutput.ReadLineAsync(Ct) ?? string.Empty;
        Assert.StartsWith("HELPER ", line, StringComparison.Ordinal);
        using var helper = Process.GetProcessById(int.Parse(line["HELPER ".Length..], CultureInfo.InvariantCulture));
        parent.Kill(entireProcessTree: false);
        await parent.WaitForExitAsync(Ct);
        using var wait = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await helper.WaitForExitAsync(wait.Token);
        Assert.True(helper.HasExited);
        OsHarness.Evidence("actual parser parent death", ["helper ended within 15 seconds"]);
    }
}
