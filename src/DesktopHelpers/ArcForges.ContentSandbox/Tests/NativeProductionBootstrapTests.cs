// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Host;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

public sealed class NativeProductionBootstrapTests
{
    [Fact]
    public void ProductReleaseTrustCopiesTheApprovedKeyAndExactCohortBeforeCallerMutation()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = key.ExportSubjectPublicKeyInfo();
        var image = new ContentSandboxNativeRelease("ArcImageNative", new string('b', 64), new string('c', 64));
        var pdf = new ContentSandboxNativeRelease("ArcPdfNative", new string('d', 64), new string('e', 64));
        var libraries = new List<ContentSandboxNativeRelease> { image, pdf };
        var keys = new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal) { ["release-1"] = spki };
        var release = new ContentSandboxReleaseTrust(Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar), "win-x64", "1.0.0-ci.108.1", new string('a', 40), keys, libraries);
        var encoded = release.Encode();
        Array.Fill(spki, (byte)0);
        keys.Clear(); libraries.Clear();
        Assert.Equal(encoded, release.Encode());
        using var document = JsonDocument.Parse(encoded);
        Assert.Equal(2, document.RootElement.GetProperty("libraries").GetArrayLength());
        Assert.Equal(image.ManifestSha256, document.RootElement.GetProperty("libraries")[0].GetProperty("manifestSha256").GetString());
        encoded[0] = 0;
        Assert.Equal((byte)'{', release.Encode()[0]);
        var options = new ContentSandboxLaunchOptions { HelperPath = Path.Combine(Path.GetTempPath(), "helper.exe"), HelperSha256 = new byte[32], RuntimeRoot = Path.GetTempPath(), ReleaseTrust = release };
        Assert.Same(release, options.ReleaseTrust);
    }

    [Theory]
    [InlineData("relative")]
    [InlineData("foreign-rid")]
    [InlineData("foreign-library")]
    [InlineData("empty-key")]
    [InlineData("duplicate-family")]
    [InlineData("bad-hash")]
    public void ProductReleaseTrustRejectsUnapprovedOrInconsistentInputs(string mutation)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keys = new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal);
        if (mutation != "empty-key") { keys.Add("release-1", key.ExportSubjectPublicKeyInfo()); }
        var image = new ContentSandboxNativeRelease(mutation == "foreign-library" ? "UnownedNative" : "ArcImageNative", new string('b', 64), mutation == "bad-hash" ? "not-a-digest" : new string('c', 64));
        var pdf = new ContentSandboxNativeRelease(mutation == "duplicate-family" ? "ArcImageNative" : "ArcPdfNative", new string('d', 64), new string('e', 64));
        _ = Assert.ThrowsAny<Exception>(() => new ContentSandboxReleaseTrust(mutation == "relative" ? "relative" : Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar),
            mutation == "foreign-rid" ? "win-x86" : "win-x64", "1.0.0-ci.108.1", new string('a', 40), keys, [image, pdf]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("{}")]
    [InlineData("{\"schemaVersion\":1,\"schemaVersion\":1,\"directory\":\"relative\",\"keys\":[],\"libraries\":[]}")]
    [InlineData("{\"schemaVersion\":2,\"directory\":\"relative\",\"keys\":[],\"libraries\":[]}")]
    public void MissingMalformedDuplicateOrForeignBootstrapRefusesBeforeAnyNativeExecution(string input)
    {
        _ = Assert.ThrowsAny<Exception>(() => NativeProductionBootstrap.Load(System.Text.Encoding.UTF8.GetBytes(input), TestContext.Current.CancellationToken));
    }

    [Fact]
    public void BootstrapCancellationIsExactAndNoFixtureTrustIsInstalled()
    {
        var token = new CancellationToken(canceled: true);
        var error = Assert.Throws<OperationCanceledException>(() => NativeProductionBootstrap.Load("{\"fixture\":true}"u8, token));
        Assert.Equal(token, error.CancellationToken);
        _ = Assert.Throws<ContentParserException>(() => new ProductionParserProfile().Prepare());
    }
}
