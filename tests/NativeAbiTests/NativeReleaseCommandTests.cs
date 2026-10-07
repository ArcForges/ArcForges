// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Native.ReleaseSigner;
using Xunit;

namespace ArcForges.Tests.NativeAbiTests;

/// <summary>Real command, crypto and files. Generated keys are test fixtures, never enrolled production credentials.</summary>
public sealed class NativeReleaseCommandTests
{
    [Fact]
    public async Task ActualPemSignVerifyAndForeignKeyOrChangedProfileRefusal()
    {
        using var files = new Fixture();
        await ReleaseCommand.RunAsync(files.Sign(), TestContext.Current.CancellationToken);
        await ReleaseCommand.RunAsync(files.Verify(), TestContext.Current.CancellationToken);
        await File.AppendAllTextAsync(files.Profile, "changed", TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<InvalidDataException>(() => ReleaseCommand.RunAsync(files.Verify(), TestContext.Current.CancellationToken));
        await File.WriteAllTextAsync(files.Profile, "profile component", TestContext.Current.CancellationToken);
        using var foreign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await File.WriteAllTextAsync(files.Pem, foreign.ExportPkcs8PrivateKeyPem(), TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<CryptographicException>(() => ReleaseCommand.RunAsync(files.Sign(Path.Combine(files.Root, "foreign.signature")), TestContext.Current.CancellationToken));
        Assert.False(File.Exists(Path.Combine(files.Root, "foreign.signature")));
    }

    [Fact]
    public async Task ClosedArgumentsAndMissingBoundedInputsRefuse()
    {
        using var files = new Fixture();
        await Assert.ThrowsAsync<ArgumentException>(() => ReleaseCommand.RunAsync([.. files.Sign(), "--foreign", "value"], TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => ReleaseCommand.RunAsync([.. files.Sign(), "--source", new string('b', 40)], TestContext.Current.CancellationToken));
        await File.WriteAllBytesAsync(files.PublicKey, new byte[4097], TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<InvalidDataException>(() => ReleaseCommand.RunAsync(files.Sign(), TestContext.Current.CancellationToken));
        Assert.False(File.Exists(files.Output));
    }

    [Fact]
    public async Task CancellationAndExistingCandidateNeverReplaceOutput()
    {
        using var files = new Fixture();
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ReleaseCommand.RunAsync(files.Sign(), cancellation.Token));
        Assert.Equal(cancellation.Token, error.CancellationToken);
        Assert.False(File.Exists(files.Output));
        await ReleaseCommand.RunAsync(files.Sign(), TestContext.Current.CancellationToken);
        var original = await File.ReadAllBytesAsync(files.Output, TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<IOException>(() => ReleaseCommand.RunAsync(files.Sign(), TestContext.Current.CancellationToken));
        Assert.Equal(original, await File.ReadAllBytesAsync(files.Output, TestContext.Current.CancellationToken));
        Assert.Empty(Directory.GetFiles(files.Root, "*.writing-*"));
    }

    [Fact]
    public async Task ConcurrentCreateOnlyWritersPreserveExactlyOneCompleteCandidate()
    {
        using var files = new Fixture();
        var errors = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ =>
            RecordWriterAsync(files.Output, TestContext.Current.CancellationToken)));
        Assert.Single(errors, error => error is null);
        Assert.All(errors.Where(error => error is not null), error => Assert.IsAssignableFrom<IOException>(error));
        Assert.Equal(new byte[64], await File.ReadAllBytesAsync(files.Output, TestContext.Current.CancellationToken));
        Assert.Empty(Directory.GetFiles(files.Root, "*.writing-*"));
    }

    [Fact]
    public async Task ActualWindowsSdkRefusesUnsignedHelperAndMissingCredentialWithoutArtifacts()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Actual Windows SDK trust component is required."); return; }
        var tool = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Windows Kits", "10", "bin", "10.0.28000.0", "x64", "signtool.exe");
        if (!File.Exists(tool)) { Assert.Skip("The reviewed installed SDK signing tool is unavailable."); return; }
        using var files = new Fixture();
        var unsigned = typeof(ReleaseCommand).Assembly.Location;
        await Assert.ThrowsAsync<CryptographicException>(() => ReleaseCommand.RunAsync(
            ["verify-helper", "--tool", tool, "--input", unsigned, "--certificate-thumbprint", new string('0', 40)], TestContext.Current.CancellationToken));
        var digest = Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(unsigned, TestContext.Current.CancellationToken)));
        await Assert.ThrowsAsync<CryptographicException>(() => ReleaseCommand.RunAsync(
            ["sign-helper", "--tool", tool, "--input", unsigned, "--input-sha256", digest, "--output", files.Output,
                "--certificate-thumbprint", new string('0', 40), "--store-location", "CurrentUser", "--timestamp", "https://timestamp.invalid.test/"],
            TestContext.Current.CancellationToken));
        Assert.False(File.Exists(files.Output));
        Assert.Empty(Directory.GetFiles(files.Root, "*.signing-*"));
    }

    [Fact]
    public async Task ActualSdkSignerIdentityAndRfc3161CannotBeReplacedByAnyTrustedLeaf()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Actual Windows SDK signed component is required."); return; }
        var tool = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Windows Kits", "10", "bin", "10.0.28000.0", "x64", "signtool.exe");
        if (!File.Exists(tool)) { Assert.Skip("The reviewed installed SDK signing tool is unavailable."); return; }
        // Observed Microsoft SDK public signing identity, never an ArcForges key.
        const string microsoft = "B835FC295FFB94EA2FCA23B0E9C1EDA3FBA4E07D";
        await WindowsHelperSigner.VerifyAsync(tool, tool, microsoft, TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<CryptographicException>(() => AuthenticodeIdentity.VerifySignerAsync(tool, microsoft,
            requireRfc3161: true, TestContext.Current.CancellationToken, new string('0', 64)));
        await Assert.ThrowsAsync<CryptographicException>(() => WindowsHelperSigner.VerifyAsync(tool, tool,
            new string('0', 40), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task HelperPublisherRefusesForeignToolClosedArgumentsAndExactCancellation()
    {
        using var files = new Fixture();
        await Assert.ThrowsAsync<ArgumentException>(() => ReleaseCommand.RunAsync(
            ["verify-helper", "--tool", files.Profile, "--input", files.Profile, "--foreign", "value"], TestContext.Current.CancellationToken));
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var failure = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ReleaseCommand.RunAsync(
            ["verify-helper", "--tool", files.Profile, "--input", files.Profile, "--certificate-thumbprint", new string('0', 40)], cancellation.Token));
        Assert.Equal(cancellation.Token, failure.CancellationToken);
        if (OperatingSystem.IsWindows())
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => ReleaseCommand.RunAsync(
                ["verify-helper", "--tool", files.Profile, "--input", files.Profile, "--certificate-thumbprint", new string('0', 40)], TestContext.Current.CancellationToken));
        }

        Assert.False(File.Exists(files.Output));
    }

    private static async Task<Exception?> RecordWriterAsync(string output, CancellationToken cancellationToken) =>
        await Record.ExceptionAsync(() => ReleaseCommand.WriteNewAsync(output, new byte[64], cancellationToken)).ConfigureAwait(false);

    private sealed class Fixture : IDisposable
    {
        internal string Root { get; } = Directory.CreateTempSubdirectory("arc-native-release-command-").FullName;
        internal string Profile => Path.Combine(Root, "profile.json");
        internal string Pem => Path.Combine(Root, "private-fixture.pem");
        internal string PublicKey => Path.Combine(Root, "approved-fixture.der");
        internal string Output => Path.Combine(Root, "output.signature.json");
        internal Fixture()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            File.WriteAllText(Profile, "profile component");
            File.WriteAllText(Path.Combine(Root, "manifest.json"), "{\"schemaVersion\":1}");
            File.WriteAllText(Pem, key.ExportPkcs8PrivateKeyPem());
            File.WriteAllBytes(PublicKey, key.ExportSubjectPublicKeyInfo());
        }

        private string[] Common => ["--manifest", Path.Combine(Root, "manifest.json"), "--profile", Profile,
            "--approved-spki", PublicKey, "--key-id", "component-test-only", "--rid", "win-x64", "--library", "ArcPdfNative",
            "--version", "1.0.0-ci.116.1", "--source", new string('a', 40)];
        internal string[] Sign(string? output = null) => ["sign", .. Common, "--output", output ?? Output, "--pem", Pem];
        internal string[] Verify() => ["verify", .. Common, "--signature", Output];
        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
