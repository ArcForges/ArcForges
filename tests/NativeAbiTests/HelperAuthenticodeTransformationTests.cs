// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using ArcForges.Native.ReleaseSigner;
using Xunit;

namespace ArcForges.Tests.NativeAbiTests;

/// <summary>Actual byte/stream and filesystem contracts; certificate framing is controlled structural input, never real OS trust proof.</summary>
public sealed class HelperAuthenticodeTransformationTests
{
    [Fact]
    public async Task OnlyExactChecksumDirectoryAndAppendedCertificateTransformationIsAllowed()
    {
        var original = Original();
        var signed = Signed(original);
        using var first = new MemoryStream(original);
        using var second = new MemoryStream(signed);
        await WindowsHelperSigner.RequireExactAuthenticodeTransformationAsync(first, second, TestContext.Current.CancellationToken);
        Assert.Equal(original.Length, first.Position);
        Assert.Equal(signed.Length, second.Position);
    }

    [Theory]
    [InlineData("code")]
    [InlineData("header")]
    [InlineData("overlay")]
    [InlineData("certificate-offset")]
    [InlineData("certificate-size")]
    [InlineData("certificate-kind")]
    [InlineData("certificate-padding")]
    [InlineData("existing-original-signature")]
    public async Task ForeignBodyHeaderOverlayAndCertificateLayoutsRefuse(string mutation)
    {
        var original = Original();
        var signed = Signed(original);
        const int security = 232;
        var certificate = (original.Length + 7) & ~7;
        switch (mutation)
        {
            case "code": signed[300] ^= 1; break;
            case "header": signed[80] ^= 1; break;
            case "overlay": signed[original.Length] = 1; break;
            case "certificate-offset": BinaryPrimitives.WriteUInt32LittleEndian(signed.AsSpan(security), (uint)(certificate - 8)); break;
            case "certificate-size": BinaryPrimitives.WriteUInt32LittleEndian(signed.AsSpan(security + 4), 24); break;
            case "certificate-kind": signed[certificate + 6] = 1; break;
            case "certificate-padding": BinaryPrimitives.WriteUInt32LittleEndian(signed.AsSpan(certificate), 25); signed[^1] = 1; break;
            case "existing-original-signature": BinaryPrimitives.WriteUInt32LittleEndian(original.AsSpan(security), 256); break;
        }

        using var first = new MemoryStream(original);
        using var second = new MemoryStream(signed);
        await Assert.ThrowsAsync<InvalidDataException>(() => WindowsHelperSigner.RequireExactAuthenticodeTransformationAsync(first, second, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CallerCancellationPreservesExactTokenAndNeverFinishesForeignTransform()
    {
        using var first = new MemoryStream(Original());
        using var second = new MemoryStream(Signed(Original()));
        using var cancel = new CancellationTokenSource();
        await cancel.CancelAsync();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            WindowsHelperSigner.RequireExactAuthenticodeTransformationAsync(first, second, cancel.Token));
        Assert.Equal(cancel.Token, error.CancellationToken);
    }

    [Fact]
    public async Task RealHeldFinalBytesAllowCreateOnlyPromotionAndRefuseConcurrentWrites()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Actual Windows sharing-mode component required."); return; }
        var root = Directory.CreateTempSubdirectory("arc-helper-transform-").FullName;
        try
        {
            var input = Path.Combine(root, "unsigned.exe");
            var pending = Path.Combine(root, "pending.exe");
            var output = Path.Combine(root, "signed.exe");
            await File.WriteAllBytesAsync(input, Original(), TestContext.Current.CancellationToken);
            await File.WriteAllBytesAsync(pending, Signed(Original()), TestContext.Current.CancellationToken);
            using var first = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous);
            using var second = new FileStream(pending, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 65536, FileOptions.Asynchronous);
            await WindowsHelperSigner.RequireExactAuthenticodeTransformationAsync(first, second, TestContext.Current.CancellationToken);
            await Assert.ThrowsAsync<IOException>(() => File.WriteAllBytesAsync(pending, new byte[8], TestContext.Current.CancellationToken));
            File.Move(pending, output, overwrite: false);
            await Assert.ThrowsAsync<IOException>(() => File.WriteAllBytesAsync(output, new byte[8], TestContext.Current.CancellationToken));
            Assert.Equal(Signed(Original()), await File.ReadAllBytesAsync(output, TestContext.Current.CancellationToken));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void ActualOsProtectedOwnerDiffersFromOrdinaryWritableStaging()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Actual Windows DACL component required."); return; }
        var directory = Directory.CreateTempSubdirectory("arc-helper-mutable-staging-");
        try
        {
            Assert.Throws<UnauthorizedAccessException>(() =>
            {
                if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException(); }
                WindowsHelperSigner.RequireProtectedSigningDirectory(directory.FullName, TestContext.Current.CancellationToken);
            });
            WindowsHelperSigner.RequireProtectedSigningDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), TestContext.Current.CancellationToken);
        }
        finally { directory.Delete(); }
    }

    private static byte[] Original()
    {
        var bytes = new byte[517];
        bytes[0] = (byte)'M'; bytes[1] = (byte)'Z';
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 64);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(64));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(68), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(84), 240);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(86), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(88), 0x20b);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(196), 16);
        bytes[300] = 42;
        return bytes;
    }

    private static byte[] Signed(byte[] original)
    {
        var certificate = (original.Length + 7) & ~7;
        var bytes = new byte[certificate + 32];
        original.CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(152), 0x11223344);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(232), (uint)certificate);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(236), 32);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(certificate), 32);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(certificate + 4), 0x200);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(certificate + 6), 2);
        return bytes;
    }
}
