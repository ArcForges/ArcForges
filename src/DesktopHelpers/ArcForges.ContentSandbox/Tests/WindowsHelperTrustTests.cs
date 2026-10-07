// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.ContentSandbox.Broker.Native;
using ArcForges.ContentSandbox.Broker.Windows;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>Actual WinVerifyTrust components. These tests certify neither first-party release enrollment nor OS isolation.</summary>
public sealed class WindowsHelperTrustTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public void ActualUnsignedModuleIsRefusedAndItsHeldHandleRemainsOwnedByTheCaller()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Actual Authenticode component requires Windows.");
        Assert.Equal(32, Marshal.SizeOf<WindowsNative.WinTrustFileInfo>());
        Assert.Equal(88, Marshal.SizeOf<WindowsNative.WinTrustData>());
        var path = Path.Combine(AppContext.BaseDirectory, "ArcForges.ContentSandbox.Tests.dll");
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        _ = Assert.Throws<CryptographicException>(() => WindowsHelperTrust.Verify(file, path, TestContext.Current.CancellationToken));
        Assert.False(file.SafeFileHandle.IsClosed);
        Assert.True(file.Length > 0);
        Assert.True(file.ReadByte() >= 0);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void CancellationIsExactAndNeverFallsThroughToSignatureSuccess()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Actual Authenticode component requires Windows.");
        var path = Path.Combine(AppContext.BaseDirectory, "ArcForges.ContentSandbox.Tests.dll");
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var token = new CancellationToken(canceled: true);
        var error = Assert.Throws<OperationCanceledException>(() => WindowsHelperTrust.Verify(file, path, token));
        Assert.Equal(token, error.CancellationToken);
        Assert.False(file.SafeFileHandle.IsClosed);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void AnActuallyInstalledSignedImagePassesStandardTrustWhenExplicitlyAvailable()
    {
        var path = Environment.GetEnvironmentVariable("ARCFORGES_TRUSTED_TEST_IMAGE");
        Assert.SkipUnless(OperatingSystem.IsWindows() && !string.IsNullOrEmpty(path), "Set ARCFORGES_TRUSTED_TEST_IMAGE to the actual admitted installed signed image; no fixture publisher proof is invented.");
        using var file = new FileStream(path!, FileMode.Open, FileAccess.Read, FileShare.Read);
        WindowsHelperTrust.Verify(file, path!, TestContext.Current.CancellationToken);
        Assert.False(file.SafeFileHandle.IsClosed);
    }
}
