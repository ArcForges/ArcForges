// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>
/// macOS is not a supported platform, so its restricted profile is a typed refusal and nothing else. The broker launches nothing there, and a
/// helper that receives a frame carrying the reserved macOS value exits with the isolation-unavailable code before any resource or parser exists.
/// </summary>
public sealed class MacProfileTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ALaunchOnMacOsIsRefusedWithoutStartingAnything()
    {
        var options = Fixtures.Options();
        await using var launcher = new ContentSandboxLauncher(options, ContentSandboxProfile.MacOsAppSandboxXpc, launcherOverride: null);
        var result = await launcher.LaunchAsync("data"u8.ToArray(), Ct);
        Assert.False(result.IsSuccess);
        Assert.Equal("security.isolation_unavailable", result.Failure!.Code);
        Assert.False(Directory.Exists(options.RuntimeRoot));
    }

    [Fact]
    public void TheReservedMacOsValueIsWireStableAndIsNeverThisPlatformsProfile()
    {
        Assert.Equal((byte)3, (byte)ContentSandboxProfileKind.MacOsAppSandboxXpc);
        Assert.NotEqual((ContentSandboxProfileKind?)ContentSandboxProfileKind.MacOsAppSandboxXpc, ProfileEnforcement.ThisPlatform);
    }

    [Fact]
    public void TheWindowsAndLinuxKindsAreUnchangedAndAreTheOnlyProfilesOfThisPlatform()
    {
        Assert.Equal((byte)1, (byte)ContentSandboxProfileKind.WindowsAppContainerJob);
        Assert.Equal((byte)2, (byte)ContentSandboxProfileKind.LinuxLandlockSeccomp);
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal<ContentSandboxProfileKind?>(ContentSandboxProfileKind.WindowsAppContainerJob, ProfileEnforcement.ThisPlatform);
        }
        else if (OperatingSystem.IsLinux())
        {
            Assert.Equal<ContentSandboxProfileKind?>(ContentSandboxProfileKind.LinuxLandlockSeccomp, ProfileEnforcement.ThisPlatform);
        }
        else
        {
            Assert.Null(ProfileEnforcement.ThisPlatform);
        }
    }

    [Fact]
    public async Task AHelperRefusesAFrameCarryingTheMacOsValueWithTheIsolationUnavailableExit()
    {
        var exit = await RunHelperAsync(ContentSandboxProfileKind.MacOsAppSandboxXpc, Ct);
        Assert.Equal(ContentSandboxContract.ExitIsolationUnavailable, exit);
    }

    [Fact]
    public async Task AHelperKeepsItsOwnPlatformKindPastTheProfileGate()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows() || OperatingSystem.IsLinux(), "This platform has no restricted profile kind.");
        var own = OperatingSystem.IsWindows() ? ContentSandboxProfileKind.WindowsAppContainerJob : ContentSandboxProfileKind.LinuxLandlockSeccomp;

        // The bootstrap resource below is too short to be a launch descriptor, so the helper stops at that check, after the profile gate.
        var exit = await RunHelperAsync(own, Ct);
        Assert.Equal(ContentSandboxContract.ExitLaunchFrameInvalid, exit);
    }

    private static string HelperPath() =>
        Path.Combine(AppContext.BaseDirectory, "ArcForges.ContentSandbox" + (OperatingSystem.IsWindows() ? ".exe" : string.Empty));

    private static ContentSandboxLaunchFrame Frame(ContentSandboxProfileKind kind) =>
        new(
            kind,
            Guid.NewGuid(),
            Guid.NewGuid(),
            1,
            Guid.NewGuid(),
            100,
            SHA256.HashData("input"u8),
            [1024],
            new ContentSandboxLimits(),
            [
                new(ContentSandboxHandleRole.Control, 10),
                new(ContentSandboxHandleRole.Service, 11),
                new(ContentSandboxHandleRole.Input, 12),
                new(ContentSandboxHandleRole.Slot0, 13),
            ],
            "hostile-test-parser",
            [1, 2, 3, 4]);

    /// <summary>Starts the built helper, writes one launch frame of the given kind to its standard input and returns its exit code.</summary>
    private static async Task<int> RunHelperAsync(ContentSandboxProfileKind kind, CancellationToken cancellationToken)
    {
        var helper = HelperPath();
        Assert.True(File.Exists(helper), "The helper host was not built next to the tests: " + helper);
        using var frame = Frame(kind);
        var encoded = frame.Encode();
        var startInfo = new ProcessStartInfo(helper)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("The helper host did not start.");
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var diagnostics = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.StandardInput.BaseStream.WriteAsync(encoded, cancellationToken);
        await process.StandardInput.BaseStream.FlushAsync(cancellationToken);
        process.StandardInput.Close();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        try
        {
            await process.WaitForExitAsync(deadline.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }

        _ = await output;
        _ = await diagnostics;
        return process.ExitCode;
    }
}
