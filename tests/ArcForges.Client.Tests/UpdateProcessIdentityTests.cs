// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;

namespace ArcForges.Client.Tests;

public sealed class UpdateProcessIdentityTests
{
    [Theory]
    [InlineData(-1001, false)]
    [InlineData(-1000, true)]
    [InlineData(-2, true)]
    [InlineData(0, true)]
    [InlineData(2, true)]
    [InlineData(1000, true)]
    [InlineData(1001, false)]
    public void EndpointTimestampUsesExistingPlausibilityWindow(long difference, bool plausible)
    {
        const long Observed = 1_795_000_000_000;
        Assert.Equal(plausible, EndpointDescriptor.HasPlausibleStartTime(Observed, Observed + difference));
    }

    [Fact]
    [Trait("env", "linux-real")]
    public void LinuxVerifiesLiveKernelBirthAndExactExecutableDespiteLegacyTimestampRounding()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux kernel process birth and executable readback.");
            return;
        }

        using var process = Process.GetCurrentProcess();
        long started = new DateTimeOffset(process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds();
        long kernel = ClientProcess.ReadLinuxStartTicks(process.Id);
        var actual = new FileInfo("/proc/self/exe").LinkTarget;
        Assert.NotNull(actual);
        NodeUpdateLauncher.RequireLinuxBoundExecutable(process, started + 2, actual, allowVerifiedCopy: false);
        Assert.Equal(kernel, ClientProcess.ReadLinuxStartTicks(process.Id));
        Assert.Throws<IOException>(() => NodeUpdateLauncher.RequireLinuxBoundExecutable(process, started + 1001, actual, allowVerifiedCopy: false));
        Assert.Throws<IOException>(() => NodeUpdateLauncher.RequireLinuxBoundExecutable(process, started, "/proc/self/exe", allowVerifiedCopy: false));
    }
}
