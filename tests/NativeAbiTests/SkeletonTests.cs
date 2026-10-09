// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.NativeAbiTests;

public sealed class NativeAbiSmokeTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "NativeAbi")]
    public void ManagedBindingsLoadAndExecuteEveryOwnedWindowsShim()
    {
        IReadOnlyList<ArcForges.NativeInterop.NativeProbeResult> results = ArcForges.NativeInterop.NativeSmoke.VerifyAll();
        Xunit.Assert.Single(results);
        Xunit.Assert.All(results, result =>
        {
            Xunit.Assert.Equal(1u, result.AbiMajor);
            Xunit.Assert.Equal(1u, result.AbiMinor);
            Xunit.Assert.Equal(0, result.Status);
            Xunit.Assert.Contains("\"capabilities\":[\"image.open\",\"image.read\",\"image.close\"]", result.BuildInfo, StringComparison.Ordinal);
        });

    }
}
