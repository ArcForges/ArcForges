// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.NativeAbiTests;

public sealed class NativeAbiSmokeTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "NativeAbi")]
    public void ManagedBindingsLoadAndExecuteEveryOwnedWindowsShim()
    {
        string? mode = Environment.GetEnvironmentVariable("ARCFORGES_NATIVE_BUILD_MODE");
        Xunit.Assert.True(mode is "cmake" or "msbuild", "The test must identify the native build path under test.");

        IReadOnlyList<ArcForges.NativeInterop.NativeProbeResult> results = ArcForges.NativeInterop.NativeSmoke.VerifyAll();
        Xunit.Assert.Equal(5, results.Count);
        Xunit.Assert.All(results, result =>
        {
            Xunit.Assert.Equal(1u, result.AbiMajor);
            Xunit.Assert.Equal(0u, result.AbiMinor);
            Xunit.Assert.Equal(0, result.Status);
            Xunit.Assert.Contains("abi=1.0", result.BuildInfo, StringComparison.Ordinal);
        });

        Xunit.Assert.Equal("ArcScopeMdfNative", ArcScope.Native.MdfNativeSmoke.Verify().LibraryName);
        Xunit.Assert.Equal(3, ArcSlate.Native.SlateNativeSmoke.Verify().Count);
    }
}
