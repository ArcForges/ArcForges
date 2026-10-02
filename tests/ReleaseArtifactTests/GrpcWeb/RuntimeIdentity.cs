// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime;
using System.Runtime.CompilerServices;

namespace ArcForges.ReleaseArtifactTests.GrpcWeb;

internal static class RuntimeIdentity
{
    /// <summary>
    /// True only when this process is a Native AOT executable. The feature switch alone is not enough: a JIT run of
    /// this project's build output also reports dynamic code as unsupported (the project sets PublishAot), so the
    /// process must also have JIT-compiled no method at all, which is observable only in a real AOT image.
    /// </summary>
    public static bool IsNativeAot => !RuntimeFeature.IsDynamicCodeSupported && JitInfo.GetCompiledMethodCount() == 0;
}
